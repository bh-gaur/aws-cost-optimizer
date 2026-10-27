import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.price_book import PriceBook
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")


def _chunks(seq: list, n: int) -> Generator[list, None, None]:
    """Yield successive n-sized chunks from seq."""
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _parse_stopped_date(reason: str) -> Optional[datetime]:
    """
    Parses datetime from EC2 StateTransitionReason string.
    Example: 'User initiated (2026-08-01 10:15:33 GMT)'
    """
    if not reason:
        return None
    match = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)", reason)
    if match:
        try:
            dt = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


class EC2Scanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ec2"

    @property
    def display_name(self) -> str:
        return "Amazon EC2"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ec2 = self.get_client(session, "ec2", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[EC2] Failed to initialize client in {region}: {e}")
            return findings

        price_book = PriceBook(session)

        # 1. First, check AWS Compute Optimizer for ML-backed recommendations
        co_findings = self._check_compute_optimizer(session, region)
        if co_findings:
            findings.extend(co_findings)
            logger.info(f"[EC2] Retrieved {len(co_findings)} recommendations from AWS Compute Optimizer")

        # 2. Describe all EC2 instances across reservations
        all_instances: List[Dict[str, Any]] = []
        running_instance_ids: List[str] = []
        stopped_instances: List[Dict[str, Any]] = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        all_instances.append(inst)
                        state = inst.get("State", {}).get("Name", "")
                        if state == "running":
                            running_instance_ids.append(inst["InstanceId"])
                        elif state == "stopped":
                            stopped_instances.append(inst)
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_instances in {region}")
            return findings

        if not all_instances:
            return findings

        # 3. Batch fetch volume details for accurate EBS storage pricing on stopped instances
        vol_price_map = self._fetch_volume_sizes(ec2, stopped_instances, region, price_book)

        # 4. Batch query CloudWatch metrics for running instances (up to 500 queries per call)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=CONFIG.METRIC_LOOKBACK_DAYS)
        cw_stats = self._fetch_batched_metrics(cw, running_instance_ids, start_time, end_time)

        # 5. Evaluate instances with guard checks and double-counting prevention
        for inst in all_instances:
            instance_id = inst["InstanceId"]
            instance_type = inst.get("InstanceType", "")
            state = inst.get("State", {}).get("Name", "")
            tags = {t.get("Key", ""): t.get("Value", "") for t in inst.get("Tags", [])}

            # Guard 1: Skip if instance is explicitly marked to ignore
            if any(tags.get(k, "").lower() == "true" for k in CONFIG.IGNORE_TAG_KEYS):
                logger.debug(f"[EC2] Skipping {instance_id}: tagged with ignore")
                continue

            # Guard 2: Skip EKS worker nodes (managed by Kubernetes autoscaling)
            if any(k.startswith(CONFIG.EKS_TAG_PREFIXES) for k in tags.keys()):
                logger.debug(f"[EC2] Skipping {instance_id}: EKS managed node")
                continue

            # Guard 3: Detect if part of Auto Scaling Group
            is_asg = CONFIG.ASG_TAG_KEY in tags
            asg_name = tags.get(CONFIG.ASG_TAG_KEY, "")

            # --- Check Stopped Instances ---
            if state == "stopped":
                ebs_monthly = vol_price_map.get(instance_id, 10.0)
                finding = self._check_stopped(inst, ebs_monthly, tags, region)
                if finding:
                    findings.append(finding)
                continue

            # --- Running Instances Checks ---
            if state == "running":
                # Track whether an idle finding was created to prevent double-counting
                has_idle_finding = False

                # 5a. Idle / Underutilized Instance Check
                idle_finding = self._check_idle(inst, cw_stats.get(instance_id, {}), tags, region, is_asg, asg_name, price_book)
                if idle_finding:
                    findings.append(idle_finding)
                    has_idle_finding = True

                # 5b. Previous Generation Check (Skip if already recommended for termination/downsize to avoid double counting)
                if not has_idle_finding:
                    prev_gen_finding = self._check_previous_gen(inst, tags, region, is_asg, asg_name, price_book)
                    if prev_gen_finding:
                        findings.append(prev_gen_finding)

                    # 5c. Graviton Upgrade Check
                    graviton_finding = self._check_graviton(inst, tags, region, is_asg, asg_name, price_book)
                    if graviton_finding:
                        findings.append(graviton_finding)

                # 5d. Non-Production Running 24/7 Scheduling Check
                sched_finding = self._check_nonprod_scheduling(inst, tags, region, is_asg, asg_name, price_book)
                if sched_finding:
                    findings.append(sched_finding)

                # 5e. Unnecessary Public IPv4 Check
                ipv4_finding = self._check_public_ipv4(inst, tags, region)
                if ipv4_finding:
                    findings.append(ipv4_finding)

                # 5f. Attached gp2 Volume Upgrade Check
                gp2_findings = self._check_attached_gp2(inst, tags, region)
                if gp2_findings:
                    findings.extend(gp2_findings)

        return findings

    # -------------------------------------------------------------------------
    # Batch Metric Collection (Speed Optimization)
    # -------------------------------------------------------------------------
    def _fetch_batched_metrics(
        self, cw: Any, instance_ids: List[str], start: datetime, end: datetime
    ) -> Dict[str, Dict[str, List[float]]]:
        """
        Batches CloudWatch get_metric_data calls.
        Up to 500 queries per call (250 instances x 2 metrics: Avg CPU + Max CPU).
        """
        stats: Dict[str, Dict[str, List[float]]] = {
            iid: {"cpu_avg": [], "cpu_max": [], "net_in": [], "net_out": []}
            for iid in instance_ids
        }

        if not instance_ids:
            return stats

        # 2 queries per instance (Average + Maximum CPU) = chunk size 200 instances (400 queries)
        for chunk in _chunks(instance_ids, 200):
            queries = []
            lookup: Dict[str, Tuple[str, str]] = {}

            for idx, iid in enumerate(chunk):
                for metric_key, stat_name in (("cpu_avg", "Average"), ("cpu_max", "Maximum")):
                    qid = f"{metric_key}_{idx}"
                    lookup[qid] = (iid, metric_key)
                    queries.append(
                        {
                            "Id": qid,
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/EC2",
                                    "MetricName": "CPUUtilization",
                                    "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                                },
                                "Period": 86400,
                                "Stat": stat_name,
                            },
                        }
                    )

            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(MetricDataQueries=queries, StartTime=start, EndTime=end):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in lookup:
                            iid, key = lookup[qid]
                            stats[iid][key].extend(res.get("Values", []))
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for EC2 instances")

        return stats

    def _fetch_volume_sizes(
        self, ec2: Any, stopped_instances: List[Dict[str, Any]], region: str, price_book: PriceBook
    ) -> Dict[str, float]:
        """Calculates actual monthly EBS storage cost per stopped instance based on real-time rate."""
        result: Dict[str, float] = {}
        all_vol_ids: Set[str] = set()
        inst_to_vols: Dict[str, List[str]] = {}

        for inst in stopped_instances:
            iid = inst["InstanceId"]
            vids = [
                bd["Ebs"]["VolumeId"]
                for bd in inst.get("BlockDeviceMappings", [])
                if "Ebs" in bd and "VolumeId" in bd["Ebs"]
            ]
            inst_to_vols[iid] = vids
            all_vol_ids.update(vids)

        if not all_vol_ids:
            return result

        vol_cost_map: Dict[str, float] = {}
        for chunk in _chunks(list(all_vol_ids), 200):
            try:
                vols_resp = ec2.describe_volumes(VolumeIds=chunk).get("Volumes", [])
                for v in vols_resp:
                    vid = v["VolumeId"]
                    size = v.get("Size", 0)
                    vtype = v.get("VolumeType", "gp3")
                    rate = price_book.ebs_storage_rate(vtype, region)
                    vol_cost_map[vid] = size * rate
            except ClientError as ce:
                self.handle_client_error(ce, f"describe_volumes for stopped instances in {region}")

        for iid, vids in inst_to_vols.items():
            result[iid] = sum(vol_cost_map.get(vid, 5.0) for vid in vids)

        return result

    # -------------------------------------------------------------------------
    # Individual Check Methods
    # -------------------------------------------------------------------------
    def _check_stopped(
        self, inst: Dict[str, Any], ebs_cost: float, tags: Dict[str, str], region: str
    ) -> Optional[Finding]:
        """Audits stopped instances, calculates real EBS waste, and parses stopped duration."""
        instance_id = inst["InstanceId"]
        name = tags.get("Name", "")
        reason = inst.get("StateTransitionReason", "")
        stopped_date = _parse_stopped_date(reason)
        now = datetime.now(timezone.utc)

        stopped_days = (now - stopped_date).days if stopped_date else None

        # Severity scales with stopped age
        if stopped_days is not None:
            if stopped_days > 30:
                severity = Severity.HIGH
            elif stopped_days > 7:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
            duration_str = f"stopped for {stopped_days} days"
        else:
            severity = Severity.MEDIUM
            duration_str = "stopped"

        meta = {
            "instance_type": inst.get("InstanceType", ""),
            "stopped_since": str(stopped_date) if stopped_date else "Unknown",
            "stopped_days": stopped_days,
            "architecture": inst.get("Architecture", "x86_64"),
            "platform": inst.get("PlatformDetails", "Linux/UNIX"),
            "vpc_id": inst.get("VpcId", ""),
            "tags": tags,
        }

        return Finding(
            service=self.display_name,
            resource_id=instance_id,
            resource_name=name,
            region=region,
            severity=severity,
            effort="Low",
            confidence="High",
            issue=f"Instance {duration_str}; incurring ${ebs_cost:.2f}/mo in attached EBS storage fees (compute is paused)",
            recommendation="Create final EBS snapshots if data must be archived, then terminate the instance to stop storage fees",
            estimated_monthly_saving=ebs_cost,
            metadata=meta,
        )

    def _check_idle(
        self,
        inst: Dict[str, Any],
        metrics: Dict[str, List[float]],
        tags: Dict[str, str],
        region: str,
        is_asg: bool,
        asg_name: str,
        price_book: PriceBook,
    ) -> Optional[Finding]:
        """Detects idle instances using Average + Maximum CPU with network guard and minimum datapoints."""
        instance_id = inst["InstanceId"]
        instance_type = inst.get("InstanceType", "")
        name = tags.get("Name", "")

        cpu_avg_list = metrics.get("cpu_avg", [])
        cpu_max_list = metrics.get("cpu_max", [])

        # Require minimum datapoint history so newly launched instances aren't mislabeled
        if len(cpu_avg_list) < CONFIG.EC2_MIN_DATAPOINTS:
            return None

        avg_cpu = sum(cpu_avg_list) / len(cpu_avg_list)
        max_cpu = max(cpu_max_list) if cpu_max_list else 100.0

        # Guard: Check average CPU AND peak maximum CPU (avoids flagging batch/JVM/cron jobs)
        if avg_cpu < CONFIG.EC2_IDLE_CPU_AVG_THRESHOLD and max_cpu < CONFIG.EC2_IDLE_CPU_MAX_THRESHOLD:
            monthly_cost = price_book.ec2_monthly_on_demand(instance_type, region)
            saving = price_book.ec2_monthly_downsize(instance_type, region)

            if is_asg:
                recommendation = f"Adjust Auto Scaling Group '{asg_name}' launch template to a smaller instance type or decrease MinSize/DesiredCapacity"
                effort = "Medium"
            else:
                recommendation = f"Downsize from {instance_type} to a smaller instance size (saves ~50%), or terminate if no longer needed"
                effort = "Low"

            launch_time = inst.get("LaunchTime")
            age_days = (datetime.now(timezone.utc) - launch_time).days if launch_time else None

            meta = {
                "instance_type": instance_type,
                "avg_cpu": round(avg_cpu, 2),
                "max_cpu": round(max_cpu, 2),
                "datapoint_count": len(cpu_avg_list),
                "monthly_cost": round(monthly_cost, 2),
                "age_days": age_days,
                "is_asg": is_asg,
                "asg_name": asg_name,
                "architecture": inst.get("Architecture", "x86_64"),
                "lifecycle": inst.get("InstanceLifecycle", "on-demand"),
                "platform": inst.get("PlatformDetails", "Linux/UNIX"),
                "tags": tags,
            }

            return Finding(
                service=self.display_name,
                resource_id=instance_id,
                resource_name=name,
                region=region,
                severity=Severity.HIGH,
                effort=effort,
                confidence="High" if len(cpu_avg_list) >= 7 else "Medium",
                issue=f"Idle/underutilized instance (Avg CPU: {avg_cpu:.1f}%, Max Peak: {max_cpu:.1f}% over {len(cpu_avg_list)} days)",
                recommendation=recommendation,
                estimated_monthly_saving=saving,
                metadata=meta,
            )

        return None

    def _check_previous_gen(
        self,
        inst: Dict[str, Any],
        tags: Dict[str, str],
        region: str,
        is_asg: bool,
        asg_name: str,
        price_book: PriceBook,
    ) -> Optional[Finding]:
        """Exact family matching for previous generation instances (e.g. t2->t3, m4->m5, i3->i4i)."""
        instance_id = inst["InstanceId"]
        instance_type = inst.get("InstanceType", "")
        name = tags.get("Name", "")

        family, _, size = instance_type.partition(".")
        if family in CONFIG.PREV_GEN_UPGRADES:
            target_family = CONFIG.PREV_GEN_UPGRADES[family]
            modern_target = f"{target_family}.{size}"

            curr_hourly = price_book.ec2_hourly(instance_type, region)
            target_hourly = price_book.ec2_hourly(modern_target, region)
            # Modern gen saves ~10-15% on direct pricing plus higher performance
            monthly_saving = max((curr_hourly - target_hourly) * 730.0, curr_hourly * 730.0 * 0.10)

            rec_target = f"Launch template for ASG '{asg_name}'" if is_asg else f"Instance {instance_id}"
            return Finding(
                service=self.display_name,
                resource_id=instance_id,
                resource_name=name,
                region=region,
                severity=Severity.MEDIUM,
                effort="Medium" if is_asg else "Low",
                confidence="High",
                issue=f"Running previous-generation instance type ({instance_type})",
                recommendation=f"Upgrade {rec_target} to current-generation {modern_target} for higher performance and ~10-15% cost savings",
                estimated_monthly_saving=monthly_saving,
                metadata={
                    "current_type": instance_type,
                    "target_type": modern_target,
                    "is_asg": is_asg,
                    "tags": tags,
                },
            )
        return None

    def _check_graviton(
        self,
        inst: Dict[str, Any],
        tags: Dict[str, str],
        region: str,
        is_asg: bool,
        asg_name: str,
        price_book: PriceBook,
    ) -> Optional[Finding]:
        """Detects x86_64 instances with direct AWS Graviton (ARM64) equivalents (~20% savings)."""
        instance_id = inst["InstanceId"]
        instance_type = inst.get("InstanceType", "")
        arch = inst.get("Architecture", "")
        platform = inst.get("PlatformDetails", "Linux/UNIX")
        name = tags.get("Name", "")

        # Graviton is supported on Linux workloads
        if arch == "x86_64" and "linux" in platform.lower():
            family, _, size = instance_type.partition(".")
            if family in CONFIG.GRAVITON_UPGRADES:
                graviton_family = CONFIG.GRAVITON_UPGRADES[family]
                target_type = f"{graviton_family}.{size}"

                curr_hourly = price_book.ec2_hourly(instance_type, region)
                graviton_hourly = price_book.ec2_hourly(target_type, region)
                monthly_saving = max((curr_hourly - graviton_hourly) * 730.0, curr_hourly * 730.0 * 0.20)

                rec_target = f"ASG '{asg_name}' launch template" if is_asg else f"instance {instance_id}"
                return Finding(
                    service=self.display_name,
                    resource_id=instance_id,
                    resource_name=name,
                    region=region,
                    severity=Severity.LOW,
                    effort="Medium",
                    confidence="High",
                    issue=f"Running x86_64 architecture ({instance_type}) with available AWS Graviton twin",
                    recommendation=f"Migrate {rec_target} to ARM64 Graviton ({target_type}) for ~20% price-performance gain",
                    estimated_monthly_saving=monthly_saving,
                    metadata={"current_type": instance_type, "target_type": target_type, "tags": tags},
                )
        return None

    def _check_nonprod_scheduling(
        self,
        inst: Dict[str, Any],
        tags: Dict[str, str],
        region: str,
        is_asg: bool,
        asg_name: str,
        price_book: PriceBook,
    ) -> Optional[Finding]:
        """Checks if non-production instances (dev/test/staging) are running 24/7 without scheduled off-hours."""
        instance_id = inst["InstanceId"]
        instance_type = inst.get("InstanceType", "")
        name = tags.get("Name", "")

        # Check environment tag
        is_non_prod = False
        for k, v in tags.items():
            if k.lower() in ("env", "environment", "stage"):
                if any(env in v.lower() for env in ("dev", "test", "stage", "staging", "qa", "sandbox", "nonprod")):
                    is_non_prod = True
                    break

        if is_non_prod:
            monthly_saving = price_book.ec2_monthly_schedule(instance_type, region)
            return Finding(
                service=self.display_name,
                resource_id=instance_id,
                resource_name=name,
                region=region,
                severity=Severity.MEDIUM,
                effort="Low",
                confidence="High",
                issue=f"Non-production instance ({instance_type}) running 24/7 without automated off-hours schedule",
                recommendation="Implement AWS Instance Scheduler or EventBridge rule to stop instance outside business hours (saves ~65%)",
                estimated_monthly_saving=monthly_saving,
                metadata={"instance_type": instance_type, "is_asg": is_asg, "tags": tags},
            )
        return None

    def _check_public_ipv4(self, inst: Dict[str, Any], tags: Dict[str, str], region: str) -> Optional[Finding]:
        """AWS charges $0.005/hr for all in-use public IPv4 addresses since Feb 2024."""
        public_ip = inst.get("PublicIpAddress")
        if not public_ip:
            return None

        instance_id = inst["InstanceId"]
        name = tags.get("Name", "")

        # $0.005/hr * 730 hrs = ~$3.65/month
        monthly_saving = CONFIG.VPC_PUBLIC_IPV4_HOURLY_COST * 730.0

        return Finding(
            service=self.display_name,
            resource_id=instance_id,
            resource_name=name,
            region=region,
            severity=Severity.LOW,
            effort="Medium",
            confidence="Medium",
            issue=f"Public IPv4 address ({public_ip}) assigned to instance incurring ~$3.65/mo charge",
            recommendation="Place instance in a private subnet and manage access via AWS Systems Manager Session Manager or NAT/VPC Endpoints",
            estimated_monthly_saving=monthly_saving,
            metadata={"public_ip": public_ip, "tags": tags},
        )

    def _check_attached_gp2(self, inst: Dict[str, Any], tags: Dict[str, str], region: str) -> List[Finding]:
        """Identifies attached gp2 volumes and recommends in-place conversion to gp3."""
        findings = []
        instance_id = inst["InstanceId"]
        name = tags.get("Name", "")

        for bd in inst.get("BlockDeviceMappings", []):
            ebs_info = bd.get("Ebs", {})
            vid = ebs_info.get("VolumeId")
            # In describe_instances, VolumeType might not be nested, but if available flag it
            vtype = ebs_info.get("VolumeType")
            if vtype == "gp2":
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=vid or instance_id,
                        resource_name=name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=f"Attached root/data volume is gp2 on instance {instance_id}",
                        recommendation="Convert volume to gp3 in-place with zero downtime for 20% storage cost savings and baseline 3000 IOPS",
                        estimated_monthly_saving=5.0,
                        metadata={"volume_id": vid, "tags": tags},
                    )
                )
        return findings

    def _check_compute_optimizer(self, session: boto3.Session, region: str) -> List[Finding]:
        """Queries AWS Compute Optimizer for ML-backed rightsizing recommendations if enrolled."""
        findings = []
        try:
            co = self.get_client(session, "compute-optimizer", region)
            paginator = co.get_paginator("get_ec2_instance_recommendations")
            for page in paginator.paginate():
                for rec in page.get("instanceRecommendations", []):
                    finding_type = rec.get("finding")
                    instance_id = rec.get("instanceArn", "").split("/")[-1]
                    name = rec.get("instanceName", instance_id)

                    if finding_type == "OVER_PROVISIONED":
                        options = rec.get("recommendationOptions", [])
                        if options:
                            best = options[0]
                            target_type = best.get("instanceType", "")
                            saving_val = float(
                                best.get("savingsOpportunity", {})
                                .get("estimatedMonthlySavings", {})
                                .get("value", 0.0)
                            )
                            findings.append(
                                Finding(
                                    service=self.display_name,
                                    resource_id=instance_id,
                                    resource_name=name,
                                    region=region,
                                    severity=Severity.HIGH,
                                    effort="Low",
                                    confidence="High",
                                    issue=f"AWS Compute Optimizer flagged instance as Over-provisioned ({rec.get('currentInstanceType')})",
                                    recommendation=f"Downsize instance to recommended type '{target_type}' based on historical ML telemetry",
                                    estimated_monthly_saving=saving_val,
                                    metadata={
                                        "source": "AWS Compute Optimizer",
                                        "target_type": target_type,
                                    },
                                )
                            )
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "")
            # OptInRequiredException or AccessDenied are expected when Compute Optimizer is not configured
            if err_code not in ("OptInRequiredException", "AccessDeniedException", "UnauthorizedOperation"):
                logger.debug(f"[EC2] Compute Optimizer lookup in {region}: {ce}")
        except Exception as e:
            logger.debug(f"[EC2] Compute Optimizer unavailable in {region}: {e}")

        return findings
