"""
Production-Grade Elastic Load Balancing (ELB) Waste & Optimization Scanner.

Detects:
1. Classic Load Balancers (CLBs):
   - CLB with 0 registered instances (HIGH waste).
   - CLB with all registered instances OutOfService (MEDIUM service outage / waste).
   - Idle CLB with 0 traffic over 30 days (HIGH waste).
   - Active CLB migration to ALB/NLB (LOW modernization savings ~ $1.80/mo).
2. Application, Network & Gateway Load Balancers (v2):
   - Unused LBs with no active listeners (HIGH waste).
   - HTTP->HTTPS redirect / fixed-response LBs with 0 traffic (HIGH waste; active ones protected).
   - Empty target groups with no registered targets (HIGH waste).
   - Target outage alerts where all targets are unhealthy (MEDIUM reliability alert, never recommend terminate).
   - Idle LBs with healthy targets but 0 traffic over 30 days (HIGH waste).
   - Non-production LBs running 24/7 with near-zero traffic (LOW off-hours schedule candidate).
3. Architecture & Hygiene:
   - ALB consolidation opportunities for multiple low-traffic ALBs in the same VPC.
   - Orphaned target groups not attached to any load balancer.
   - Cross-zone data transfer cost on high-traffic NLBs.

Production Features:
- Real-time regional pricing via AWS Price List Service API (PriceBook) including public IPv4 hourly charges.
- Batched CloudWatch metric queries (400 queries per call) for 30-day traffic auditing.
- Batched tag lookups (20 ARNs per call) to eliminate N+1 API bottlenecks.
- Single paginated describe_target_groups call mapping to load balancers.
- Infrastructure-as-Code & controller protection (Kubernetes AWS Load Balancer Controller, Beanstalk, CloudFormation).
- Deletion protection audit and 7-day creation grace period.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
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


# Traffic metric configuration by LB type
V2_TRAFFIC_METRICS = {
    "application": ("AWS/ApplicationELB", "RequestCount"),
    "network": ("AWS/NetworkELB", "ProcessedBytes"),
    "gateway": ("AWS/GatewayELB", "ProcessedBytes"),
}


class ELBScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "elb"

    @property
    def display_name(self) -> str:
        return "Elastic Load Balancing (ELB)"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        price_book = PriceBook(session)
        now = datetime.now(timezone.utc)
        lookback_days = CONFIG.ELB_LOOKBACK_DAYS
        start_time = now - timedelta(days=lookback_days)

        try:
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[ELB] Could not initialize CloudWatch client in {region}: {e}")
            cw = None

        # =====================================================================
        # 1. Classic Load Balancers (v1 / CLB)
        # =====================================================================
        try:
            elb_v1 = self.get_client(session, "elb", region)
            clb_findings = self._scan_classic_load_balancers(
                elb_v1=elb_v1,
                cw=cw,
                price_book=price_book,
                region=region,
                now=now,
                start_time=start_time,
                lookback_days=lookback_days,
            )
            findings.extend(clb_findings)
        except ClientError as ce:
            self.handle_client_error(ce, f"Classic Load Balancers in {region}")
        except Exception as e:
            logger.debug(f"[ELB] Classic Load Balancer scan skipped: {e}")

        # =====================================================================
        # 2. Application, Network, & Gateway Load Balancers (v2)
        # =====================================================================
        try:
            elbv2 = self.get_client(session, "elbv2", region)
            v2_findings = self._scan_v2_load_balancers(
                elbv2=elbv2,
                cw=cw,
                price_book=price_book,
                region=region,
                now=now,
                start_time=start_time,
                lookback_days=lookback_days,
            )
            findings.extend(v2_findings)
        except ClientError as ce:
            self.handle_client_error(ce, f"ELBv2 Load Balancers in {region}")
        except Exception as e:
            logger.debug(f"[ELB] ELBv2 scan failed in {region}: {e}")

        return findings

    # -------------------------------------------------------------------------
    # Classic Load Balancers Scanner
    # -------------------------------------------------------------------------
    def _scan_classic_load_balancers(
        self,
        elb_v1: Any,
        cw: Any,
        price_book: PriceBook,
        region: str,
        now: datetime,
        start_time: datetime,
        lookback_days: int,
    ) -> List[Finding]:
        findings: List[Finding] = []
        paginator = elb_v1.get_paginator("describe_load_balancers")
        all_clbs: List[Dict[str, Any]] = []

        for page in paginator.paginate():
            all_clbs.extend(page.get("LoadBalancerDescriptions", []))

        if not all_clbs:
            return findings

        # Batch fetch tags for CLBs
        clb_names = [lb["LoadBalancerName"] for lb in all_clbs]
        tags_by_name = self._batch_fetch_clb_tags(elb_v1, clb_names)

        # Batch fetch 30-day traffic for CLBs
        traffic_map: Dict[str, float] = {}
        if cw:
            traffic_map = self._fetch_clb_traffic(cw, clb_names, start_time, now)

        for lb in all_clbs:
            name = lb.get("LoadBalancerName", "")
            try:
                # 1. Grace period check (7 days)
                created_time = lb.get("CreatedTime")
                if created_time:
                    age_days = (now - created_time).days
                    if age_days < CONFIG.ELB_GRACE_PERIOD_DAYS:
                        continue
                else:
                    age_days = 30

                # 2. Dimensions & Pricing
                scheme = lb.get("Scheme", "internal")
                internet_facing = scheme == "internet-facing"
                azs = lb.get("AvailabilityZones", [])
                az_count = len(azs)
                instances = lb.get("Instances", [])
                instances_count = len(instances)

                # Real-time base cost + public IPv4 charges
                monthly_base = price_book.elb_monthly_base(
                    "classic", az_count=az_count, internet_facing=internet_facing, region=region
                )
                alb_monthly_base = price_book.elb_monthly_base(
                    "application", az_count=az_count, internet_facing=internet_facing, region=region
                )

                tags = tags_by_name.get(name, {})
                managed_by = self._detect_manager(tags)

                common_meta = {
                    "type": "classic",
                    "scheme": scheme,
                    "internet_facing": internet_facing,
                    "az_count": az_count,
                    "instances_count": instances_count,
                    "age_days": age_days,
                    "monthly_base_cost": round(monthly_base, 2),
                    "managed_by": managed_by,
                    "tags": tags,
                }

                # Case A: 0 Registered Instances
                if instances_count == 0:
                    rec = (
                        f"Decommission the owning {managed_by} stack or delete this unattached Classic Load Balancer"
                        if managed_by
                        else "Verify DNS routing and delete the Classic Load Balancer (nothing is registered behind it)"
                    )
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="High",
                            issue=f"Classic Load Balancer with 0 registered instances (incurring ${monthly_base:.2f}/mo)",
                            recommendation=rec,
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # Case B: Instances Registered -> Check Instance Health
                all_out_of_service = False
                try:
                    health_resp = elb_v1.describe_instance_health(LoadBalancerName=name)
                    health_states = [
                        i.get("State", "") for i in health_resp.get("InstanceStates", [])
                    ]
                    if health_states and all(s == "OutOfService" for s in health_states):
                        all_out_of_service = True
                except ClientError:
                    pass

                if all_out_of_service:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Medium",
                            confidence="High",
                            issue=(
                                f"Classic Load Balancer with all {instances_count} registered instances OutOfService "
                                f"(incurring ${monthly_base:.2f}/mo)"
                            ),
                            recommendation=(
                                "Investigate backend EC2 health check failures or decommission abandoned load balancer"
                            ),
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # Case C: Check Traffic over lookback window
                traffic_bytes = traffic_map.get(name, 0.0)
                if traffic_bytes == 0.0 and age_days >= lookback_days:
                    rec = (
                        f"Decommission via {managed_by} or delete this idle load balancer"
                        if managed_by
                        else "Verify application traffic; decommission idle load balancer"
                    )
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="Medium",
                            issue=(
                                f"Idle Classic Load Balancer (registered instances InService, but 0 traffic over {lookback_days} days)"
                            ),
                            recommendation=rec,
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # Case D: Active CLB -> Modernization recommendation (ALB/NLB)
                # Realistic delta: CLB base ($18.25) vs ALB base ($16.42) = ~$1.83/mo
                migration_saving = max(monthly_base - alb_monthly_base, 0.0)
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=name,
                        resource_name=name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Medium",
                        confidence="High",
                        issue=f"Legacy Classic Load Balancer in use ({instances_count} registered instances)",
                        recommendation=(
                            "Migrate to Application Load Balancer (ALB) or Network Load Balancer (NLB) for modern protocols "
                            f"(HTTP/2, gRPC), enhanced path/host routing, and ~${migration_saving:.2f}/mo base savings"
                        ),
                        estimated_monthly_saving=migration_saving,
                        metadata=common_meta,
                    )
                )

            except ClientError as ce:
                self.handle_client_error(ce, f"Classic Load Balancer {name}")

        return findings

    # -------------------------------------------------------------------------
    # ELBv2 Scanner (Application, Network, Gateway LBs)
    # -------------------------------------------------------------------------
    def _scan_v2_load_balancers(
        self,
        elbv2: Any,
        cw: Any,
        price_book: PriceBook,
        region: str,
        now: datetime,
        start_time: datetime,
        lookback_days: int,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Paginate all v2 Load Balancers
        all_lbs: List[Dict[str, Any]] = []
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            all_lbs.extend(page.get("LoadBalancers", []))

        # 2. Paginate all Target Groups in ONE pass (eliminates N+1 describe_target_groups)
        tgs_by_lb: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        all_target_groups: List[Dict[str, Any]] = []
        try:
            tg_paginator = elbv2.get_paginator("describe_target_groups")
            for page in tg_paginator.paginate():
                for tg in page.get("TargetGroups", []):
                    all_target_groups.append(tg)
                    for lb_arn in tg.get("LoadBalancerArns", []):
                        tgs_by_lb[lb_arn].append(tg)
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_target_groups in {region}")

        # 3. Check for Unused Target Groups (Hygiene)
        for tg in all_target_groups:
            tg_arn = tg.get("TargetGroupArn", "")
            tg_name = tg.get("TargetGroupName", "")
            lb_arns = tg.get("LoadBalancerArns", [])
            if not lb_arns:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=tg_arn,
                        resource_name=tg_name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=f"Unused Target Group '{tg_name}' not associated with any Load Balancer",
                        recommendation="Audit target group and delete if no longer referenced in launch templates or CI/CD",
                        estimated_monthly_saving=0.0,
                        metadata={"target_group_type": tg.get("TargetType", "instance")},
                    )
                )

        if not all_lbs:
            return findings

        # 4. Batch fetch tags for all v2 LBs (chunks of 20 ARNs)
        lb_arns = [lb["LoadBalancerArn"] for lb in all_lbs]
        tags_by_arn = self._batch_fetch_v2_tags(elbv2, lb_arns)

        # 5. Batch fetch 30-day traffic metrics from CloudWatch
        traffic_map: Dict[str, float] = {}
        if cw:
            traffic_map = self._fetch_v2_traffic(cw, all_lbs, start_time, now)

        # Track active ALBs by VPC for ALB consolidation detection
        albs_by_vpc: Dict[str, List[Tuple[Dict[str, Any], float]]] = defaultdict(list)

        # 6. Evaluate each Load Balancer
        for lb in all_lbs:
            arn = lb.get("LoadBalancerArn", "")
            name = lb.get("LoadBalancerName", "")
            lb_type = lb.get("Type", "application")
            vpc_id = lb.get("VpcId", "")

            try:
                # A. Grace Period: Skip LBs created within the last 7 days
                created_time = lb.get("CreatedTime")
                if created_time:
                    age_days = (now - created_time).days
                    if age_days < CONFIG.ELB_GRACE_PERIOD_DAYS:
                        continue
                else:
                    age_days = 30

                # B. Dimensions & Real-Time Pricing
                scheme = lb.get("Scheme", "internal")
                internet_facing = scheme == "internet-facing"
                azs = lb.get("AvailabilityZones", [])
                az_count = len(azs)

                monthly_base = price_book.elb_monthly_base(
                    lb_type, az_count=az_count, internet_facing=internet_facing, region=region
                )

                tags = tags_by_arn.get(arn, {})
                managed_by = self._detect_manager(tags)

                # C. Check Load Balancer Attributes (Deletion Protection & Cross-Zone)
                del_prot_enabled, cross_zone_enabled = self._fetch_lb_attributes(elbv2, arn)

                # D. Traffic stats
                traffic_30d = traffic_map.get(arn, 0.0)

                common_meta = {
                    "arn": arn,
                    "type": lb_type,
                    "scheme": scheme,
                    "internet_facing": internet_facing,
                    "az_count": az_count,
                    "vpc_id": vpc_id,
                    "age_days": age_days,
                    "traffic_30d": round(traffic_30d, 2),
                    "monthly_base_cost": round(monthly_base, 2),
                    "deletion_protection": del_prot_enabled,
                    "cross_zone": cross_zone_enabled,
                    "managed_by": managed_by,
                    "tags": tags,
                }

                # Helper to format recommendation respecting managed controllers & deletion protection
                def make_rec(action_desc: str) -> str:
                    parts = []
                    if del_prot_enabled:
                        parts.append("Disable deletion protection first")
                    if managed_by:
                        parts.append(f"Manage or remove via {managed_by} to prevent auto-recreation")
                    else:
                        parts.append(action_desc)
                    return ". ".join(parts)

                # E. Check Listeners
                listeners = elbv2.describe_listeners(LoadBalancerArn=arn).get("Listeners", [])
                if not listeners:
                    # Unambiguously unused: no listeners configured
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="High",
                            issue=f"Unused {lb_type.upper()} with 0 active listeners (costing ${monthly_base:.2f}/mo)",
                            recommendation=make_rec("Verify nothing points to this DNS name and delete the load balancer"),
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # F. Classify Target Groups and Targets
                tgs_for_lb = tgs_by_lb.get(arn, [])
                common_meta["target_group_count"] = len(tgs_for_lb)

                # Case 1: No Target Groups attached (e.g. HTTP->HTTPS Redirect / Fixed-Response ALB)
                if not tgs_for_lb:
                    if traffic_30d == 0.0 and age_days >= lookback_days:
                        # 0 requests on a redirect/fixed-response ALB -> Idle waste
                        findings.append(
                            Finding(
                                service=self.display_name,
                                resource_id=arn,
                                resource_name=name,
                                region=region,
                                severity=Severity.HIGH,
                                effort="Low",
                                confidence="Medium",
                                issue=(
                                    f"Idle redirect/fixed-response {lb_type.upper()} (0 requests over {lookback_days} days, "
                                    f"costing ${monthly_base:.2f}/mo)"
                                ),
                                recommendation=make_rec("Decommission unused redirect load balancer or consolidate rules onto existing active ALBs"),
                                estimated_monthly_saving=monthly_base,
                                metadata=common_meta,
                            )
                        )
                    # If traffic > 0, it's a legitimate active redirect/fixed-response ALB - DO NOT flag!
                    continue

                # Case 2: Target Groups Attached -> Query Target Health
                states: List[str] = []
                for tg in tgs_for_lb:
                    tg_arn = tg["TargetGroupArn"]
                    try:
                        th_resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                        for th in th_resp.get("TargetHealthDescriptions", []):
                            states.append(th.get("TargetHealth", {}).get("State", "unknown"))
                    except ClientError:
                        pass

                common_meta["target_count"] = len(states)
                common_meta["healthy_count"] = sum(1 for s in states if s in ("healthy", "initial"))
                common_meta["unhealthy_count"] = sum(1 for s in states if s == "unhealthy")

                # Subcase 2a: No targets registered across any target group
                if not states:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="High",
                            issue=(
                                f"{lb_type.upper()} with 0 registered targets across {len(tgs_for_lb)} target group(s) "
                                f"(costing ${monthly_base:.2f}/mo)"
                            ),
                            recommendation=make_rec("Register backend targets or decommission unused load balancer"),
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # Subcase 2b: All targets are UNHEALTHY -> Outage / Health Check failure
                # IMPORTANT: Never recommend deleting an active service during an outage!
                if all(s == "unhealthy" for s in states):
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Medium",
                            confidence="High",
                            issue=(
                                f"{lb_type.upper()} service outage: all {len(states)} registered targets are unhealthy "
                                f"(costing ${monthly_base:.2f}/mo)"
                            ),
                            recommendation=(
                                "DO NOT delete load balancer. Investigate target application crashes, security group "
                                "port blocking, or misconfigured health check paths"
                            ),
                            estimated_monthly_saving=0.0,  # Reliability issue, not cost waste
                            metadata=common_meta,
                        )
                    )
                    continue

                # Subcase 2c: Targets healthy/initial -> Check 30-day traffic
                unit_label = "requests" if lb_type == "application" else "bytes"
                if traffic_30d == 0.0 and age_days >= lookback_days:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="Medium",
                            issue=(
                                f"Idle {lb_type.upper()} with healthy targets but 0 {unit_label} over {lookback_days} days "
                                f"(costing ${monthly_base:.2f}/mo)"
                            ),
                            recommendation=make_rec("Audit DNS/CNAME records and application dependencies; decommission if abandoned"),
                            estimated_monthly_saving=monthly_base,
                            metadata=common_meta,
                        )
                    )
                    continue

                # Track active ALBs for VPC-level consolidation
                if lb_type == "application":
                    albs_by_vpc[vpc_id].append((lb, traffic_30d))

                # Subcase 2d: Non-production 24/7 check
                is_non_prod = False
                for k, v in tags.items():
                    if k.lower() in ("env", "environment") and any(
                        env in v.lower() for env in ("dev", "test", "stage", "staging", "nonprod")
                    ):
                        is_non_prod = True
                        break

                daily_traffic = traffic_30d / max(lookback_days, 1)
                if is_non_prod and daily_traffic < 100.0:
                    # Non-prod environment with minimal traffic running 24/7
                    saving_non_prod = monthly_base * 0.65  # ~65% savings with off-hours scheduling
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Medium",
                            confidence="Medium",
                            issue=(
                                f"Non-production {lb_type.upper()} running 24/7 with low traffic "
                                f"({daily_traffic:.0f} {unit_label}/day)"
                            ),
                            recommendation=(
                                "Schedule non-prod environments to spin down outside business hours or consolidate "
                                "onto a shared development ALB"
                            ),
                            estimated_monthly_saving=saving_non_prod,
                            metadata=common_meta,
                        )
                    )

                # Subcase 2e: NLB Cross-Zone Transfer Costs
                if lb_type == "network" and cross_zone_enabled and traffic_30d > (1000 * 1024**3):  # > 1 TB
                    # Cross-AZ traffic costs $0.01/GB in each direction
                    traffic_gb = traffic_30d / (1024**3)
                    cross_zone_saving = (traffic_gb * 0.66) * 0.01  # ~2/3 cross-AZ in 3-AZ setup
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Medium",
                            confidence="Low",
                            issue=(
                                f"High cross-zone traffic on NLB ({traffic_gb:.1f} GB/mo) with cross-zone load balancing enabled"
                            ),
                            recommendation=(
                                "Evaluate disabling cross-zone load balancing if client traffic is evenly distributed across AZs, "
                                f"potentially saving ~${cross_zone_saving:.2f}/mo in inter-AZ data transfer fees"
                            ),
                            estimated_monthly_saving=cross_zone_saving,
                            metadata=common_meta,
                        )
                    )

            except ClientError as ce:
                self.handle_client_error(ce, f"Load Balancer {name} ({arn})")

        # ---------------------------------------------------------------------
        # 7. ALB Consolidation Opportunities by VPC
        # ---------------------------------------------------------------------
        for vpc_id, alb_list in albs_by_vpc.items():
            if len(alb_list) >= 2:
                # Check if multiple ALBs have low average traffic
                low_traffic_albs = [
                    (lb, t)
                    for lb, t in alb_list
                    if (t / max(lookback_days, 1)) < CONFIG.ELB_CONSOLIDATION_DAILY_REQUESTS
                ]
                if len(low_traffic_albs) >= 2:
                    consol_count = len(low_traffic_albs) - 1
                    avg_base = price_book.elb_monthly_base("application", region=region)
                    consol_savings = consol_count * avg_base
                    alb_names = [lb["LoadBalancerName"] for lb, _ in low_traffic_albs]
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=vpc_id,
                            resource_name=f"VPC {vpc_id} ({len(low_traffic_albs)} ALBs)",
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="High",
                            confidence="Medium",
                            issue=(
                                f"ALB Consolidation opportunity: {len(low_traffic_albs)} low-traffic ALBs in VPC '{vpc_id}' "
                                f"({', '.join(alb_names[:3])}{'...' if len(alb_names) > 3 else ''})"
                            ),
                            recommendation=(
                                f"Consolidate {len(low_traffic_albs)} separate microservice ALBs onto a single shared ALB "
                                f"using host-based and path-based listener rules, eliminating base fees and public IPv4 charges "
                                f"for {consol_count} load balancer(s)"
                            ),
                            estimated_monthly_saving=consol_savings,
                            metadata={
                                "vpc_id": vpc_id,
                                "alb_count": len(low_traffic_albs),
                                "alb_names": alb_names,
                            },
                        )
                    )

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    @staticmethod
    def _detect_manager(tags: Dict[str, str]) -> Optional[str]:
        """Identifies if a load balancer is managed by Kubernetes, Beanstalk, or CloudFormation."""
        if any(
            k.startswith(("elbv2.k8s.aws", "ingress.k8s.aws", "kubernetes.io/cluster"))
            for k in tags
        ):
            return "Kubernetes (AWS Load Balancer Controller)"
        if "elasticbeanstalk:environment-name" in tags:
            return "Elastic Beanstalk"
        if "aws:cloudformation:stack-name" in tags:
            return "AWS CloudFormation"
        return None

    def _fetch_lb_attributes(self, elbv2: Any, arn: str) -> Tuple[bool, bool]:
        """Fetches deletion_protection.enabled and cross_zone_load_balancing.enabled."""
        del_prot = False
        cross_zone = False
        try:
            attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn).get("Attributes", [])
            for a in attrs:
                k, v = a.get("Key"), a.get("Value")
                if k == "deletion_protection.enabled" and v == "true":
                    del_prot = True
                elif k == "cross_zone_load_balancing.enabled" and v == "true":
                    cross_zone = True
        except ClientError:
            pass
        return del_prot, cross_zone

    def _batch_fetch_v2_tags(self, elbv2: Any, arns: List[str]) -> Dict[str, Dict[str, str]]:
        """Batch fetches tags for v2 load balancers in chunks of 20 ARNs."""
        tags_by_arn: Dict[str, Dict[str, str]] = {}
        for chunk in _chunks(arns, 20):
            try:
                resp = elbv2.describe_tags(ResourceArns=chunk)
                for td in resp.get("TagDescriptions", []):
                    arn = td.get("ResourceArn", "")
                    tags_by_arn[arn] = {t["Key"]: t["Value"] for t in td.get("Tags", [])}
            except ClientError as ce:
                self.handle_client_error(ce, "batch describe_tags for ELBv2")
        return tags_by_arn

    def _batch_fetch_clb_tags(self, elb_v1: Any, names: List[str]) -> Dict[str, Dict[str, str]]:
        """Batch fetches tags for Classic Load Balancers in chunks of 20 names."""
        tags_by_name: Dict[str, Dict[str, str]] = {}
        for chunk in _chunks(names, 20):
            try:
                resp = elb_v1.describe_tags(LoadBalancerNames=chunk)
                for td in resp.get("TagDescriptions", []):
                    name = td.get("LoadBalancerName", "")
                    tags_by_name[name] = {t["Key"]: t["Value"] for t in td.get("Tags", [])}
            except ClientError as ce:
                self.handle_client_error(ce, "batch describe_tags for CLB")
        return tags_by_name

    def _fetch_v2_traffic(
        self,
        cw: Any,
        lbs: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
    ) -> Dict[str, float]:
        """
        Batches CloudWatch get_metric_data queries for ELBv2 traffic (RequestCount or ProcessedBytes).
        Batches up to 400 queries per call.
        """
        results: Dict[str, float] = {}
        if not lbs:
            return results

        for chunk in _chunks(lbs, 400):
            queries = []
            lookup: Dict[str, str] = {}

            for idx, lb in enumerate(chunk):
                arn = lb.get("LoadBalancerArn", "")
                lb_type = lb.get("Type", "application")

                if "loadbalancer/" not in arn:
                    continue

                dim_val = arn.split("loadbalancer/", 1)[1]
                ns, metric = V2_TRAFFIC_METRICS.get(
                    lb_type, ("AWS/ApplicationELB", "RequestCount")
                )
                qid = f"q_{idx}"
                lookup[qid] = arn

                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": ns,
                                "MetricName": metric,
                                "Dimensions": [{"Name": "LoadBalancer", "Value": dim_val}],
                            },
                            "Period": 86400 * CONFIG.ELB_LOOKBACK_DAYS,
                            "Stat": "Sum",
                        },
                    }
                )

            if not queries:
                continue

            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=queries, StartTime=start, EndTime=end
                ):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in lookup:
                            arn = lookup[qid]
                            results[arn] = sum(res.get("Values", []))
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for ELBv2 traffic")

        return results

    def _fetch_clb_traffic(
        self,
        cw: Any,
        names: List[str],
        start: datetime,
        end: datetime,
    ) -> Dict[str, float]:
        """
        Batches CloudWatch get_metric_data queries for Classic Load Balancer EstimatedProcessedBytes.
        """
        results: Dict[str, float] = {}
        if not names:
            return results

        for chunk in _chunks(names, 400):
            queries = []
            lookup: Dict[str, str] = {}

            for idx, name in enumerate(chunk):
                qid = f"q_clb_{idx}"
                lookup[qid] = name
                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/ELB",
                                "MetricName": "EstimatedProcessedBytes",
                                "Dimensions": [{"Name": "LoadBalancerName", "Value": name}],
                            },
                            "Period": 86400 * CONFIG.ELB_LOOKBACK_DAYS,
                            "Stat": "Sum",
                        },
                    }
                )

            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=queries, StartTime=start, EndTime=end
                ):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in lookup:
                            name = lookup[qid]
                            results[name] = sum(res.get("Values", []))
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for CLB traffic")

        return results
