import logging
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


class EBSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ebs"

    @property
    def display_name(self) -> str:
        return "Amazon EBS"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ec2 = self.get_client(session, "ec2", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[EBS] Failed to initialize client in {region}: {e}")
            return findings

        price_book = PriceBook(session)

        # 1. Volume Scan & Checks
        live_volume_ids, volume_findings = self._check_volumes(ec2, cw, region, price_book)
        findings.extend(volume_findings)

        # 2. Snapshot Scan & Hygiene Checks
        snapshot_findings = self._check_snapshots(ec2, live_volume_ids, region, price_book)
        findings.extend(snapshot_findings)

        # 3. Fast Snapshot Restore (FSR) Check
        fsr_findings = self._check_fast_snapshot_restores(ec2, region)
        findings.extend(fsr_findings)

        # 4. Data Lifecycle Manager (DLM) Policy Check
        dlm_findings = self._check_dlm_policies(session, region)
        findings.extend(dlm_findings)

        return findings

    # -------------------------------------------------------------------------
    # 1. Volume Checks
    # -------------------------------------------------------------------------
    def _check_volumes(
        self, ec2: Any, cw: Any, region: str, price_book: PriceBook
    ) -> Tuple[Set[str], List[Finding]]:
        """
        Scans EBS volumes for unattached disks, gp2->gp3 migration, io1/io2 overprovisioning,
        and idle attached disks.
        """
        findings: List[Finding] = []
        live_volume_ids: Set[str] = set()
        attached_volume_ids: List[str] = []
        all_volumes: List[Dict[str, Any]] = []

        now = datetime.now(timezone.utc)

        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    all_volumes.append(vol)
                    vid = vol["VolumeId"]
                    live_volume_ids.add(vid)
                    if vol.get("State") == "in-use" and vol.get("Attachments"):
                        attached_volume_ids.append(vid)
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_volumes in {region}")
            return live_volume_ids, findings

        # Batch query CloudWatch I/O metrics for attached volumes to detect idle disks
        vol_io_stats = self._fetch_batched_volume_io(cw, attached_volume_ids)

        for vol in all_volumes:
            vol_id = vol["VolumeId"]
            size_gb = vol.get("Size", 0)
            vol_type = vol.get("VolumeType", "gp3")
            vol_state = vol.get("State", "")
            attachments = vol.get("Attachments", [])
            create_time = vol.get("CreateTime")
            created_days_ago = (now - create_time).days if create_time else None

            tags = {t.get("Key", ""): t.get("Value", "") for t in vol.get("Tags", [])}
            name = tags.get("Name", "")

            # Guard: Skip if tagged with cost-optimizer:ignore
            if any(tags.get(k, "").lower() == "true" for k in CONFIG.IGNORE_TAG_KEYS):
                continue

            rate = price_book.ebs_storage_rate(vol_type, region)
            monthly_cost = size_gb * rate

            common_meta = {
                "size_gb": size_gb,
                "volume_type": vol_type,
                "encrypted": vol.get("Encrypted", False),
                "iops": vol.get("Iops"),
                "throughput": vol.get("Throughput"),
                "availability_zone": vol.get("AvailabilityZone", ""),
                "multi_attach": vol.get("MultiAttachEnabled", False),
                "created_days_ago": created_days_ago,
                "tags": tags,
            }

            # -------------------------------------------------------------
            # Check 1a: Unattached (Orphaned) Volume
            # Reliable signal: State == 'available' (avoids transitional states)
            # -------------------------------------------------------------
            if vol_state == "available":
                # Severity scales with cost and age
                if monthly_cost >= 20.0 or (created_days_ago and created_days_ago > 30):
                    severity = Severity.HIGH
                elif monthly_cost >= 5.0 or (created_days_ago and created_days_ago > 7):
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                age_desc = f" ({created_days_ago} days old)" if created_days_ago else ""
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=vol_id,
                        resource_name=name,
                        region=region,
                        severity=severity,
                        effort="Low",
                        confidence="High",
                        issue=f"Unattached (orphaned) {vol_type} volume of {size_gb} GB{age_desc}",
                        recommendation="Create a final backup snapshot if needed and delete the unused volume",
                        estimated_monthly_saving=monthly_cost,
                        metadata=common_meta,
                    )
                )
                # CRITICAL: Skip overlapping checks (gp2 / io1 / oversized) since deleting it renders them moot!
                continue

            # -------------------------------------------------------------
            # Attached Volume Metadata
            # -------------------------------------------------------------
            first_att = attachments[0] if attachments else {}
            attached_inst_id = first_att.get("InstanceId", "")
            delete_on_termination = first_att.get("DeleteOnTermination", False)
            common_meta["attached_instance_id"] = attached_inst_id
            common_meta["delete_on_termination"] = delete_on_termination

            # -------------------------------------------------------------
            # Check 1b: gp2 -> gp3 Migration (with IOPS formula accounting)
            # -------------------------------------------------------------
            if vol_type == "gp2":
                gp2_rate = price_book.ebs_storage_rate("gp2", region)
                gp3_rate = price_book.ebs_storage_rate("gp3", region)

                # gp2 provides 3 IOPS/GB (baseline 100 up to 16,000 IOPS burst/baseline)
                baseline_iops = min(max(size_gb * 3, 100), 16000)
                # gp3 provides 3,000 IOPS free. Above 3,000, gp3 charges $0.005/provisioned IOPS-month
                extra_iops_cost = max(baseline_iops - 3000, 0) * 0.005
                saving = size_gb * (gp2_rate - gp3_rate) - extra_iops_cost

                # Only recommend gp3 if it actually saves money after accounting for provisioned IOPS
                if saving > 0.50:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=vol_id,
                            resource_name=name,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Low",
                            confidence="High",
                            issue=f"Legacy General Purpose volume (gp2) of {size_gb} GB (provides {baseline_iops} IOPS)",
                            recommendation=(
                                f"Migrate in-place with zero downtime using 'aws ec2 modify-volume --volume-id {vol_id} --volume-type gp3'. "
                                "gp3 includes baseline 3,000 IOPS and 125 MB/s throughput free"
                            ),
                            estimated_monthly_saving=saving,
                            metadata=common_meta,
                        )
                    )

            # -------------------------------------------------------------
            # Check 1c: io1 / io2 -> gp3 Migration
            # io1/io2 has high provisioned IOPS cost ($0.065/IOPS). If <= 16,000 IOPS, gp3 is dramatically cheaper.
            # -------------------------------------------------------------
            if vol_type in ("io1", "io2"):
                provisioned_iops = vol.get("Iops", 0)
                if provisioned_iops <= 16000:
                    # io1/io2 cost: size * $0.125 + iops * $0.065
                    io_cost = size_gb * 0.125 + provisioned_iops * 0.065
                    # gp3 cost: size * $0.08 + extra_iops * $0.005
                    gp3_cost = size_gb * 0.08 + max(provisioned_iops - 3000, 0) * 0.005
                    saving = io_cost - gp3_cost
                    if saving > 5.0:
                        findings.append(
                            Finding(
                                service=self.display_name,
                                resource_id=vol_id,
                                resource_name=name,
                                region=region,
                                severity=Severity.HIGH,
                                effort="Medium",
                                confidence="High",
                                issue=f"Expensive Provisioned IOPS volume ({vol_type}) of {size_gb} GB with {provisioned_iops} IOPS",
                                recommendation=(
                                    f"Convert to gp3 with {provisioned_iops} provisioned IOPS. gp3 supports up to 16,000 IOPS "
                                    "at a fraction of the cost ($0.005 vs $0.065 per IOPS)"
                                ),
                                estimated_monthly_saving=saving,
                                metadata=common_meta,
                            )
                        )

            # -------------------------------------------------------------
            # Check 1d: Idle Attached Volume (Zero I/O operations over lookback)
            # -------------------------------------------------------------
            total_ops = vol_io_stats.get(vol_id)
            if total_ops is not None and total_ops == 0:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=vol_id,
                        resource_name=name,
                        region=region,
                        severity=Severity.MEDIUM,
                        effort="Medium",
                        confidence="High",
                        issue=f"Idle attached EBS volume ({size_gb} GB, {vol_type}) had 0 read/write operations over the last {CONFIG.METRIC_LOOKBACK_DAYS} days",
                        recommendation=f"Review instance {attached_inst_id}; detach, snapshot, and delete volume if no longer needed",
                        estimated_monthly_saving=monthly_cost,
                        metadata=common_meta,
                    )
                )

        return live_volume_ids, findings

    # -------------------------------------------------------------------------
    # 2. Snapshot Checks (Protected & Honest Savings)
    # -------------------------------------------------------------------------
    def _check_snapshots(
        self, ec2: Any, live_volume_ids: Set[str], region: str, price_book: PriceBook
    ) -> List[Finding]:
        """
        Audits EBS snapshots while protecting snapshots in-use by AMIs,
        ignoring AWS Backup/DLM managed snapshots, and calculating honest savings.
        """
        findings: List[Finding] = []
        now = datetime.now(timezone.utc)

        # 2a. Pre-fetch all AMI snapshot IDs to protect snapshots in use
        ami_snapshots: Set[str] = set()
        try:
            images = ec2.describe_images(Owners=["self"]).get("Images", [])
            for img in images:
                for bd in img.get("BlockDeviceMappings", []):
                    if "Ebs" in bd and "SnapshotId" in bd["Ebs"]:
                        ami_snapshots.add(bd["Ebs"]["SnapshotId"])
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_images in {region}")

        # 2b. Collect all user snapshots
        all_snapshots: List[Dict[str, Any]] = []
        snapshots_by_volume: Dict[str, List[Dict[str, Any]]] = {}

        try:
            snap_paginator = ec2.get_paginator("describe_snapshots")
            for page in snap_paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []):
                    all_snapshots.append(snap)
                    vol_id = snap.get("VolumeId", "")
                    if vol_id:
                        snapshots_by_volume.setdefault(vol_id, []).append(snap)
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_snapshots in {region}")
            return findings

        # 2c. Evaluate snapshots
        snap_price_per_gb = CONFIG.EBS_SNAPSHOT_COST_PER_GB

        for snap in all_snapshots:
            snap_id = snap["SnapshotId"]
            snap_size = snap.get("VolumeSize", 0)
            vol_id = snap.get("VolumeId", "")
            create_time = snap.get("StartTime")
            age_days = (now - create_time).days if create_time else 0
            storage_tier = snap.get("StorageTier", "standard")

            tags = {t.get("Key", ""): t.get("Value", "") for t in snap.get("Tags", [])}
            name = tags.get("Name", snap.get("Description", "")[:40])

            # Protection 1: Skip snapshots backing an active AMI (cannot be deleted until AMI deregistered)
            if snap_id in ami_snapshots:
                logger.debug(f"[EBS] Skipping {snap_id}: backs an active AMI")
                continue

            # Protection 2: Skip snapshots managed by AWS Backup or DLM lifecycle
            if any(k.startswith(("aws:backup", "aws:dlm")) for k in tags):
                logger.debug(f"[EBS] Skipping {snap_id}: managed by AWS Backup / DLM")
                continue

            # Detection: Orphaned snapshots (source volume has been deleted)
            is_orphaned = vol_id not in live_volume_ids if vol_id else True

            # Honest Savings: Snapshots are incremental. Deleting an old snapshot only frees
            # unique unreferenced blocks (conservative factor of 30% of source volume size).
            honest_saving = round(snap_size * snap_price_per_gb * 0.30, 2)

            meta = {
                "source_volume_id": vol_id,
                "volume_size_gb": snap_size,
                "age_days": age_days,
                "is_orphaned": is_orphaned,
                "storage_tier": storage_tier,
                "tags": tags,
            }

            # Check 2a: Orphaned Snapshot (Source volume deleted)
            if is_orphaned and age_days > 30:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=snap_id,
                        resource_name=name,
                        region=region,
                        severity=Severity.MEDIUM,
                        effort="Low",
                        confidence="High",
                        issue=f"Orphaned EBS snapshot ({age_days} days old, source volume {vol_id} deleted)",
                        recommendation="Verify backup requirements and delete orphaned snapshot to stop incremental storage fees",
                        estimated_monthly_saving=max(honest_saving, 1.0),
                        metadata=meta,
                    )
                )
                continue

            # Check 2b: Stale Snapshot (> 90 days old)
            if age_days > CONFIG.EBS_STALE_SNAPSHOT_DAYS:
                # Check if candidate for AWS EBS Snapshot Archive (~75% cheaper per GB: $0.0125/GB)
                if age_days > 180 and storage_tier == "standard":
                    archive_saving = round(snap_size * (snap_price_per_gb - 0.0125) * 0.30, 2)
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=snap_id,
                            resource_name=name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Low",
                            confidence="Medium",
                            issue=f"Long-term snapshot ({age_days} days old) in Standard storage tier",
                            recommendation="Archive snapshot to EBS Snapshot Archive tier for ~75% lower storage cost ($0.0125/GB-mo)",
                            estimated_monthly_saving=max(archive_saving, 1.0),
                            metadata=meta,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=snap_id,
                            resource_name=name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Low",
                            confidence="Low",  # Honest confidence: incremental savings vary
                            issue=f"Stale EBS snapshot ({age_days} days old, source volume size: {snap_size} GB)",
                            recommendation=f"Audit retention policy and prune snapshots older than {CONFIG.EBS_STALE_SNAPSHOT_DAYS} days",
                            estimated_monthly_saving=max(honest_saving, 0.50),
                            metadata=meta,
                        )
                    )

        # 2d. Check: Too Many Snapshots per Volume (> 10 snapshots)
        for vol_id, snaps in snapshots_by_volume.items():
            if len(snaps) > 10:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=vol_id,
                        resource_name=f"Volume {vol_id}",
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=f"High snapshot accumulation ({len(snaps)} snapshots retained for volume {vol_id})",
                        recommendation="Implement AWS Data Lifecycle Manager (DLM) to automate snapshot pruning and retain only the latest N backups",
                        estimated_monthly_saving=len(snaps) * 1.50,
                        metadata={"snapshot_count": len(snaps)},
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # 3. Fast Snapshot Restore (FSR) Check
    # -------------------------------------------------------------------------
    def _check_fast_snapshot_restores(self, ec2: Any, region: str) -> List[Finding]:
        """
        Fast Snapshot Restore (FSR) costs $0.75 per DSR per AZ per hour ($547.50/AZ/mo).
        Leaving it enabled accidentally produces massive hidden bills.
        """
        findings: List[Finding] = []
        try:
            resp = ec2.describe_fast_snapshot_restores(
                Filters=[{"Name": "state", "Values": ["enabled", "enabling"]}]
            )
            for item in resp.get("FastSnapshotRestores", []):
                snap_id = item.get("SnapshotId")
                az = item.get("AvailabilityZone")
                # $0.75/hr * 730 = $547.50/month per AZ
                monthly_cost = 0.75 * 730.0
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=snap_id,
                        resource_name=f"FSR-{az}",
                        region=region,
                        severity=Severity.HIGH,
                        effort="Low",
                        confidence="High",
                        issue=f"Fast Snapshot Restore (FSR) enabled in {az} incurring $0.75/hour fee ($547.50/mo)",
                        recommendation=f"Disable FSR on snapshot {snap_id} in {az} if fast instant volume initialization is no longer actively needed",
                        estimated_monthly_saving=monthly_cost,
                        metadata={"availability_zone": az, "hourly_rate": 0.75},
                    )
                )
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "")
            if err_code not in ("InvalidAction", "AccessDeniedException", "UnauthorizedOperation"):
                self.handle_client_error(ce, f"describe_fast_snapshot_restores in {region}")
        return findings

    # -------------------------------------------------------------------------
    # 4. Data Lifecycle Manager (DLM) Governance Check
    # -------------------------------------------------------------------------
    def _check_dlm_policies(self, session: boto3.Session, region: str) -> List[Finding]:
        """Checks if AWS Data Lifecycle Manager (DLM) is configured in the region."""
        findings: List[Finding] = []
        try:
            dlm = self.get_client(session, "dlm", region)
            resp = dlm.get_lifecycle_policies(State="ENABLED")
            policies = resp.get("Policies", [])
            if not policies:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id="dlm-governance",
                        resource_name="EBS Lifecycle Governance",
                        region=region,
                        severity=Severity.LOW,
                        effort="Medium",
                        confidence="High",
                        issue="No AWS Data Lifecycle Manager (DLM) policies configured in this region",
                        recommendation="Create DLM policies to automatically snapshot EBS volumes and enforce automated retention/deletion schedules",
                        estimated_monthly_saving=25.0,
                    )
                )
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "")
            if err_code not in ("AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClientException"):
                logger.debug(f"[EBS] DLM check in {region}: {ce}")
        except Exception as e:
            logger.debug(f"[EBS] DLM unavailable in {region}: {e}")
        return findings

    # -------------------------------------------------------------------------
    # Batch CloudWatch I/O Querying for Attached Volumes
    # -------------------------------------------------------------------------
    def _fetch_batched_volume_io(self, cw: Any, volume_ids: List[str]) -> Dict[str, float]:
        """
        Batches CloudWatch get_metric_data calls to check if attached volumes had any I/O operations.
        Queries VolumeReadOps + VolumeWriteOps.
        """
        results: Dict[str, float] = {}
        if not volume_ids:
            return results

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=CONFIG.METRIC_LOOKBACK_DAYS)

        # 2 queries per volume (ReadOps + WriteOps) = chunk size 200 volumes (400 queries)
        for chunk in _chunks(volume_ids, 200):
            queries = []
            lookup: Dict[str, Tuple[str, str]] = {}

            for idx, vid in enumerate(chunk):
                for metric_name, key in (("VolumeReadOps", "read"), ("VolumeWriteOps", "write")):
                    qid = f"{key}_{idx}"
                    lookup[qid] = (vid, key)
                    queries.append(
                        {
                            "Id": qid,
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/EBS",
                                    "MetricName": metric_name,
                                    "Dimensions": [{"Name": "VolumeId", "Value": vid}],
                                },
                                "Period": 86400 * CONFIG.METRIC_LOOKBACK_DAYS,
                                "Stat": "Sum",
                            },
                        }
                    )

            try:
                paginator = cw.get_paginator("get_metric_data")
                vol_sums: Dict[str, float] = {vid: 0.0 for vid in chunk}
                for page in paginator.paginate(MetricDataQueries=queries, StartTime=start_time, EndTime=end_time):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in lookup:
                            vid, _ = lookup[qid]
                            vals = res.get("Values", [])
                            vol_sums[vid] += sum(vals)

                results.update(vol_sums)
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for EBS Volume I/O")

        return results
