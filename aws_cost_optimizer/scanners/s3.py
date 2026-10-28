"""
Production-Grade AWS S3 Cost, Storage & Configuration Optimization Scanner.

Comprehensive Audit Areas:
1. AccessDenied & Permission Resilience:
   - Distinguishes 'NoSuchLifecycleConfiguration' (valid empty config) from 'AccessDenied'
     or other IAM permission errors.
   - Rolls up unauditable buckets into a single regional summary finding rather than emitting
     false-positive missing configuration alerts.
2. Single Merged Lifecycle Findings (No Finding Sprawl):
   - Audits lifecycle rules holistically: transition/expiration, abort incomplete multipart uploads,
     noncurrent version expiry, and expired object delete markers.
   - Consolidates all lifecycle gaps for a bucket into ONE single actionable finding with
     clear effort and confidence ratings.
3. Accurate CloudWatch Storage & Object Sizing (Zero Dollar Guesses):
   - Batches CloudWatch daily storage metrics (BucketSizeBytes for StandardStorage and
     NumberOfObjects for AllStorageTypes) per region using get_metric_data.
   - Calculates real cost deltas between S3 Standard ($0.023/GB-mo) and Standard-IA ($0.0125/GB-mo)
     scaled by an assumed cold-data fraction (default 50%).
   - Flags small-object heavy buckets (< 128 KB avg object size) where Standard-IA transitions
     are uneconomical due to minimum billable size and transition request fees.
   - Drops negligible findings (< $1.00/mo) to eliminate noise.
4. Safe SSE-KMS & S3 Bucket Keys Auditing:
   - Identifies SSE-KMS encrypted buckets missing S3 Bucket Keys.
   - Explicitly warns that Bucket Keys apply only to new objects (existing objects require in-place copy)
     and that encryption context changes from object ARN to bucket ARN (checking IAM/KMS policies).
   - Skips dual-layer KMS (aws:kms:dsse).
5. Account-Level Cost Explorer Spend Sizing:
   - Groups 30-day S3 spend by USAGE_TYPE (TimedStorage, Requests, DataTransfer, Retrieval)
     to establish whether storage, API calls, or egress drives costs.
6. Guardrails & Infrastructure as Code:
   - Respects ignore tags ('cost-optimizer:ignore', etc.).
   - Detects CloudFormation managed buckets ('aws:cloudformation:stack-name') and advises template updates.
   - Skips CDK bootstrap buckets ('cdk-*-assets-*') and newly created buckets (< 3 days).
7. Advanced Storage & Cost Traps:
   - Server access logging target buckets without lifecycle policies (grow unbounded).
   - S3 Transfer Acceleration enabled (extra $0.04-$0.08/GB transfer charges).
   - Cross-region replication (duplicate storage and inter-region transfer charges).
   - Early-deletion trap detection in existing lifecycle rules (expiration shorter than class minimum duration).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import fnmatch
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")

# Storage class minimum duration (days)
STORAGE_CLASS_MIN_DAYS: Dict[str, int] = {
    "STANDARD_IA": 30,
    "ONEZONE_IA": 30,
    "GLACIER": 90,
    "GLACIER_IR": 90,
    "DEEP_ARCHIVE": 180,
}


def _covers_bucket(rule: Dict[str, Any]) -> bool:
    """Checks if a lifecycle rule applies to the whole bucket (not scoped to a prefix/tag)."""
    f = rule.get("Filter")
    if f is None:
        # Legacy format: top-level Prefix
        return rule.get("Prefix", "") == ""
    # Modern format: Filter dict
    return f in ({}, {"Prefix": ""})


class S3Scanner(BaseScanner):
    @property
    def name(self) -> str:
        return "s3"

    @property
    def display_name(self) -> str:
        return "Amazon S3"

    @property
    def is_global(self) -> bool:
        return True

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc)

        try:
            s3_global = self.get_client(session, "s3", "us-east-1")
            buckets = s3_global.list_buckets().get("Buckets", [])
        except Exception as e:
            logger.error(f"[S3] Could not list buckets: {e}")
            return findings

        if not buckets:
            return findings

        # 1. Account-level Cost Explorer Spend Sizing (Storage vs Requests vs Transfer)
        ce_finding = self._audit_s3_cost_explorer(session, region, now)
        if ce_finding:
            findings.append(ce_finding)

        # 2. Resolve Bucket Regions and Filter Ignored / New Buckets
        bucket_metas: List[Dict[str, Any]] = []
        for b in buckets:
            b_name = b.get("Name", "")
            created_at = b.get("CreationDate")

            # Age guard: skip buckets younger than 3 days (metrics take 24-48 hours to publish)
            if created_at and (now - created_at).days < 3:
                continue

            # Skip CDK bootstrap asset buckets
            if fnmatch.fnmatch(b_name, "cdk-*-assets-*"):
                continue

            # Resolve bucket region
            try:
                loc_resp = s3_global.get_bucket_location(Bucket=b_name)
                b_region = loc_resp.get("LocationConstraint") or "us-east-1"
                if b_region == "EU":
                    b_region = "eu-west-1"
            except Exception:
                b_region = "us-east-1"

            bucket_metas.append({
                "name": b_name,
                "region": b_region,
                "created_at": created_at,
            })

        # 3. Group Buckets by Region for Batched CloudWatch Storage Metrics
        region_buckets: Dict[str, List[str]] = {}
        for bm in bucket_metas:
            region_buckets.setdefault(bm["region"], []).append(bm["name"])

        bucket_stats: Dict[str, Dict[str, float]] = {}
        for reg, b_names in region_buckets.items():
            stats = self._fetch_batched_bucket_stats(session, reg, b_names, now)
            bucket_stats.update(stats)

        # 4. Multi-threaded Per-Bucket Audit
        unauditable_buckets: Dict[str, List[str]] = {}
        log_target_buckets: Set[str] = set()

        max_workers = min(16, len(bucket_metas)) if bucket_metas else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_bucket = {
                executor.submit(
                    self._audit_single_bucket,
                    session,
                    bm["name"],
                    bm["region"],
                    bm["created_at"],
                    bucket_stats.get(bm["name"], {"std_bytes": 0.0, "objects": 0.0}),
                    now,
                ): bm["name"]
                for bm in bucket_metas
            }

            for future in as_completed(future_to_bucket):
                b_name = future_to_bucket[future]
                try:
                    b_findings, target_log_bucket, err_code = future.result()
                    if err_code:
                        unauditable_buckets.setdefault(err_code, []).append(b_name)
                    findings.extend(b_findings)
                    if target_log_bucket:
                        log_target_buckets.add(target_log_bucket)
                except Exception as e:
                    logger.debug(f"[S3] Unexpected failure auditing {b_name}: {e}")
                    unauditable_buckets.setdefault("Exception", []).append(b_name)

        # 5. Check Log Target Buckets for Missing Lifecycle Policies
        for log_b in log_target_buckets:
            # Check if log target bucket was among audited buckets and lacks lifecycle
            for f in findings:
                if f.resource_id == log_b and "Lifecycle" in f.issue:
                    f.severity = Severity.HIGH
                    f.issue = f"Server Access Log target bucket ({log_b}) lacks lifecycle policy (unbounded log growth)"
                    f.recommendation = (
                        f"Target bucket '{log_b}' receives S3 server access logs. "
                        "Without a lifecycle expiration rule (e.g. 30-90 days), log data accumulates forever."
                    )
                    break

        # 6. Roll up Unauditable Buckets (AccessDenied) into a Single Summary Finding
        for err_code, un_buckets in unauditable_buckets.items():
            if un_buckets:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=f"s3-unauditable-{err_code.lower()}",
                        resource_name=f"{len(un_buckets)} Unauditable S3 Buckets",
                        region="us-east-1",
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=(
                            f"{len(un_buckets)} S3 bucket(s) could not be fully audited due to IAM permissions ({err_code}). "
                            "These buckets were skipped to prevent false-positive missing configuration reports."
                        ),
                        recommendation=(
                            "Ensure the audit IAM role has 's3:GetLifecycleConfiguration', 's3:GetBucketVersioning', "
                            "'s3:GetEncryptionConfiguration', and 's3:GetBucketTagging' permissions."
                        ),
                        estimated_monthly_saving=0.0,
                        metadata={"error_code": err_code, "unaudited_buckets": un_buckets},
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Cost Explorer Spend Sizing (Storage vs Requests vs DataTransfer)
    # -------------------------------------------------------------------------
    def _audit_s3_cost_explorer(
        self, session: boto3.Session, region: str, now: datetime
    ) -> Optional[Finding]:
        try:
            ce = self.get_client(session, "ce", "us-east-1")
            end_date = now.strftime("%Y-%m-%d")
            start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")

            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                Filter={"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Simple Storage Service"]}},
                GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
            )

            storage_cost = 0.0
            request_cost = 0.0
            transfer_cost = 0.0

            for group in resp.get("ResultsByTime", [{}])[-1].get("Groups", []):
                utype = group.get("Keys", [""])[0]
                cost = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0.0))
                if "TimedStorage" in utype:
                    storage_cost += cost
                elif "Requests" in utype:
                    request_cost += cost
                elif "DataTransfer" in utype:
                    transfer_cost += cost

            total_cost = storage_cost + request_cost + transfer_cost

            # If request costs dominate storage costs (e.g. high-frequency GET/PUT requests)
            if request_cost >= 25.0 and request_cost > (1.5 * max(storage_cost, 1.0)):
                return Finding(
                    service=self.display_name,
                    resource_id=f"s3-spend-requests-{region}",
                    resource_name="S3 API Request Spend",
                    region=region,
                    severity=Severity.HIGH if request_cost >= 100.0 else Severity.MEDIUM,
                    effort="Medium",
                    confidence="High",
                    issue=(
                        f"S3 API request charges (${request_cost:.2f}/mo) dominate storage fees (${storage_cost:.2f}/mo). "
                        "High-frequency API requests (PUT/GET/LIST) drive the majority of S3 spend"
                    ),
                    recommendation=(
                        "Optimize request patterns: (1) Add CloudFront caching in front of read-heavy S3 buckets. "
                        "(2) Batch small writes to reduce PUT request volume. "
                        "(3) Enable S3 Bucket Keys on SSE-KMS encrypted buckets to eliminate duplicate KMS request charges."
                    ),
                    estimated_monthly_saving=round(request_cost * 0.30, 2),
                    metadata={
                        "monthly_request_cost": round(request_cost, 2),
                        "monthly_storage_cost": round(storage_cost, 2),
                        "total_s3_spend": round(total_cost, 2),
                    },
                )
        except ClientError:
            pass
        except Exception as e:
            logger.debug(f"[S3] Cost Explorer query skipped: {e}")
        return None

    # -------------------------------------------------------------------------
    # Batched CloudWatch S3 Storage Metrics
    # -------------------------------------------------------------------------
    def _fetch_batched_bucket_stats(
        self, session: boto3.Session, region: str, buckets: List[str], now: datetime
    ) -> Dict[str, Dict[str, float]]:
        """
        Batches CloudWatch get_metric_data calls for S3 storage metrics:
        - BucketSizeBytes (StorageType=StandardStorage)
        - NumberOfObjects (StorageType=AllStorageTypes)
        S3 publishes storage metrics daily; look back 3 days to get the most recent point.
        """
        stats: Dict[str, Dict[str, float]] = {b: {"std_bytes": 0.0, "objects": 0.0} for b in buckets}
        if not buckets:
            return stats

        try:
            cw = self.get_client(session, "cloudwatch", region)
        except Exception:
            return stats

        start_time = now - timedelta(days=3)
        chunk_size = 200  # 2 queries * 200 = 400 queries per call (max 500)

        for i in range(0, len(buckets), chunk_size):
            chunk = buckets[i : i + chunk_size]
            queries: List[Dict[str, Any]] = []
            lookup: Dict[str, Tuple[str, str]] = {}

            for idx, b_name in enumerate(chunk):
                q_sz = f"sz_{idx}"
                q_ob = f"ob_{idx}"

                lookup[q_sz] = (b_name, "std_bytes")
                lookup[q_ob] = (b_name, "objects")

                queries.append(
                    {
                        "Id": q_sz,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/S3",
                                "MetricName": "BucketSizeBytes",
                                "Dimensions": [
                                    {"Name": "BucketName", "Value": b_name},
                                    {"Name": "StorageType", "Value": "StandardStorage"},
                                ],
                            },
                            "Period": 86400,
                            "Stat": "Average",
                        },
                    }
                )
                queries.append(
                    {
                        "Id": q_ob,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/S3",
                                "MetricName": "NumberOfObjects",
                                "Dimensions": [
                                    {"Name": "BucketName", "Value": b_name},
                                    {"Name": "StorageType", "Value": "AllStorageTypes"},
                                ],
                            },
                            "Period": 86400,
                            "Stat": "Average",
                        },
                    }
                )

            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=queries, StartTime=start_time, EndTime=now
                ):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in lookup:
                            b_name, metric_key = lookup[qid]
                            vals = res.get("Values", [])
                            if vals:
                                stats[b_name][metric_key] = vals[0]  # Most recent value
            except ClientError as ce:
                self.handle_client_error(ce, f"CloudWatch metrics for S3 in {region}")

        return stats

    # -------------------------------------------------------------------------
    # Single Bucket Comprehensive Audit
    # -------------------------------------------------------------------------
    def _audit_single_bucket(
        self,
        session: boto3.Session,
        b_name: str,
        b_region: str,
        created_at: Optional[datetime],
        metrics: Dict[str, float],
        now: datetime,
    ) -> Tuple[List[Finding], Optional[str], Optional[str]]:
        findings: List[Finding] = []
        target_log_bucket: Optional[str] = None
        s3 = self.get_client(session, "s3", b_region)

        # 1. Tags & IaC / Ignore Checks
        tags: Dict[str, str] = {}
        try:
            tag_resp = s3.get_bucket_tagging(Bucket=b_name)
            tags = {t.get("Key", ""): t.get("Value", "") for t in tag_resp.get("TagSet", [])}
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code not in ("NoSuchTagSet", "AccessDenied"):
                self.handle_client_error(ce, f"tagging for {b_name}")
        except Exception as e:
            logger.debug(f"[S3] tagging check failed for {b_name}: {e}")

        # Check Ignore tags
        if any(k in tags for k in CONFIG.IGNORE_TAG_KEYS):
            return findings, target_log_bucket, None

        is_cfn_managed = "aws:cloudformation:stack-name" in tags
        cfn_stack = tags.get("aws:cloudformation:stack-name", "")

        # 2. Server Access Logging Configuration
        try:
            log_resp = s3.get_bucket_logging(Bucket=b_name)
            logging_enabled = log_resp.get("LoggingEnabled")
            if logging_enabled:
                target_log_bucket = logging_enabled.get("TargetBucket")
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code != "AccessDenied":
                self.handle_client_error(ce, f"logging for {b_name}")
        except Exception as e:
            logger.debug(f"[S3] logging check failed for {b_name}: {e}")

        # 3. Versioning Status
        versioning_status = "Disabled"
        try:
            v_resp = s3.get_bucket_versioning(Bucket=b_name)
            versioning_status = v_resp.get("Status", "Disabled")
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code != "AccessDenied":
                self.handle_client_error(ce, f"versioning for {b_name}")
        except Exception as e:
            logger.debug(f"[S3] versioning check failed for {b_name}: {e}")

        is_versioned = versioning_status in ("Enabled", "Suspended")

        # 4. Lifecycle Configuration & Gap Analysis
        rules, lc_err = self._get_bucket_lifecycle(s3, b_name)
        if lc_err:
            # Cannot read lifecycle due to IAM permissions; skip to prevent false findings
            return findings, target_log_bucket, lc_err

        # Sizing calculations from CloudWatch metrics
        std_bytes = metrics.get("std_bytes", 0.0)
        std_gb = std_bytes / (1024**3)
        num_objects = metrics.get("objects", 0.0)
        avg_kb = (std_bytes / num_objects / 1024) if num_objects > 0 else 0.0

        # Calculate realistic saving based on cold data fraction
        # Difference between Standard ($0.023/GB-mo) and Standard-IA ($0.0125/GB-mo) = $0.0105/GB-mo
        rate_delta = CONFIG.S3_STANDARD_STORAGE_COST_PER_GB - CONFIG.S3_STANDARD_IA_COST_PER_GB
        potential_saving = std_gb * rate_delta * CONFIG.S3_ASSUMED_COLD_DATA_FRACTION

        # Analyze Lifecycle Gaps
        gaps = self._analyze_lifecycle_gaps(rules or [], is_versioned)

        if gaps:
            gap_descriptions: List[str] = []
            if "transition_expiration" in gaps:
                gap_descriptions.append("No storage transition/expiration policy")
            if "abort_multipart" in gaps:
                gap_descriptions.append("No bucket-wide incomplete multipart upload abort rule")
            if "noncurrent_version_expiration" in gaps:
                gap_descriptions.append("No noncurrent version expiration policy (versioned bucket)")
            if "expired_delete_markers" in gaps:
                gap_descriptions.append("No expired object delete marker cleanup rule")

            # Determine severity and estimated saving
            rec_prefix = f"Update CloudFormation stack '{cfn_stack}': " if is_cfn_managed else ""

            # Check if bucket is small-object heavy (avg object < 128 KB)
            if num_objects > 1000 and avg_kb > 0 and avg_kb < CONFIG.S3_MIN_AVG_OBJECT_SIZE_KB:
                issue_msg = (
                    f"Lifecycle policy gaps in small-object bucket ({b_name}): {', '.join(gap_descriptions)}. "
                    f"Avg object size is only {avg_kb:.1f} KB (Standard-IA minimum billable size is 128 KB)."
                )
                rec_msg = (
                    f"{rec_prefix}Configure lifecycle rules to abort incomplete multipart uploads and expire old versions. "
                    "CAUTION: Avoid transitioning to Standard-IA as objects under 128 KB incur 128 KB billing plus transition request fees. "
                    "Consider S3 Intelligent-Tiering or expiration instead."
                )
                est_saving = 0.0
                confidence = "High"
                effort = "Low"
                severity = Severity.LOW
            elif potential_saving >= CONFIG.S3_MIN_MONTHLY_SAVING_THRESHOLD:
                issue_msg = (
                    f"S3 bucket ({b_name}) holds {std_gb:.1f} GB ({int(num_objects):,} objects) with lifecycle gaps: "
                    f"{', '.join(gap_descriptions)}"
                )
                rec_msg = (
                    f"{rec_prefix}Add a lifecycle configuration to transition objects older than 30–90 days to Standard-IA/Glacier, "
                    f"abort incomplete multipart uploads after {CONFIG.S3_MULTIPART_EXPIRATION_DAYS} days, and expire noncurrent versions."
                )
                est_saving = round(potential_saving, 2)
                confidence = "Low"  # Accurate access patterns require Storage Lens or Storage Class Analysis
                effort = "Medium"
                severity = Severity.HIGH if est_saving >= 50.0 else Severity.MEDIUM
            else:
                # Small or empty bucket: hygiene finding
                issue_msg = f"S3 bucket ({b_name}) has lifecycle gaps: {', '.join(gap_descriptions)}"
                rec_msg = (
                    f"{rec_prefix}Add lifecycle rules to abort incomplete multipart uploads after {CONFIG.S3_MULTIPART_EXPIRATION_DAYS} days "
                    "and clean up old object versions."
                )
                est_saving = 0.0
                confidence = "High"
                effort = "Low"
                severity = Severity.LOW

            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=b_name,
                    resource_name=b_name,
                    region=b_region,
                    severity=severity,
                    effort=effort,
                    confidence=confidence,
                    issue=issue_msg,
                    recommendation=rec_msg,
                    estimated_monthly_saving=est_saving,
                    metadata={
                        "bucket": b_name,
                        "storage_gb": round(std_gb, 2),
                        "object_count": int(num_objects),
                        "avg_object_kb": round(avg_kb, 2),
                        "assumed_cold_fraction": CONFIG.S3_ASSUMED_COLD_DATA_FRACTION,
                        "versioning_status": versioning_status,
                        "lifecycle_gaps": gaps,
                        "managed_by": "CloudFormation" if is_cfn_managed else "Console/Direct",
                    },
                )
            )

        # 5. Early-Deletion Traps in Existing Lifecycle Rules
        early_del_finding = self._check_early_deletion_traps(b_name, b_region, rules or [])
        if early_del_finding:
            findings.append(early_del_finding)

        # 6. S3 SSE-KMS & S3 Bucket Keys Check
        bkey_finding = self._check_bucket_keys(s3, b_name, b_region, is_cfn_managed, cfn_stack)
        if bkey_finding:
            findings.append(bkey_finding)

        # 7. S3 Transfer Acceleration Check
        accel_finding = self._check_transfer_acceleration(s3, b_name, b_region)
        if accel_finding:
            findings.append(accel_finding)

        # 8. S3 Cross-Region Replication Check
        repl_finding = self._check_replication(s3, b_name, b_region)
        if repl_finding:
            findings.append(repl_finding)

        return findings, target_log_bucket, None

    # -------------------------------------------------------------------------
    # Lifecycle Gaps & Early Deletion Traps
    # -------------------------------------------------------------------------
    def _get_bucket_lifecycle(
        self, s3: Any, bucket: str
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        """
        Returns (rules, error_code).
        - ([], None) -> Valid call, no lifecycle configuration exists (NoSuchLifecycleConfiguration).
        - (rules, None) -> Valid call, lifecycle rules returned.
        - (None, error_code) -> Error occurred (e.g. AccessDenied). Cannot verify configuration.
        """
        try:
            resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            return resp.get("Rules", []), None
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code == "NoSuchLifecycleConfiguration":
                return [], None
            return None, code

    def _analyze_lifecycle_gaps(
        self, rules: List[Dict[str, Any]], is_versioned: bool
    ) -> List[str]:
        """Detects missing components in a bucket's lifecycle policy."""
        enabled = [r for r in rules if r.get("Status") == "Enabled"]
        gaps: List[str] = []

        # 1. Transition or Expiration
        has_transition_or_exp = any(
            bool(r.get("Transitions")) or ("Expiration" in r) for r in enabled
        )
        if not has_transition_or_exp:
            gaps.append("transition_expiration")

        # 2. Abort Incomplete Multipart Uploads (must cover the whole bucket)
        has_abort = any(
            "AbortIncompleteMultipartUpload" in r and _covers_bucket(r) for r in enabled
        )
        if not has_abort:
            gaps.append("abort_multipart")

        # 3. Noncurrent Version Expiry (for versioned buckets)
        if is_versioned:
            has_noncurrent_exp = any(
                "NoncurrentVersionExpiration" in r and _covers_bucket(r) for r in enabled
            )
            if not has_noncurrent_exp:
                gaps.append("noncurrent_version_expiration")

            # 4. Expired Object Delete Marker Cleanup
            has_expired_dm = any(
                r.get("Expiration", {}).get("ExpiredObjectDeleteMarker") is True
                or r.get("NoncurrentVersionExpiration", {}).get("NewerNoncurrentVersions") is not None
                for r in enabled
            )
            if not has_expired_dm:
                gaps.append("expired_delete_markers")

        return gaps

    def _check_early_deletion_traps(
        self, bucket: str, region: str, rules: List[Dict[str, Any]]
    ) -> Optional[Finding]:
        """
        Detects lifecycle rules where an object is transitioned to a storage class
        with a minimum retention requirement, but expired before that period elapses.
        For example: Transition to Glacier at Day 30, but Expire at Day 60 (Glacier min duration is 90 days),
        incurring prorated early deletion fees for the remaining 30 days.
        """
        enabled = [r for r in rules if r.get("Status") == "Enabled"]
        for r in enabled:
            exp_days = r.get("Expiration", {}).get("Days")
            if not exp_days:
                continue

            for t in r.get("Transitions", []):
                t_days = t.get("Days")
                s_class = t.get("StorageClass", "")
                min_days = STORAGE_CLASS_MIN_DAYS.get(s_class)
                if t_days and min_days:
                    time_in_class = exp_days - t_days
                    if 0 < time_in_class < min_days:
                        wasted_days = min_days - time_in_class
                        return Finding(
                            service=self.display_name,
                            resource_id=bucket,
                            resource_name=bucket,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Low",
                            confidence="High",
                            issue=(
                                f"Early deletion penalty in lifecycle rule for {bucket}: objects transition to "
                                f"{s_class} at day {t_days} and expire at day {exp_days} ({time_in_class} days in class). "
                                f"{s_class} has a {min_days}-day minimum billing duration, incurring prorated charges for {wasted_days} days."
                            ),
                            recommendation=(
                                f"Extend the expiration rule from {exp_days} days to at least {t_days + min_days} days "
                                f"to avoid paying early deletion fees on {s_class} storage."
                            ),
                            estimated_monthly_saving=0.0,
                            metadata={
                                "rule_id": r.get("ID", ""),
                                "storage_class": s_class,
                                "min_duration_days": min_days,
                                "configured_days": time_in_class,
                            },
                        )
        return None

    # -------------------------------------------------------------------------
    # S3 Bucket Keys (SSE-KMS)
    # -------------------------------------------------------------------------
    def _check_bucket_keys(
        self, s3: Any, bucket: str, region: str, is_cfn_managed: bool, cfn_stack: str
    ) -> Optional[Finding]:
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            for r in rules:
                apply_sse = r.get("ApplyServerSideEncryptionByDefault", {})
                algo = apply_sse.get("SSEAlgorithm")
                bucket_key_enabled = r.get("BucketKeyEnabled", False)

                # Flag SSE-KMS without Bucket Keys (skip aws:kms:dsse dual-layer)
                if algo == "aws:kms" and not bucket_key_enabled:
                    rec_prefix = f"Update CloudFormation stack '{cfn_stack}': " if is_cfn_managed else ""
                    return Finding(
                        service=self.display_name,
                        resource_id=bucket,
                        resource_name=bucket,
                        region=region,
                        severity=Severity.MEDIUM,
                        effort="Low",
                        confidence="High",
                        issue=f"S3 SSE-KMS encryption enabled without S3 Bucket Keys on {bucket}",
                        recommendation=(
                            f"{rec_prefix}Enable S3 Bucket Keys to decrease AWS KMS request traffic by up to 99%. "
                            "IMPORTANT CAVEATS: (1) S3 Bucket Keys change the KMS encryption context from the object ARN "
                            "to the bucket ARN. Verify that no IAM or KMS key policies restrict access matching object ARNs. "
                            "(2) Existing objects require an in-place 'aws s3 cp' rewrite to adopt bucket keys."
                        ),
                        estimated_monthly_saving=10.0,
                        metadata={
                            "bucket": bucket,
                            "sse_algorithm": algo,
                            "kms_master_key_id": apply_sse.get("KMSMasterKeyId", "default"),
                            "bucket_key_enabled": False,
                        },
                    )
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code not in ("ServerSideEncryptionConfigurationNotFoundError", "AccessDenied"):
                self.handle_client_error(ce, f"encryption for {bucket}")
        except Exception as e:
            logger.debug(f"[S3] encryption check failed for {bucket}: {e}")
        return None

    # -------------------------------------------------------------------------
    # S3 Transfer Acceleration
    # -------------------------------------------------------------------------
    def _check_transfer_acceleration(self, s3: Any, bucket: str, region: str) -> Optional[Finding]:
        try:
            accel = s3.get_bucket_accelerate_configuration(Bucket=bucket)
            if accel.get("Status") == "Enabled":
                return Finding(
                    service=self.display_name,
                    resource_id=bucket,
                    resource_name=bucket,
                    region=region,
                    severity=Severity.LOW,
                    effort="Low",
                    confidence="High",
                    issue=f"S3 Transfer Acceleration is enabled on {bucket} ($0.04-$0.08/GB premium)",
                    recommendation=(
                        "Verify whether fast globally-distributed uploads are still required. "
                        "Disable S3 Transfer Acceleration if workloads upload from the same region or standard speeds suffice."
                    ),
                    estimated_monthly_saving=0.0,
                    metadata={"transfer_acceleration": "Enabled"},
                )
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code not in ("MethodNotAllowed", "UnsupportedArgument", "AccessDenied"):
                self.handle_client_error(ce, f"acceleration for {bucket}")
        except Exception as e:
            logger.debug(f"[S3] acceleration check failed for {bucket}: {e}")
        return None

    # -------------------------------------------------------------------------
    # S3 Cross-Region Replication
    # -------------------------------------------------------------------------
    def _check_replication(self, s3: Any, bucket: str, region: str) -> Optional[Finding]:
        try:
            repl = s3.get_bucket_replication(Bucket=bucket)
            rules = repl.get("ReplicationConfiguration", {}).get("Rules", [])
            active_rules = [r for r in rules if r.get("Status") == "Enabled"]
            if active_rules:
                destinations = [
                    r.get("Destination", {}).get("Bucket", "unknown") for r in active_rules
                ]
                return Finding(
                    service=self.display_name,
                    resource_id=bucket,
                    resource_name=bucket,
                    region=region,
                    severity=Severity.LOW,
                    effort="Medium",
                    confidence="High",
                    issue=(
                        f"Cross-Region Replication enabled on {bucket} replicating to [{', '.join(destinations)}]. "
                        "Incurs duplicate storage charges and inter-region data transfer fees ($0.02/GB)."
                    ),
                    recommendation=(
                        "Audit replication requirements: ensure compliance or DR mandates justify duplicating all objects. "
                        "Consider scoping replication via prefix/tag filters or adjusting destination storage class."
                    ),
                    estimated_monthly_saving=0.0,
                    metadata={"replication_destinations": destinations, "rule_count": len(active_rules)},
                )
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code not in ("ReplicationConfigurationNotFoundError", "AccessDenied"):
                self.handle_client_error(ce, f"replication for {bucket}")
        except Exception as e:
            logger.debug(f"[S3] replication check failed for {bucket}: {e}")
        return None
