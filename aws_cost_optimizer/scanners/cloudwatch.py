import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")


def _chunks(seq: list, n: int) -> Generator[list, None, None]:
    """Yield successive n-sized chunks from seq."""
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


# Recommended retention days and category by prefix
RETENTION_BY_PREFIX: Dict[str, Tuple[int, str]] = {
    "/aws/lambda/": (14, "AWS Lambda"),
    "/aws/apigateway/": (30, "Amazon API Gateway"),
    "/aws/eks/": (30, "Amazon EKS"),
    "/aws/ecs/": (30, "Amazon ECS"),
    "/aws/rds/": (30, "Amazon RDS"),
    "/aws/vpc/flowlogs": (14, "VPC Flow Logs"),
    "/aws/elasticbeanstalk/": (30, "Elastic Beanstalk"),
    "/aws/codebuild/": (30, "AWS CodeBuild"),
    "/aws/cloudtrail": (365, "AWS CloudTrail Audit"),
}


class CloudWatchScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "cloudwatch"

    @property
    def display_name(self) -> str:
        return "Amazon CloudWatch Logs"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            logs = self.get_client(session, "logs", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[CloudWatch] Failed to initialize client in {region}: {e}")
            return findings

        # 1. Collect all log groups in the region
        all_groups: List[Dict[str, Any]] = []
        try:
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                all_groups.extend(page.get("logGroups", []))
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_log_groups in {region}")
            return findings

        if not all_groups:
            return findings

        group_names = [g["logGroupName"] for g in all_groups]

        # 2. Batch query 30-day incoming ingestion volume (IncomingBytes)
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=30)
        ingestion_map = self._fetch_batched_ingestion(cw, group_names, start_time, now)

        # 3. Pre-fetch active Lambda functions to detect orphaned Lambda log groups
        active_lambdas = self._fetch_active_lambda_functions(session, region)

        # 4. Evaluate each log group
        storage_price_gb = CONFIG.CLOUDWATCH_LOGS_COST_PER_GB
        ingestion_price_gb = CONFIG.CLOUDWATCH_INGESTION_COST_PER_GB

        for group in all_groups:
            name = group.get("logGroupName", "")
            retention_days = group.get("retentionInDays")
            stored_bytes = group.get("storedBytes", 0)
            stored_gb = stored_bytes / (1024**3)
            stored_mb = stored_bytes / (1024**2)
            log_class = group.get("logGroupClass", "STANDARD")
            kms_key = group.get("kmsKeyId")

            # Determine log age
            creation_ms = group.get("creationTime", 0)
            created = datetime.fromtimestamp(creation_ms / 1000, tz=timezone.utc) if creation_ms else now
            age_days = max((now - created).days, 1)

            # Ingestion stats
            ingested_gb_30d = ingestion_map.get(name, 0.0)
            monthly_ingestion_cost = ingested_gb_30d * ingestion_price_gb

            # Determine tailored retention and source service
            target_retention, source_service = self._detect_service_and_target(name)

            common_meta = {
                "source_service": source_service,
                "creation_age_days": age_days,
                "log_group_class": log_class,
                "stored_mb": round(stored_mb, 2),
                "stored_gb": round(stored_gb, 4),
                "ingested_gb_30d": round(ingested_gb_30d, 3),
                "monthly_ingestion_cost": round(monthly_ingestion_cost, 2),
                "recommended_retention_days": target_retention,
                "kms_key_id": kms_key,
            }

            # -------------------------------------------------------------
            # Check 1: Orphaned Lambda Log Group (Function deleted, logs remain)
            # -------------------------------------------------------------
            is_orphaned_lambda = False
            if name.startswith("/aws/lambda/"):
                fn_name = name[len("/aws/lambda/") :]
                if active_lambdas and fn_name not in active_lambdas:
                    is_orphaned_lambda = True
                    sev = Severity.HIGH if stored_gb >= 10.0 else Severity.MEDIUM
                    savings = stored_gb * storage_price_gb
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=sev,
                            effort="Low",
                            confidence="High",
                            issue=f"Orphaned Lambda log group (function '{fn_name}' no longer exists; holding {stored_mb:.1f} MB)",
                            recommendation="Verify historical retention requirements and delete the orphaned log group or export to S3 Glacier",
                            estimated_monthly_saving=max(savings, 0.50),
                            metadata=common_meta,
                        )
                    )

            # -------------------------------------------------------------
            # Check 2: Empty or Dead Log Groups (0 stored bytes & 0 ingestion)
            # -------------------------------------------------------------
            if stored_bytes == 0 and ingested_gb_30d == 0.0 and age_days >= 7:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=name,
                        resource_name=name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=f"Empty / inactive log group (0 bytes stored and 0 incoming bytes over 30 days, created {age_days} days ago)",
                        recommendation="Verify no dormant service writes to this group, then delete to reduce clutter",
                        estimated_monthly_saving=0.0,
                        metadata=common_meta,
                    )
                )
                continue

            # -------------------------------------------------------------
            # Check 3: Never-Expire Retention Policy (Realistic Retention Math)
            # -------------------------------------------------------------
            if retention_days is None and not is_orphaned_lambda:
                # Realistic delta: fraction of data older than target retention
                old_fraction = max(0.0, 1.0 - (target_retention / age_days))
                saving = stored_gb * storage_price_gb * old_fraction

                # Drop arbitrary $3 floor: skip noise below $0.50
                if saving >= 0.50:
                    sev = (
                        Severity.HIGH
                        if saving >= 20.0
                        else (Severity.MEDIUM if saving >= 5.0 else Severity.LOW)
                    )
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=sev,
                            effort="Low",
                            confidence="Medium",
                            issue=f"Log group set to 'Never Expire' retention (accumulated {stored_mb:.1f} MB over {age_days} days)",
                            recommendation=(
                                f"Set retention to {target_retention} days for {source_service}. "
                                f"Estimated {old_fraction * 100:.0f}% of stored data is older than {target_retention} days"
                            ),
                            estimated_monthly_saving=saving,
                            metadata=common_meta,
                        )
                    )

            # -------------------------------------------------------------
            # Check 4: Overlong Retention on Non-Compliance Operational Logs
            # -------------------------------------------------------------
            if (
                retention_days is not None
                and retention_days >= 365
                and not name.startswith("/aws/cloudtrail")
                and age_days > target_retention
            ):
                excess_fraction = max(0.0, 1.0 - (target_retention / retention_days))
                saving = stored_gb * storage_price_gb * excess_fraction
                if saving >= 1.0:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Low",
                            confidence="Medium",
                            issue=f"Excessive retention ({retention_days} days) for operational {source_service} logs",
                            recommendation=f"Reduce retention to {target_retention} days, or export older historical archives to S3 Glacier",
                            estimated_monthly_saving=saving,
                            metadata=common_meta,
                        )
                    )

            # -------------------------------------------------------------
            # Check 5: High-Ingestion Groups & Infrequent Access (IA) Candidates
            # Ingestion is ~$0.50/GB (10-20x higher than storage!)
            # -------------------------------------------------------------
            if ingested_gb_30d >= CONFIG.CLOUDWATCH_HIGH_INGESTION_GB_THRESHOLD:
                # Check for metric/subscription filters before recommending IA class
                has_filters = self._has_active_filters(logs, name)

                if not has_filters and log_class == "STANDARD":
                    # Infrequent Access saves ~50% on ingestion ($0.25/GB vs $0.50/GB)
                    ia_saving = ingested_gb_30d * (
                        CONFIG.CLOUDWATCH_INGESTION_COST_PER_GB
                        - CONFIG.CLOUDWATCH_IA_INGESTION_COST_PER_GB
                    )
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.HIGH if ia_saving >= 25.0 else Severity.MEDIUM,
                            effort="Medium",
                            confidence="High",
                            issue=(
                                f"High log ingestion ({ingested_gb_30d:.1f} GB/mo costing ${monthly_ingestion_cost:.2f}/mo) "
                                "with no metric or subscription filters"
                            ),
                            recommendation=(
                                "Migrate to CloudWatch Logs Infrequent Access (IA) class for a 50% discount on ingestion "
                                f"($0.25/GB vs $0.50/GB, saving ~${ia_saving:.2f}/mo)"
                            ),
                            estimated_monthly_saving=ia_saving,
                            metadata=common_meta,
                        )
                    )
                else:
                    # Filters exist or already IA: recommend verbosity tuning
                    verbosity_saving = monthly_ingestion_cost * 0.25  # ~25% reduction
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=name,
                            resource_name=name,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Low",
                            confidence="Medium",
                            issue=f"High log ingestion volume ({ingested_gb_30d:.1f} GB/mo costing ${monthly_ingestion_cost:.2f}/mo)",
                            recommendation="Reduce log level (DEBUG -> INFO), filter health-check probes, or sample high-frequency events",
                            estimated_monthly_saving=verbosity_saving,
                            metadata=common_meta,
                        )
                    )

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    @staticmethod
    def _detect_service_and_target(group_name: str) -> Tuple[int, str]:
        """Maps log group prefix to recommended retention days and service name."""
        for prefix, (days, svc) in RETENTION_BY_PREFIX.items():
            if group_name.startswith(prefix):
                return days, svc
        return 30, "Application / Custom Service"

    def _fetch_batched_ingestion(
        self, cw: Any, group_names: List[str], start: datetime, end: datetime
    ) -> Dict[str, float]:
        """
        Batches CloudWatch get_metric_data queries for IncomingBytes (Sum over 30 days).
        Up to 400 queries per batch call.
        """
        results: Dict[str, float] = {}
        if not group_names:
            return results

        for chunk in _chunks(group_names, 400):
            queries = []
            lookup: Dict[str, str] = {}

            for idx, gname in enumerate(chunk):
                qid = f"q_{idx}"
                lookup[qid] = gname
                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Logs",
                                "MetricName": "IncomingBytes",
                                "Dimensions": [{"Name": "LogGroupName", "Value": gname}],
                            },
                            "Period": 86400 * 30,
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
                            gname = lookup[qid]
                            total_bytes = sum(res.get("Values", []))
                            results[gname] = total_bytes / (1024**3)  # Convert to GB
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for CloudWatch IncomingBytes")

        return results

    def _fetch_active_lambda_functions(self, session: boto3.Session, region: str) -> Set[str]:
        """Collects active Lambda function names in the region to detect orphaned log groups."""
        active: Set[str] = set()
        try:
            lambda_client = self.get_client(session, "lambda", region)
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    active.add(fn.get("FunctionName", ""))
        except ClientError as ce:
            err_code = ce.response.get("Error", {}).get("Code", "")
            if err_code not in ("AccessDeniedException", "UnauthorizedOperation"):
                logger.debug(f"[CloudWatch] list_functions in {region}: {ce}")
        except Exception as e:
            logger.debug(f"[CloudWatch] Lambda client unavailable: {e}")
        return active

    def _has_active_filters(self, logs: Any, group_name: str) -> bool:
        """Checks if a log group has metric or subscription filters (incompatible with IA class)."""
        try:
            mf = logs.describe_metric_filters(logGroupName=group_name).get("metricFilters", [])
            if mf:
                return True
            sf = logs.describe_subscription_filters(logGroupName=group_name).get(
                "subscriptionFilters", []
            )
            if sf:
                return True
        except ClientError:
            pass
        return False
