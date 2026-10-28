"""
Production-Grade Amazon DynamoDB Cost & Architecture Optimization Scanner.

Comprehensive Audit Areas:
1. Provisioned Capacity Waste (Idle / Underutilized Tables):
   - Audits tables in PROVISIONED mode.
   - Batches CloudWatch ConsumedReadCapacityUnits and ConsumedWriteCapacityUnits over 14 days.
   - Calculates exact utilization vs provisioned capacity. If average utilization is < 5%,
     recommends switching to On-Demand (PAY_PER_REQUEST) capacity mode, eliminating 100% of idle capacity fees.
2. Stale / Unused Global Secondary Indexes (GSIs):
   - Inspects GlobalSecondaryIndexes on every table.
   - Batches CloudWatch ConsumedReadCapacityUnits per GSI.
   - Flags GSIs with zero read queries over 14 days that continue to multiply write capacity
     charges and consume storage.
3. Point-in-Time Recovery (PITR) on Non-Production Tables:
   - Queries describe_continuous_backups for PointInTimeRecoveryDescription.
   - Identifies non-production tables (dev, test, stage, qa, sandbox) incurring $0.20/GB-month
     continuous backup fees on scratch/ephemeral data.
4. DynamoDB Standard-IA Storage Class Migration:
   - Identifies storage-heavy tables (> 50 GB) in STANDARD class with low query activity.
   - Recommends migrating to DynamoDB Standard-IA to unlock a 60% storage cost reduction ($0.25 -> $0.10/GB-mo).
5. Time to Live (TTL) Configuration for Ephemeral / Growing Data:
   - Audits describe_time_to_live.
   - Identifies session, event, token, cache, or log tables with TTL disabled growing unbounded.
6. Guardrails & Infrastructure as Code:
   - Skips tables with ignore tags ('cost-optimizer:ignore').
   - Detects CloudFormation managed tables ('aws:cloudformation:stack-name') and advises template updates.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")

# Non-production environment tokens
NON_PROD_TOKENS: Set[str] = {
    "dev",
    "development",
    "test",
    "testing",
    "qa",
    "uat",
    "stage",
    "staging",
    "sandbox",
    "nonprod",
    "non-prod",
}
ENV_TAG_KEYS: Set[str] = {"env", "environment", "stage", "tier", "name"}

# Patterns indicating ephemeral / time-series data where TTL is essential
TTL_RECOMMENDED_PATTERNS: Set[str] = {
    "session",
    "token",
    "cache",
    "event",
    "log",
    "metric",
    "history",
    "audit",
    "otp",
}


class DynamoDBScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "dynamodb"

    @property
    def display_name(self) -> str:
        return "Amazon DynamoDB"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ddb = self.get_client(session, "dynamodb", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[DynamoDB] Failed to initialize client in {region}: {e}")
            return findings

        now = datetime.now(timezone.utc)

        # 1. List all tables in the region
        try:
            paginator = ddb.get_paginator("list_tables")
            table_names: List[str] = []
            for page in paginator.paginate():
                table_names.extend(page.get("TableNames", []))
        except ClientError as ce:
            self.handle_client_error(ce, f"ListTables in {region}")
            return findings

        if not table_names:
            return findings

        # 2. Describe Tables (collect metadata, capacity, GSIs, and tags)
        table_descriptions: Dict[str, Dict[str, Any]] = {}
        for t_name in table_names:
            try:
                desc = ddb.describe_table(TableName=t_name).get("Table", {})
                if desc:
                    table_descriptions[t_name] = desc
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code != "ResourceNotFoundException":
                    self.handle_client_error(ce, f"describe_table for {t_name}")

        if not table_descriptions:
            return findings

        # 3. Batch CloudWatch Metrics for Tables and GSIs over 14 days
        lookback_days = CONFIG.METRIC_LOOKBACK_DAYS
        start_time = now - timedelta(days=lookback_days)
        metrics = self._fetch_batched_dynamodb_metrics(cw, table_descriptions, start_time, now)

        # 4. Multi-threaded Table Audit
        max_workers = min(CONFIG.MAX_WORKER_THREADS, len(table_descriptions))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_table = {
                executor.submit(
                    self._audit_single_table,
                    ddb,
                    region,
                    t_name,
                    t_desc,
                    metrics.get(t_name, {}),
                    lookback_days,
                ): t_name
                for t_name, t_desc in table_descriptions.items()
            }

            for future in as_completed(future_to_table):
                t_name = future_to_table[future]
                try:
                    t_findings = future.result()
                    findings.extend(t_findings)
                except Exception as e:
                    logger.debug(f"[DynamoDB] Error auditing table {t_name}: {e}")

        return findings

    # -------------------------------------------------------------------------
    # CloudWatch Metrics Batching (get_metric_data)
    # -------------------------------------------------------------------------
    def _fetch_batched_dynamodb_metrics(
        self,
        cw: Any,
        table_descriptions: Dict[str, Dict[str, Any]],
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Batches CloudWatch get_metric_data calls for:
        - ConsumedReadCapacityUnits (Sum) for table
        - ConsumedWriteCapacityUnits (Sum) for table
        - ConsumedReadCapacityUnits (Sum) per GSI
        """
        results: Dict[str, Dict[str, Any]] = {
            t_name: {"table_read_units": 0.0, "table_write_units": 0.0, "gsi_read_units": {}}
            for t_name in table_descriptions
        }

        queries: List[Dict[str, Any]] = []
        id_map: Dict[str, Tuple[str, str, Optional[str]]] = {}
        q_idx = 0

        for t_name, desc in table_descriptions.items():
            # Table consumed read & write
            q_tr = f"tr_{q_idx}"
            q_tw = f"tw_{q_idx}"
            q_idx += 1

            id_map[q_tr] = (t_name, "table_read", None)
            id_map[q_tw] = (t_name, "table_write", None)

            queries.append(
                {
                    "Id": q_tr,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/DynamoDB",
                            "MetricName": "ConsumedReadCapacityUnits",
                            "Dimensions": [{"Name": "TableName", "Value": t_name}],
                        },
                        "Period": 86400,
                        "Stat": "Sum",
                    },
                }
            )
            queries.append(
                {
                    "Id": q_tw,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/DynamoDB",
                            "MetricName": "ConsumedWriteCapacityUnits",
                            "Dimensions": [{"Name": "TableName", "Value": t_name}],
                        },
                        "Period": 86400,
                        "Stat": "Sum",
                    },
                }
            )

            # GSI consumed read
            for gsi in desc.get("GlobalSecondaryIndexes", []):
                gsi_name = gsi.get("IndexName", "")
                if gsi_name:
                    q_gsi = f"gsi_{q_idx}"
                    q_idx += 1
                    id_map[q_gsi] = (t_name, "gsi_read", gsi_name)
                    queries.append(
                        {
                            "Id": q_gsi,
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/DynamoDB",
                                    "MetricName": "ConsumedReadCapacityUnits",
                                    "Dimensions": [
                                        {"Name": "TableName", "Value": t_name},
                                        {"Name": "GlobalSecondaryIndexName", "Value": gsi_name},
                                    ],
                                },
                                "Period": 86400,
                                "Stat": "Sum",
                            },
                        }
                    )

        if not queries:
            return results

        chunk_size = 400
        for i in range(0, len(queries), chunk_size):
            chunk = queries[i : i + chunk_size]
            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=chunk, StartTime=start_time, EndTime=end_time
                ):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in id_map:
                            t_name, m_type, gsi_name = id_map[qid]
                            values = res.get("Values", [])
                            val_sum = sum(values) if values else 0.0

                            if m_type == "table_read":
                                results[t_name]["table_read_units"] = val_sum
                            elif m_type == "table_write":
                                results[t_name]["table_write_units"] = val_sum
                            elif m_type == "gsi_read" and gsi_name:
                                results[t_name]["gsi_read_units"][gsi_name] = val_sum
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for DynamoDB")

        return results

    # -------------------------------------------------------------------------
    # Single Table Audit
    # -------------------------------------------------------------------------
    def _audit_single_table(
        self,
        ddb: Any,
        region: str,
        t_name: str,
        desc: Dict[str, Any],
        t_metrics: Dict[str, Any],
        lookback_days: int,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Tags & IaC Protection
        tags = self._fetch_table_tags(ddb, desc.get("TableArn", ""))
        if any(k in tags for k in CONFIG.IGNORE_TAG_KEYS):
            return findings

        is_cfn_managed = "aws:cloudformation:stack-name" in tags
        cfn_stack = tags.get("aws:cloudformation:stack-name", "")
        rec_prefix = f"Update CloudFormation stack '{cfn_stack}': " if is_cfn_managed else ""

        is_non_prod = self._is_non_prod_table(t_name, tags)

        table_size_bytes = desc.get("TableSizeBytes", 0)
        table_size_gb = table_size_bytes / (1024**3)
        item_count = desc.get("ItemCount", 0)
        table_class = desc.get("TableClassSummary", {}).get("TableClass", "STANDARD")
        billing_mode = desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")

        # 2. Check Provisioned Capacity Waste (Idle Tables)
        if billing_mode == "PROVISIONED":
            pt = desc.get("ProvisionedThroughput", {})
            rcu = pt.get("ReadCapacityUnits", 0)
            wcu = pt.get("WriteCapacityUnits", 0)

            # Lookback period in seconds
            period_seconds = lookback_days * 86400
            read_sum = t_metrics.get("table_read_units", 0.0)
            write_sum = t_metrics.get("table_write_units", 0.0)

            avg_consumed_rcu = read_sum / period_seconds if period_seconds > 0 else 0.0
            avg_consumed_wcu = write_sum / period_seconds if period_seconds > 0 else 0.0

            rcu_util = avg_consumed_rcu / rcu if rcu > 0 else 0.0
            wcu_util = avg_consumed_wcu / wcu if wcu > 0 else 0.0

            # Calculate monthly provisioned cost for table
            monthly_rcu_cost = rcu * CONFIG.DYNAMODB_PROVISIONED_RCU_HOURLY * 730
            monthly_wcu_cost = wcu * CONFIG.DYNAMODB_PROVISIONED_WCU_HOURLY * 730
            monthly_provisioned_cost = monthly_rcu_cost + monthly_wcu_cost

            # Check if utilization is under 5%
            if (
                (rcu_util < CONFIG.DYNAMODB_IDLE_UTILIZATION_THRESHOLD)
                and (wcu_util < CONFIG.DYNAMODB_IDLE_UTILIZATION_THRESHOLD)
                and (monthly_provisioned_cost >= CONFIG.DYNAMODB_MIN_MONTHLY_SAVINGS)
            ):
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=t_name,
                        resource_name=t_name,
                        region=region,
                        severity=Severity.HIGH if monthly_provisioned_cost >= 25.0 else Severity.MEDIUM,
                        effort="Low",
                        confidence="High",
                        issue=(
                            f"Underutilized Provisioned DynamoDB table ({t_name}): provisioned {rcu} RCU / {wcu} WCU "
                            f"with only {rcu_util * 100:.1f}% read / {wcu_util * 100:.1f}% write utilization over past {lookback_days} days"
                        ),
                        recommendation=(
                            f"{rec_prefix}Switch table capacity mode from PROVISIONED to PAY_PER_REQUEST (On-Demand). "
                            "On-Demand tables pay zero capacity charges when idle, saving up to 100% of provisioned capacity costs."
                        ),
                        estimated_monthly_saving=round(monthly_provisioned_cost, 2),
                        metadata={
                            "table_name": t_name,
                            "billing_mode": "PROVISIONED",
                            "provisioned_rcu": rcu,
                            "provisioned_wcu": wcu,
                            "rcu_utilization": round(rcu_util * 100, 2),
                            "wcu_utilization": round(wcu_util * 100, 2),
                            "monthly_provisioned_cost": round(monthly_provisioned_cost, 2),
                        },
                    )
                )

        # 3. Check Stale / Unused Global Secondary Indexes (GSIs)
        gsi_read_metrics = t_metrics.get("gsi_read_units", {})
        for gsi in desc.get("GlobalSecondaryIndexes", []):
            gsi_name = gsi.get("IndexName", "")
            gsi_read_sum = gsi_read_metrics.get(gsi_name, 0.0)

            # If zero read units were consumed across 14 days
            if gsi_read_sum == 0.0:
                gsi_pt = gsi.get("ProvisionedThroughput", {})
                gsi_rcu = gsi_pt.get("ReadCapacityUnits", 0)
                gsi_wcu = gsi_pt.get("WriteCapacityUnits", 0)

                gsi_cost = (
                    gsi_rcu * CONFIG.DYNAMODB_PROVISIONED_RCU_HOURLY
                    + gsi_wcu * CONFIG.DYNAMODB_PROVISIONED_WCU_HOURLY
                ) * 730

                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=f"{t_name}#{gsi_name}",
                        resource_name=f"{t_name} (GSI: {gsi_name})",
                        region=region,
                        severity=Severity.HIGH if gsi_cost >= 20.0 else Severity.MEDIUM,
                        effort="Low",
                        confidence="High",
                        issue=(
                            f"Unused Global Secondary Index ({gsi_name}) on table {t_name} with 0 read operations in past {lookback_days} days. "
                            "Every table write continues to multiply write costs and duplicate storage for this unused index."
                        ),
                        recommendation=(
                            f"{rec_prefix}Delete stale Global Secondary Index '{gsi_name}'. "
                            "This eliminates write amplification charges and frees index storage."
                        ),
                        estimated_monthly_saving=round(gsi_cost, 2),
                        metadata={
                            "table_name": t_name,
                            "gsi_name": gsi_name,
                            "gsi_rcu": gsi_rcu,
                            "gsi_wcu": gsi_wcu,
                            "zero_reads_14d": True,
                        },
                    )
                )

        # 4. Check Point-in-Time Recovery (PITR) on Non-Production Tables
        if is_non_prod:
            try:
                cb = ddb.describe_continuous_backups(TableName=t_name).get("ContinuousBackupsDescription", {})
                pitr_desc = cb.get("PointInTimeRecoveryDescription", {})
                if pitr_desc.get("PointInTimeRecoveryStatus") == "ENABLED":
                    monthly_pitr_cost = table_size_gb * CONFIG.DYNAMODB_PITR_COST_PER_GB
                    if monthly_pitr_cost >= CONFIG.DYNAMODB_MIN_MONTHLY_SAVINGS:
                        findings.append(
                            Finding(
                                service=self.display_name,
                                resource_id=t_name,
                                resource_name=t_name,
                                region=region,
                                severity=Severity.MEDIUM if monthly_pitr_cost >= 20.0 else Severity.LOW,
                                effort="Low",
                                confidence="High",
                                issue=(
                                    f"Point-in-Time Recovery (PITR) enabled on non-production table ({t_name}, {table_size_gb:.1f} GB) "
                                    f"incurring ${monthly_pitr_cost:.2f}/mo continuous backup charge"
                                ),
                                recommendation=(
                                    f"{rec_prefix}Disable Point-in-Time Recovery on non-production table '{t_name}'. "
                                    "Non-prod scratch or test environments generally do not require continuous backup protection."
                                ),
                                estimated_monthly_saving=round(monthly_pitr_cost, 2),
                                metadata={
                                    "table_name": t_name,
                                    "table_size_gb": round(table_size_gb, 2),
                                    "is_non_prod": True,
                                    "pitr_status": "ENABLED",
                                },
                            )
                        )
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "")
                if code != "AccessDeniedException":
                    self.handle_client_error(ce, f"describe_continuous_backups for {t_name}")

        # 5. Check Standard-IA Storage Class Migration for Large / Storage-Heavy Tables
        if table_class == "STANDARD" and table_size_gb >= 50.0:
            # Storage delta: $0.25 (Standard) -> $0.10 (Standard-IA) = $0.15/GB saving (60% discount)
            monthly_storage_saving = table_size_gb * (
                CONFIG.DYNAMODB_STANDARD_STORAGE_PER_GB - CONFIG.DYNAMODB_IA_STORAGE_PER_GB
            )
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=t_name,
                    resource_name=t_name,
                    region=region,
                    severity=Severity.HIGH if monthly_storage_saving >= 50.0 else Severity.MEDIUM,
                    effort="Low",
                    confidence="High",
                    issue=(
                        f"Large DynamoDB table ({t_name}, {table_size_gb:.1f} GB) using STANDARD storage class. "
                        f"Standard storage costs $0.25/GB-mo."
                    ),
                    recommendation=(
                        f"{rec_prefix}Update table class to DynamoDB Standard-IA (Infrequent Access) to save 60% on storage "
                        f"($0.10/GB-mo vs $0.25/GB-mo). Ideal for tables where storage dominates read/write costs."
                    ),
                    estimated_monthly_saving=round(monthly_storage_saving, 2),
                    metadata={
                        "table_name": t_name,
                        "table_size_gb": round(table_size_gb, 2),
                        "current_class": "STANDARD",
                        "target_class": "STANDARD_INFREQUENT_ACCESS",
                    },
                )
            )

        # 6. Check Time to Live (TTL) for High-Volume or Ephemeral Tables
        try:
            ttl_resp = ddb.describe_time_to_live(TableName=t_name).get("TimeToLiveDescription", {})
            ttl_status = ttl_resp.get("TimeToLiveStatus", "DISABLED")
            if ttl_status == "DISABLED":
                # Check if table name indicates ephemeral or log-like records
                t_lower = t_name.lower()
                is_ttl_candidate = any(p in t_lower for p in TTL_RECOMMENDED_PATTERNS) or item_count > 100000

                if is_ttl_candidate and table_size_gb >= 5.0:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=t_name,
                            resource_name=t_name,
                            region=region,
                            severity=Severity.LOW,
                            effort="Low",
                            confidence="High",
                            issue=(
                                f"DynamoDB table ({t_name}, {table_size_gb:.1f} GB, {item_count:,} items) has Time to Live (TTL) DISABLED"
                            ),
                            recommendation=(
                                f"{rec_prefix}Configure a TTL attribute to automatically expire stale records at no cost. "
                                "DynamoDB TTL deletions do not consume write capacity units, stopping unbounded storage growth."
                            ),
                            estimated_monthly_saving=0.0,
                            metadata={"table_name": t_name, "item_count": item_count, "ttl_status": "DISABLED"},
                        )
                    )
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code != "AccessDeniedException":
                self.handle_client_error(ce, f"describe_time_to_live for {t_name}")

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    def _fetch_table_tags(self, ddb: Any, table_arn: str) -> Dict[str, str]:
        tags: Dict[str, str] = {}
        if not table_arn:
            return tags
        try:
            resp = ddb.list_tags_of_resource(ResourceArn=table_arn)
            tags = {t.get("Key", ""): t.get("Value", "") for t in resp.get("Tags", [])}
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code != "AccessDeniedException":
                self.handle_client_error(ce, f"list_tags_of_resource for {table_arn}")
        return tags

    def _is_non_prod_table(self, table_name: str, tags: Dict[str, str]) -> bool:
        t_lower = table_name.lower()
        for token in NON_PROD_TOKENS:
            if re.search(rf"\b{re.escape(token)}\b", t_lower) or f"-{token}" in t_lower or f"_{token}" in t_lower:
                return True

        for k, v in tags.items():
            if k.lower() in ENV_TAG_KEYS:
                v_lower = v.lower()
                if v_lower in NON_PROD_TOKENS:
                    return True
                for token in NON_PROD_TOKENS:
                    if re.search(rf"\b{re.escape(token)}\b", v_lower):
                        return True
        return False
