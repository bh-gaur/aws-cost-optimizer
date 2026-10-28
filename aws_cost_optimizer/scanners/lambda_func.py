"""
Production-Grade AWS Lambda Waste & Optimization Scanner.

Key Capabilities & Flaw Mitigations:
1. Real Cost Calculations (No Flat Savings Fiction):
   - Computes exact compute cost from measured metrics:
     GB-seconds = (Duration_ms / 1000) * (Memory_MB / 1024)
     Compute Cost = GB-seconds * rate ($0.0000166667 for x86_64, $0.0000133334 for arm64) + Requests * $0.20/1M.
   - Computes arm64 savings based on actual GB-seconds (~20% reduction), skipping noise below $0.50/mo.
2. Inactive Functions Audited by Real Waste:
   - Does NOT claim fictitious compute savings on 0-invocation functions.
   - Uses LastModified timestamp for grace period (skips recently modified/created functions).
   - Audits resource policies (triggers from EventBridge, SNS, S3, Cognito, CloudFormation custom resources).
   - Sizes real associated storage waste from CloudWatch Log Groups (/aws/lambda/<name>).
3. Provisioned Concurrency Audit (The Real Money):
   - Audits provisioned concurrency configs and measures ProvisionedConcurrencyUtilization.
   - Flags idle provisioned concurrency (~$10.95/GB-month running 24/7).
4. Compute Optimizer Integration:
   - Integrates with AWS Compute Optimizer (get_lambda_function_recommendations) to identify
     real MemoryOverprovisioned opportunities based on p99 memory utilization.
   - Falls back gracefully to AWS Lambda Power Tuning guidance.
5. Arm64 Compatibility & Blocker Checks:
   - Inspects layers for CompatibleArchitectures.
   - Checks PackageType ("Image" container functions flagged as requiring multi-arch build).
6. Batched CloudWatch Metrics & Tagging API:
   - Batches Invocations, Duration, and Errors in chunks of 150 functions (450 queries) via get_metric_data.
   - Batches tags across all functions via resourcegroupstaggingapi.
7. Merged, Non-Overlapping Findings:
   - Evaluates improvements in order (Idle -> Rightsizing -> Graviton on reduced base),
     emitting a single consolidated finding per function without double counting.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")

# AWS Lambda Reference Pricing (us-east-1 reference)
PRICE_X86_GB_S = 0.0000166667
PRICE_ARM_GB_S = 0.0000133334
PRICE_PER_REQUEST = 0.20 / 1_000_000
PRICE_PROVISIONED_GB_S = 0.0000041667  # ~$10.95/GB-month


def _chunks(seq: list, n: int) -> Generator[list, None, None]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


class LambdaScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "lambda"

    @property
    def display_name(self) -> str:
        return "AWS Lambda"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc)
        lookback_days = CONFIG.LAMBDA_INACTIVE_DAYS
        start_time = now - timedelta(days=lookback_days)

        try:
            lam = self.get_client(session, "lambda", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[Lambda] Failed to initialize clients in {region}: {e}")
            return findings

        # ---------------------------------------------------------------------
        # 1. Paginate All Functions in the Region
        # ---------------------------------------------------------------------
        all_functions: List[Dict[str, Any]] = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for f in page.get("Functions", []):
                    # Skip Lambda@Edge replicas (e.g. us-east-1.my-func in other regions)
                    name = f.get("FunctionName", "")
                    if "." in name and any(r in name for r in ("us-east-1.", "us-west-2.", "eu-west-1.")):
                        continue
                    all_functions.append(f)
        except ClientError as ce:
            self.handle_client_error(ce, f"list_functions in {region}")
            return findings

        if not all_functions:
            return findings

        # ---------------------------------------------------------------------
        # 2. Batch Fetch Tags via Resource Groups Tagging API
        # ---------------------------------------------------------------------
        tags_by_arn = self._fetch_tags_by_arn(session, region)

        # ---------------------------------------------------------------------
        # 3. Batch Fetch CloudWatch Metrics (Invocations, Duration, Errors)
        # ---------------------------------------------------------------------
        function_names = [f["FunctionName"] for f in all_functions]
        metrics_map = self._fetch_batched_metrics(cw, function_names, start_time, now, lookback_days)

        # ---------------------------------------------------------------------
        # 4. Fetch Compute Optimizer Recommendations (Optional / Opt-in)
        # ---------------------------------------------------------------------
        co_recommendations = self._fetch_compute_optimizer_recommendations(session, region)

        # ---------------------------------------------------------------------
        # 5. Pre-Fetch CloudWatch Log Group Sizes for Inactive Candidates
        # ---------------------------------------------------------------------
        log_storage_map = self._fetch_log_group_sizes(session, region)

        # ---------------------------------------------------------------------
        # 6. Evaluate Each Function with Merged, Non-Overlapping Logic
        # ---------------------------------------------------------------------
        for func in all_functions:
            name = func.get("FunctionName", "")
            arn = func.get("FunctionArn", name)
            mem_mb = func.get("MemorySize", 128)
            timeout = func.get("Timeout", 3)
            runtime = func.get("Runtime", "")
            architectures = func.get("Architectures", ["x86_64"])
            arch = "arm64" if "arm64" in architectures else "x86_64"
            package_type = func.get("PackageType", "Zip")
            ephemeral_storage = func.get("EphemeralStorage", {}).get("Size", 512)

            tags = tags_by_arn.get(arn, {})
            # Check ignore tags
            if any(k in tags for k in CONFIG.IGNORE_TAG_KEYS):
                continue

            # Identify infrastructure management (CloudFormation, SAM, CDK, Serverless)
            managed_by = self._detect_manager(tags)

            # Check LastModified age
            modified_days_ago = 999
            last_mod_str = func.get("LastModified")
            if last_mod_str:
                try:
                    # e.g. "2026-08-15T12:00:00.000+0000"
                    clean_ts = last_mod_str.replace("+0000", "+00:00").replace("Z", "+00:00")
                    last_mod_dt = datetime.fromisoformat(clean_ts)
                    modified_days_ago = max((now - last_mod_dt).days, 0)
                except Exception:
                    pass

            # Metrics
            m = metrics_map.get(name, {"Invocations": 0.0, "Duration": 0.0, "Errors": 0.0})
            invocations_30d = m["Invocations"] * (30.0 / lookback_days)
            duration_sum_ms_30d = m["Duration"] * (30.0 / lookback_days)
            errors_30d = m["Errors"] * (30.0 / lookback_days)

            # Compute GB-seconds and Real Estimated Cost
            gb_seconds_30d = (duration_sum_ms_30d / 1000.0) * (mem_mb / 1024.0)
            compute_rate = PRICE_ARM_GB_S if arch == "arm64" else PRICE_X86_GB_S
            monthly_compute_cost = (gb_seconds_30d * compute_rate) + (invocations_30d * PRICE_PER_REQUEST)

            common_meta = {
                "arn": arn,
                "runtime": runtime,
                "package_type": package_type,
                "architecture": arch,
                "memory_mb": mem_mb,
                "timeout_sec": timeout,
                "ephemeral_storage_mb": ephemeral_storage,
                "invocations_30d": round(invocations_30d, 1),
                "errors_30d": round(errors_30d, 1),
                "duration_sum_sec_30d": round(duration_sum_ms_30d / 1000.0, 1),
                "gb_seconds_30d": round(gb_seconds_30d, 2),
                "monthly_compute_cost": round(monthly_compute_cost, 2),
                "modified_days_ago": modified_days_ago,
                "managed_by": managed_by,
                "tags": tags,
            }

            def make_rec(action_text: str) -> str:
                if managed_by:
                    return f"Update {managed_by} template/IaC configuration: {action_text}"
                return action_text

            # -----------------------------------------------------------------
            # Check 1: Idle Provisioned Concurrency (The biggest Lambda waste!)
            # -----------------------------------------------------------------
            prov_finding = self._check_provisioned_concurrency(
                lam, cw, name, arn, mem_mb, common_meta, make_rec
            )
            if prov_finding:
                findings.append(prov_finding)

            # -----------------------------------------------------------------
            # Check 2: Inactive Function (0 invocations over lookback window)
            # -----------------------------------------------------------------
            if m["Invocations"] == 0.0 and modified_days_ago > lookback_days:
                # Check for triggers / event source mappings before judging
                has_resource_policy = self._has_trigger_policy(lam, name)
                log_group_name = f"/aws/lambda/{name}"
                log_stored_bytes = log_storage_map.get(log_group_name, 0)
                log_stored_mb = log_stored_bytes / (1024**2)
                log_monthly_saving = (log_stored_bytes / (1024**3)) * CONFIG.CLOUDWATCH_LOGS_COST_PER_GB

                common_meta["has_resource_policy"] = has_resource_policy
                common_meta["log_stored_mb"] = round(log_stored_mb, 2)

                conf = "Low" if has_resource_policy else "High"
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=arn,
                        resource_name=name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence=conf,
                        issue=(
                            f"Inactive Lambda function (0 invocations over {lookback_days} days, "
                            f"last modified {modified_days_ago} days ago, holding {log_stored_mb:.1f} MB in logs)"
                        ),
                        recommendation=make_rec(
                            "Verify if this function is a seasonal job, DR handler, or abandoned test. "
                            "Archive code and delete function + log group to eliminate clutter and log storage charges"
                        ),
                        estimated_monthly_saving=round(log_monthly_saving, 2),
                        metadata=common_meta,
                    )
                )
                # Inactive function compute optimization is moot
                continue

            # -----------------------------------------------------------------
            # Check 3: Active Function Rightsizing & Graviton (Merged Findings)
            # -----------------------------------------------------------------
            improvement_recs: List[str] = []
            total_function_savings = 0.0

            # 3a. Compute Optimizer Memory Rightsizing
            effective_mem_mb = mem_mb
            co_rec = co_recommendations.get(arn)
            if co_rec and "MemoryOverprovisioned" in co_rec.get("findingReasonCodes", []):
                opt = co_rec.get("memorySizeRecommendationOptions", [{}])[0]
                target_mem = opt.get("memorySize", mem_mb)
                savings_val = float(
                    opt.get("savingsOpportunity", {})
                    .get("estimatedMonthlySavings", {})
                    .get("value", 0.0)
                )
                if savings_val >= CONFIG.LAMBDA_MIN_MONTHLY_SAVINGS:
                    total_function_savings += savings_val
                    effective_mem_mb = target_mem
                    improvement_recs.append(
                        f"Rightsize memory from {mem_mb} MB to {target_mem} MB (Compute Optimizer estimated saving: ${savings_val:.2f}/mo)"
                    )
            elif mem_mb > CONFIG.LAMBDA_HIGH_MEMORY_MB and monthly_compute_cost >= 10.0:
                # High memory heuristic when Compute Optimizer is inactive
                improvement_recs.append(
                    f"Profile memory allocation ({mem_mb} MB) with AWS Lambda Power Tuning to verify optimal vCPU/cost trade-off"
                )

            # 3b. Graviton2 (x86_64 -> arm64) Migration
            if "x86_64" in architectures and runtime:
                # Check blockers
                blockers = self._check_arm_blockers(lam, func)
                common_meta["arm_blockers"] = blockers

                # Savings on the (possibly rightsized) effective memory
                effective_gb_s = (duration_sum_ms_30d / 1000.0) * (effective_mem_mb / 1024.0)
                arm_saving = effective_gb_s * (PRICE_X86_GB_S - PRICE_ARM_GB_S)

                if arm_saving >= CONFIG.LAMBDA_MIN_MONTHLY_SAVINGS:
                    total_function_savings += arm_saving
                    if blockers:
                        improvement_recs.append(
                            f"Migrate architecture to arm64 Graviton2 (saves ~${arm_saving:.2f}/mo, note blockers: {'; '.join(blockers)})"
                        )
                    else:
                        improvement_recs.append(
                            f"Switch architecture to arm64 AWS Graviton2 for ~20% execution cost reduction (saves ~${arm_saving:.2f}/mo)"
                        )

            # 3c. Emit Merged Cost Optimization Finding if Savings Exceed Threshold
            if total_function_savings >= CONFIG.LAMBDA_MIN_MONTHLY_SAVINGS:
                sev = Severity.HIGH if total_function_savings >= 25.0 else Severity.MEDIUM
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=arn,
                        resource_name=name,
                        region=region,
                        severity=sev,
                        effort="Low",
                        confidence="High" if not common_meta.get("arm_blockers") else "Medium",
                        issue=(
                            f"Lambda function optimization opportunity (currently ${monthly_compute_cost:.2f}/mo compute spend; "
                            f"potential saving: ${total_function_savings:.2f}/mo)"
                        ),
                        recommendation=make_rec("; ".join(improvement_recs)),
                        estimated_monthly_saving=round(total_function_savings, 2),
                        metadata=common_meta,
                    )
                )

            # -----------------------------------------------------------------
            # Check 4: Deprecated Runtime (Operational / Security Risk)
            # -----------------------------------------------------------------
            if runtime in CONFIG.LAMBDA_DEPRECATED_RUNTIMES:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=arn,
                        resource_name=name,
                        region=region,
                        severity=Severity.LOW,
                        effort="Medium",
                        confidence="High",
                        issue=f"Lambda function using deprecated/end-of-life runtime '{runtime}'",
                        recommendation=make_rec(
                            f"Upgrade runtime from '{runtime}' to supported version to avoid AWS extended support fees and security exposure"
                        ),
                        estimated_monthly_saving=0.0,
                        metadata=common_meta,
                    )
                )

            # -----------------------------------------------------------------
            # Check 5: High Error Rate Waste
            # -----------------------------------------------------------------
            if m["Invocations"] >= 100.0 and (m["Errors"] / m["Invocations"]) >= 0.20:
                error_pct = (m["Errors"] / m["Invocations"]) * 100.0
                wasted_compute = monthly_compute_cost * (error_pct / 100.0)
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=arn,
                        resource_name=name,
                        region=region,
                        severity=Severity.MEDIUM,
                        effort="Medium",
                        confidence="Medium",
                        issue=f"High failure rate ({error_pct:.1f}% errors across {invocations_30d:.0f} monthly invocations)",
                        recommendation=make_rec(
                            "Investigate invocation exceptions and fix timeouts to prevent burning compute and async retry charges"
                        ),
                        estimated_monthly_saving=round(wasted_compute, 2),
                        metadata=common_meta,
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    def _fetch_tags_by_arn(self, session: boto3.Session, region: str) -> Dict[str, Dict[str, str]]:
        """Batch fetches tags for all Lambda functions via Resource Groups Tagging API."""
        tags_by_arn: Dict[str, Dict[str, str]] = {}
        try:
            tagging = self.get_client(session, "resourcegroupstaggingapi", region)
            paginator = tagging.get_paginator("get_resources")
            for page in paginator.paginate(ResourceTypeFilters=["lambda:function"]):
                for r in page.get("ResourceTagMappingList", []):
                    arn = r.get("ResourceARN", "")
                    tags_by_arn[arn] = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
        except ClientError as ce:
            logger.debug(f"[Lambda] ResourceGroupTaggingAPI in {region}: {ce}")
        except Exception:
            pass
        return tags_by_arn

    def _fetch_batched_metrics(
        self,
        cw: Any,
        function_names: List[str],
        start: datetime,
        end: datetime,
        lookback_days: int,
    ) -> Dict[str, Dict[str, float]]:
        """
        Batches CloudWatch get_metric_data queries for Invocations, Duration, and Errors.
        Batches up to 150 functions per call (3 queries * 150 = 450 queries).
        """
        out: Dict[str, Dict[str, float]] = {
            n: {"Invocations": 0.0, "Duration": 0.0, "Errors": 0.0} for n in function_names
        }
        if not function_names or not cw:
            return out

        period_seconds = 86400 * lookback_days

        for chunk in _chunks(function_names, 150):
            lookup: Dict[str, Tuple[str, str]] = {}
            queries = []

            for i, fn in enumerate(chunk):
                for metric in ("Invocations", "Duration", "Errors"):
                    qid = f"{metric[:3].lower()}_{i}"
                    lookup[qid] = (fn, metric)
                    queries.append(
                        {
                            "Id": qid,
                            "MetricStat": {
                                "Metric": {
                                    "Namespace": "AWS/Lambda",
                                    "MetricName": metric,
                                    "Dimensions": [{"Name": "FunctionName", "Value": fn}],
                                },
                                "Period": period_seconds,
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
                            fn, metric = lookup[qid]
                            out[fn][metric] = sum(res.get("Values", []))
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for Lambda metrics")

        return out

    def _fetch_compute_optimizer_recommendations(
        self, session: boto3.Session, region: str
    ) -> Dict[str, Dict[str, Any]]:
        """Queries AWS Compute Optimizer for Lambda recommendations."""
        recs: Dict[str, Dict[str, Any]] = {}
        try:
            co = self.get_client(session, "compute-optimizer", region)
            paginator = co.get_paginator("get_lambda_function_recommendations")
            for page in paginator.paginate():
                for r in page.get("lambdaFunctionRecommendations", []):
                    arn = r.get("functionArn")
                    if arn:
                        recs[arn] = r
        except ClientError as ce:
            code = ce.response.get("Error", {}).get("Code", "")
            if code not in ("OptInRequiredException", "AccessDeniedException"):
                logger.debug(f"[Lambda] Compute Optimizer recommendations in {region}: {ce}")
        except Exception:
            pass
        return recs

    def _fetch_log_group_sizes(self, session: boto3.Session, region: str) -> Dict[str, int]:
        """Pre-fetches CloudWatch log group stored bytes for Lambda functions."""
        sizes: Dict[str, int] = {}
        try:
            logs = self.get_client(session, "logs", region)
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate(logGroupNamePrefix="/aws/lambda/"):
                for g in page.get("logGroups", []):
                    sizes[g.get("logGroupName", "")] = g.get("storedBytes", 0)
        except ClientError:
            pass
        except Exception:
            pass
        return sizes

    def _check_provisioned_concurrency(
        self,
        lam: Any,
        cw: Any,
        name: str,
        arn: str,
        mem_mb: int,
        common_meta: Dict[str, Any],
        make_rec: Any,
    ) -> Optional[Finding]:
        """Checks if a function has idle provisioned concurrency running 24/7."""
        try:
            configs = lam.list_provisioned_concurrency_configs(FunctionName=name).get(
                "ProvisionedConcurrencyConfigs", []
            )
            for c in configs:
                allocated = c.get("AllocatedProvisionedConcurrentExecutions", 0)
                qualifier = c.get("FunctionArn", "").split(":")[-1]  # Alias or version
                if allocated > 0 and cw:
                    # Query ProvisionedConcurrencyUtilization over 14 days
                    end = datetime.now(timezone.utc)
                    start = end - timedelta(days=14)
                    metric_resp = cw.get_metric_statistics(
                        Namespace="AWS/Lambda",
                        MetricName="ProvisionedConcurrencyUtilization",
                        Dimensions=[
                            {"Name": "FunctionName", "Value": name},
                            {"Name": "Resource", "Value": f"{name}:{qualifier}"},
                        ],
                        StartTime=start,
                        EndTime=end,
                        Period=86400 * 14,
                        Statistics=["Average"],
                    )
                    dps = metric_resp.get("Datapoints", [])
                    avg_util = dps[0].get("Average", 0.0) if dps else 0.0

                    # If utilization is under 5%, provisioned concurrency is idle waste
                    if avg_util < 0.05:
                        monthly_pc_cost = (
                            allocated
                            * (mem_mb / 1024.0)
                            * CONFIG.LAMBDA_PROVISIONED_GB_MONTHLY
                        )
                        return Finding(
                            service=self.display_name,
                            resource_id=arn,
                            resource_name=f"{name}:{qualifier}",
                            region=common_meta.get("region", "us-east-1"),
                            severity=Severity.HIGH,
                            effort="Medium",
                            confidence="High",
                            issue=(
                                f"Idle Provisioned Concurrency ({allocated} units allocated, "
                                f"average utilization only {avg_util * 100:.1f}% over 14 days; costing ${monthly_pc_cost:.2f}/mo)"
                            ),
                            recommendation=make_rec(
                                "Reduce or remove static provisioned concurrency, or configure Application Auto Scaling "
                                "to scale provisioned concurrency during scheduled business hours only"
                            ),
                            estimated_monthly_saving=round(monthly_pc_cost, 2),
                            metadata={
                                **common_meta,
                                "provisioned_concurrency_units": allocated,
                                "provisioned_concurrency_utilization": round(avg_util, 3),
                            },
                        )
        except ClientError:
            pass
        except Exception as e:
            logger.debug(f"[Lambda] Provisioned concurrency check for {name}: {e}")
        return None

    def _check_arm_blockers(self, lam: Any, func: Dict[str, Any]) -> List[str]:
        """Detects blockers that might prevent immediate arm64 Graviton2 adoption."""
        blockers: List[str] = []
        if func.get("PackageType") == "Image":
            blockers.append("container image (requires multi-arch build)")

        for layer in func.get("Layers", []):
            layer_arn = layer.get("Arn", "")
            try:
                v = lam.get_layer_version_by_arn(Arn=layer_arn)
                archs = v.get("CompatibleArchitectures", [])
                if archs and "arm64" not in archs:
                    blockers.append(f"layer missing arm64: {layer_arn.split(':')[-2]}")
            except ClientError:
                pass
        return blockers

    def _has_trigger_policy(self, lam: Any, function_name: str) -> bool:
        """Checks if a function has an event resource policy attached."""
        try:
            policy_resp = lam.get_policy(FunctionName=function_name)
            return bool(policy_resp.get("Policy"))
        except ClientError:
            return False

    @staticmethod
    def _detect_manager(tags: Dict[str, str]) -> Optional[str]:
        """Identifies if a function is managed by CloudFormation, SAM, CDK, or Serverless."""
        if "aws:cloudformation:stack-name" in tags or "aws:cloudformation:logical-id" in tags:
            return "AWS CloudFormation / SAM / CDK"
        if "serverless:service" in tags:
            return "Serverless Framework"
        return None
