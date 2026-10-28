"""
Production-Grade AWS Key Management Service (KMS) Waste & Optimization Scanner.

Key Cost Characteristics & Flaw Mitigations:
1. No Blind Age Checks:
   - Keys do not spoil with age; long-lived keys often protect mission-critical data.
   - Replaces age-only heuristics with evidence of use (active grants + CloudTrail cryptographic operations).
2. Elimination of PendingDeletion Bugs:
   - AWS does NOT bill keys in 'PendingDeletion' or 'PendingReplicaDeletion'.
   - Accurately tracks them with $0 savings, adding safety alerts for monitoring.
3. Pre-Filtered Aliases & Zero N+1 Calls:
   - Pre-fetches all aliases with list_aliases.
   - Skips AWS-managed keys ('alias/aws/*') before describe_key, saving dozens of API calls.
4. Real Usage Evidence (Grants + CloudTrail):
   - Positive usage evidence via active grants (EBS, RDS, Redshift, EMR).
   - Direct cryptographic usage check in CloudTrail (Decrypt, Encrypt, GenerateDataKey).
   - Only flags keys with 0 grants AND 0 crypto events over the lookback window (90 days).
5. Safe, Non-Destructive Recommendations:
   - Never advises immediate schedule_key_deletion (which is irreversible and causes permanent data loss).
   - Enforces a safety-first workflow: disable key -> monitor CloudTrail for DisabledException -> schedule deletion.
6. Spend Sizing via Cost Explorer:
   - Analyzes account-level KMS spend (Key storage fees vs API request charges).
   - Flags when request volume dominates base fees and advises client-side caching or S3 Bucket Keys.
7. Noise Reduction & Roll-Up:
   - Rolls up multiple $1/mo findings into consolidated, actionable regional findings.
   - Tracks unauditable keys (AccessDenied) into a dedicated summary finding.
8. Multi-Region Replicas & Custom Key Stores (CloudHSM):
   - Identifies multi-region replica keys ($1/mo each).
   - Flags Custom Key Stores (CloudHSM clusters costing hundreds of dollars/month).
"""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")

# Cryptographic operation prefixes in CloudTrail
CRYPTO_PREFIXES: Tuple[str, ...] = (
    "Decrypt",
    "Encrypt",
    "GenerateDataKey",
    "ReEncrypt",
    "Sign",
    "Verify",
    "GenerateMac",
    "VerifyMac",
)


class KMSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "kms"

    @property
    def display_name(self) -> str:
        return "AWS KMS"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc)
        lookback_days = CONFIG.KMS_LOOKBACK_DAYS
        start_time = now - timedelta(days=lookback_days)

        try:
            kms = self.get_client(session, "kms", region)
        except Exception as e:
            logger.error(f"[KMS] Failed to initialize KMS client in {region}: {e}")
            return findings

        # Optional CloudTrail client for auditing crypto usage
        ct = None
        try:
            ct = self.get_client(session, "cloudtrail", region)
        except Exception as e:
            logger.debug(f"[KMS] CloudTrail client unavailable in {region}: {e}")

        # ---------------------------------------------------------------------
        # 1. Account-Level Cost Explorer KMS Spend Sizing (Requests vs Key Fees)
        # ---------------------------------------------------------------------
        ce_finding = self._audit_kms_cost_explorer(session, region, now)
        if ce_finding:
            findings.append(ce_finding)

        # ---------------------------------------------------------------------
        # 2. Pre-Fetch All Aliases to Map TargetKeyIds & Skip AWS-Managed Keys
        # ---------------------------------------------------------------------
        alias_map = self._build_alias_map(kms)

        # ---------------------------------------------------------------------
        # 3. Categorize & Audit Customer Managed Keys
        # ---------------------------------------------------------------------
        disabled_keys: List[Dict[str, Any]] = []
        idle_enabled_keys: List[Dict[str, Any]] = []
        pending_deletion_keys: List[Dict[str, Any]] = []
        custom_store_keys: List[Dict[str, Any]] = []
        access_denied_keys: List[str] = []

        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_entry in page.get("Keys", []):
                    key_id = key_entry.get("KeyId", "")
                    key_arn = key_entry.get("KeyArn", key_id)
                    aliases = alias_map.get(key_id, [])

                    # Quick Skip: AWS-managed keys (e.g. alias/aws/s3, alias/aws/ebs)
                    # AWS-managed keys are free ($0/month) and cannot be deleted
                    if any(a.startswith("alias/aws/") for a in aliases):
                        continue

                    # Describe Key Metadata
                    try:
                        meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    except ClientError as ce:
                        code = ce.response.get("Error", {}).get("Code", "")
                        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
                            access_denied_keys.append(key_id)
                        continue

                    # Filter out AWS-owned or AWS-managed keys
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue

                    state = meta.get("KeyState", "")
                    created = meta.get("CreationDate")
                    age_days = (now - created).days if created else 0
                    desc = meta.get("Description", "")
                    alias_label = ", ".join(aliases) if aliases else (desc[:40] if desc else key_id[:16])

                    # Multi-Region & Custom Key Store details
                    mr_config = meta.get("MultiRegionConfiguration", {})
                    is_replica = mr_config.get("MultiRegionKeyType") == "REPLICA"
                    custom_store_id = meta.get("CustomKeyStoreId")
                    key_spec = meta.get("CustomerMasterKeySpec", meta.get("KeySpec", "SYMMETRIC_DEFAULT"))

                    key_info = {
                        "key_id": key_id,
                        "key_arn": key_arn,
                        "alias": alias_label,
                        "aliases": aliases,
                        "state": state,
                        "age_days": age_days,
                        "is_multi_region_replica": is_replica,
                        "custom_key_store_id": custom_store_id,
                        "key_spec": key_spec,
                    }

                    # Case A: Pending Deletion (AWS stops billing these; zero savings to claim)
                    if state in ("PendingDeletion", "PendingReplicaDeletion"):
                        key_info["deletion_date"] = str(meta.get("DeletionDate", ""))
                        pending_deletion_keys.append(key_info)
                        continue

                    # Case B: Disabled Customer Key ($1.00/mo fee still charged)
                    if state == "Disabled":
                        disabled_keys.append(key_info)
                        continue

                    # Case C: Enabled Customer Key -> Evidence of Use Check
                    if state == "Enabled":
                        # Check 1: Active Grants (EBS, RDS, Redshift attach grants)
                        has_grants = self._has_active_grants(kms, key_id)

                        # Check 2: CloudTrail Cryptographic Activity (Decrypt, Encrypt)
                        has_crypto_activity = True
                        if not has_grants:
                            has_crypto_activity = self._has_recent_crypto_activity(
                                ct, key_arn, start_time
                            )

                        if not has_grants and not has_crypto_activity:
                            # 0 grants AND 0 crypto operations in 90 days
                            idle_enabled_keys.append(key_info)
                        else:
                            # Active key check: Custom Key Store check
                            if custom_store_id:
                                custom_store_keys.append(key_info)

        except ClientError as ce:
            self.handle_client_error(ce, f"list_keys in {region}")

        # ---------------------------------------------------------------------
        # 4. Generate High-Quality, Rolled-Up Findings
        # ---------------------------------------------------------------------
        rate = CONFIG.KMS_KEY_MONTHLY_COST

        # Finding 1: Disabled Customer Managed Keys
        if disabled_keys:
            total_saving = len(disabled_keys) * rate
            primary_id = disabled_keys[0]["key_id"] if len(disabled_keys) == 1 else f"kms-disabled-{region}"
            primary_name = disabled_keys[0]["alias"] if len(disabled_keys) == 1 else f"{len(disabled_keys)} Disabled Customer Keys"
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=primary_id,
                    resource_name=primary_name,
                    region=region,
                    severity=Severity.MEDIUM,
                    effort="Low",
                    confidence="High",
                    issue=(
                        f"{len(disabled_keys)} disabled Customer Managed KMS Key(s) still incurring ${total_saving:.2f}/mo "
                        f"(${rate:.2f}/key/month base storage fee)"
                    ),
                    recommendation=(
                        "Verify whether historical snapshots, archives, or backups require these keys. If confirmed unneeded, "
                        "schedule deletion with a 30-day waiting period. "
                        "WARNING: Key deletion is permanent and irrecoverably destroys all data encrypted under the key."
                    ),
                    estimated_monthly_saving=total_saving,
                    metadata={"keys": disabled_keys, "count": len(disabled_keys)},
                )
            )

        # Finding 2: Inactive Enabled Keys (0 Grants + 0 Crypto Operations in 90 Days)
        if idle_enabled_keys:
            total_saving = len(idle_enabled_keys) * rate
            primary_id = idle_enabled_keys[0]["key_id"] if len(idle_enabled_keys) == 1 else f"kms-inactive-{region}"
            primary_name = idle_enabled_keys[0]["alias"] if len(idle_enabled_keys) == 1 else f"{len(idle_enabled_keys)} Inactive Customer Keys"
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=primary_id,
                    resource_name=primary_name,
                    region=region,
                    severity=Severity.LOW,
                    effort="Medium",
                    confidence="Medium",
                    issue=(
                        f"{len(idle_enabled_keys)} Customer Managed KMS Key(s) show 0 active grants and 0 cryptographic "
                        f"operations in CloudTrail over the last {lookback_days} days (costing ${total_saving:.2f}/mo)"
                    ),
                    recommendation=(
                        "Safety-first procedure: (1) Disable the key first. (2) Monitor CloudTrail for 'DisabledException' or "
                        "'KMSInvalidStateException' for 30–60 days to catch quarterly/annual batch jobs. (3) If no applications fail, "
                        "schedule key deletion with a 30-day waiting period. "
                        "WARNING: Key deletion permanently renders all data encrypted under this key unrecoverable."
                    ),
                    estimated_monthly_saving=total_saving,
                    metadata={
                        "keys": idle_enabled_keys,
                        "count": len(idle_enabled_keys),
                        "lookback_days": lookback_days,
                    },
                )
            )

        # Finding 3: Keys in Custom Key Stores (CloudHSM hardware spend)
        if custom_store_keys:
            store_ids = sorted(list({k["custom_key_store_id"] for k in custom_store_keys}))
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=f"kms-custom-store-{region}",
                    resource_name=f"Custom Key Store ({', '.join(store_ids)})",
                    region=region,
                    severity=Severity.HIGH,
                    effort="High",
                    confidence="High",
                    issue=(
                        f"{len(custom_store_keys)} KMS Key(s) hosted in AWS CloudHSM Custom Key Store(s): {', '.join(store_ids)}. "
                        "CloudHSM clusters incur dedicated hardware charges ($1,000+/mo per cluster) far exceeding $1/key fees"
                    ),
                    recommendation=(
                        "Review whether dedicated CloudHSM hardware is still strictly required for compliance (e.g. FIPS 140-2 Level 3). "
                        "Migrating to standard multi-tenant AWS KMS HSMs eliminates the dedicated CloudHSM cluster fee"
                    ),
                    estimated_monthly_saving=0.0,
                    metadata={"custom_store_ids": store_ids, "key_count": len(custom_store_keys)},
                )
            )

        # Finding 4: Keys Pending Deletion (Safety & Hygiene alert)
        if pending_deletion_keys:
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=f"kms-pending-deletion-{region}",
                    resource_name=f"{len(pending_deletion_keys)} Keys Pending Deletion",
                    region=region,
                    severity=Severity.LOW,
                    effort="Low",
                    confidence="High",
                    issue=(
                        f"{len(pending_deletion_keys)} Customer Managed KMS Key(s) currently scheduled for permanent deletion "
                        "(AWS charges $0 while in Pending Deletion)"
                    ),
                    recommendation=(
                        "Ensure a CloudWatch metric alarm is configured for 'KMSInvalidStateException' to catch any accidental "
                        "decryption attempts before the scheduled deletion date arrives"
                    ),
                    estimated_monthly_saving=0.0,
                    metadata={"keys": pending_deletion_keys, "count": len(pending_deletion_keys)},
                )
            )

        # Finding 5: Unauditable Keys due to AccessDenied
        if access_denied_keys:
            potential_waste = len(access_denied_keys) * rate
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=f"kms-access-denied-{region}",
                    resource_name=f"{len(access_denied_keys)} Unauditable KMS Keys",
                    region=region,
                    severity=Severity.LOW,
                    effort="Low",
                    confidence="High",
                    issue=(
                        f"{len(access_denied_keys)} Customer Managed KMS key(s) could not be described due to IAM permissions "
                        f"(AccessDeniedException, potential ~${potential_waste:.2f}/mo unverified spend)"
                    ),
                    recommendation="Grant kms:DescribeKey and kms:ListGrants permissions to the audit role to inspect these keys",
                    estimated_monthly_saving=potential_waste,
                    metadata={"unaudited_key_ids": access_denied_keys, "count": len(access_denied_keys)},
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    def _build_alias_map(self, kms: Any) -> Dict[str, List[str]]:
        """Maps TargetKeyId to a list of alias names."""
        m: Dict[str, List[str]] = defaultdict(list)
        try:
            for page in kms.get_paginator("list_aliases").paginate():
                for a in page.get("Aliases", []):
                    tid = a.get("TargetKeyId")
                    if tid:
                        m[tid].append(a.get("AliasName", ""))
        except ClientError as ce:
            self.handle_client_error(ce, "list_aliases in KMS")
        return m

    def _has_active_grants(self, kms: Any, key_id: str) -> bool:
        """Checks if a key has active grants (used by EBS, RDS, Redshift, etc.)."""
        try:
            for page in kms.get_paginator("list_grants").paginate(KeyId=key_id):
                if page.get("Grants"):
                    return True
        except ClientError:
            pass
        return False

    def _has_recent_crypto_activity(
        self, ct: Any, key_arn: str, start_time: datetime
    ) -> bool:
        """
        Queries CloudTrail lookup_events for cryptographic operations (Decrypt, Encrypt, GenerateDataKey).
        Returns True if activity is detected (or if CloudTrail is unavailable, defaulting to safe behavior).
        """
        if not ct:
            return True  # Safe default: cannot verify absence of activity

        try:
            paginator = ct.get_paginator("lookup_events")
            max_pages = CONFIG.KMS_MAX_CLOUDTRAIL_PAGES
            for idx, page in enumerate(
                paginator.paginate(
                    LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": key_arn}],
                    StartTime=start_time,
                )
            ):
                for ev in page.get("Events", []):
                    ename = ev.get("EventName", "")
                    if ename.startswith(CRYPTO_PREFIXES):
                        return True
                if idx + 1 >= max_pages:
                    break
            return False
        except ClientError as ce:
            # On rate limits or permissions, default to safe assumption (active)
            logger.debug(f"[KMS] CloudTrail lookup_events for {key_arn}: {ce}")
            return True
        except Exception:
            return True

    def _audit_kms_cost_explorer(
        self, session: boto3.Session, region: str, now: datetime
    ) -> Optional[Finding]:
        """
        Queries AWS Cost Explorer at the account level to size Key fees vs Request fees.
        Flags when high-frequency API calls dominate the bill.
        """
        try:
            ce = self.get_client(session, "ce", "us-east-1")
            end_date = now.strftime("%Y-%m-%d")
            start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d")

            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start_date, "End": end_date},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                Filter={"Dimensions": {"Key": "SERVICE", "Values": ["AWS Key Management Service"]}},
                GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
            )

            key_cost = 0.0
            request_cost = 0.0

            for group in resp.get("ResultsByTime", [{}])[-1].get("Groups", []):
                usage_type = group.get("Keys", [""])[0]
                cost = float(group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0.0))
                if "KMS-Keys" in usage_type:
                    key_cost += cost
                elif "KMS-Request" in usage_type or "KMS-Requests" in usage_type:
                    request_cost += cost

            # If request costs dominate key storage costs significantly (e.g. > $20/mo and > 2x key fees)
            if request_cost >= 20.0 and request_cost > (2.0 * max(key_cost, 1.0)):
                saving_est = request_cost * 0.50  # ~50% savings via caching / Bucket Keys
                return Finding(
                    service=self.display_name,
                    resource_id=f"kms-request-charges-{region}",
                    resource_name="KMS API Request Volume",
                    region=region,
                    severity=Severity.HIGH if request_cost >= 50.0 else Severity.MEDIUM,
                    effort="Medium",
                    confidence="High",
                    issue=(
                        f"KMS API request charges (${request_cost:.2f}/mo) dominate key storage fees (${key_cost:.2f}/mo). "
                        "High-frequency Decrypt/GenerateDataKey API calls drive the majority of KMS spend"
                    ),
                    recommendation=(
                        "Optimize request volume: (1) Enable S3 Bucket Keys on SSE-KMS encrypted buckets (cuts S3 KMS request fees by up to 99%). "
                        "(2) Implement client-side data key caching with the AWS Encryption SDK for microservices. "
                        "(3) Cache secrets fetched from AWS Secrets Manager."
                    ),
                    estimated_monthly_saving=saving_est,
                    metadata={
                        "monthly_request_cost": round(request_cost, 2),
                        "monthly_key_cost": round(key_cost, 2),
                    },
                )
        except ClientError:
            pass
        except Exception as e:
            logger.debug(f"[KMS] Cost Explorer query skipped: {e}")
        return None
