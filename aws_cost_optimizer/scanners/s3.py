import logging
from typing import List
import boto3
from botocore.exceptions import ClientError
from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")


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
        try:
            s3 = self.get_client(session, "s3")
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            logger.error(f"[S3] Could not list buckets: {e}")
            return findings

        for b in buckets:
            b_name = b.get("Name", "")

            # 1. Bucket Location / Region
            try:
                loc_resp = s3.get_bucket_location(Bucket=b_name)
                b_region = loc_resp.get("LocationConstraint") or "us-east-1"
                if b_region == "EU":
                    b_region = "eu-west-1"
            except ClientError:
                b_region = "global"

            # 2. Lifecycle Configuration
            has_lifecycle = False
            has_abort_multipart = False
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=b_name)
                rules = lifecycle.get("Rules", [])
                if rules:
                    has_lifecycle = True
                    for r in rules:
                        if r.get("Status") == "Enabled" and "AbortIncompleteMultipartUpload" in r:
                            has_abort_multipart = True
                            break
            except ClientError as ce:
                err_code = ce.response.get("Error", {}).get("Code", "")
                if err_code not in ("NoSuchLifecycleConfiguration", "AccessDenied"):
                    self.handle_client_error(ce, f"lifecycle for bucket {b_name}")

            if not has_lifecycle:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=b_name,
                        resource_name=b_name,
                        region=b_region,
                        severity=Severity.MEDIUM,
                        issue="No S3 Lifecycle policy configured",
                        recommendation="Configure lifecycle rules to transition older objects to Infrequent Access / Glacier or expire temporary data",
                        estimated_monthly_saving=15.0,
                    )
                )

            if not has_abort_multipart:
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=b_name,
                        resource_name=b_name,
                        region=b_region,
                        severity=Severity.LOW,
                        issue="No 'AbortIncompleteMultipartUpload' rule configured",
                        recommendation=f"Add an S3 lifecycle rule to abort incomplete multipart uploads after {CONFIG.S3_MULTIPART_EXPIRATION_DAYS} days to prevent silent storage fees",
                        estimated_monthly_saving=5.0,
                    )
                )

            # 3. Versioning check
            try:
                versioning = s3.get_bucket_versioning(Bucket=b_name)
                if versioning.get("Status") == "Enabled" and not has_lifecycle:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=b_name,
                            resource_name=b_name,
                            region=b_region,
                            severity=Severity.MEDIUM,
                            issue="Versioning enabled with no NoncurrentVersionExpiration lifecycle rule",
                            recommendation="Add a lifecycle rule to expire non-current object versions after 30-90 days to avoid duplicate storage costs",
                            estimated_monthly_saving=20.0,
                        )
                    )
            except ClientError as ce:
                err_code = ce.response.get("Error", {}).get("Code", "")
                if err_code != "AccessDenied":
                    self.handle_client_error(ce, f"versioning for bucket {b_name}")

            # 4. SSE-KMS without S3 Bucket Keys check
            try:
                enc = s3.get_bucket_encryption(Bucket=b_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                for r in rules:
                    apply_server_side = r.get("ApplyServerSideEncryptionByDefault", {})
                    algo = apply_server_side.get("SSEAlgorithm")
                    bucket_key_enabled = r.get("BucketKeyEnabled", False)
                    if algo == "aws:kms" and not bucket_key_enabled:
                        findings.append(
                            Finding(
                                service=self.display_name,
                                resource_id=b_name,
                                resource_name=b_name,
                                region=b_region,
                                severity=Severity.MEDIUM,
                                effort="Low",
                                confidence="High",
                                issue="S3 SSE-KMS encryption enabled without S3 Bucket Keys",
                                recommendation=(
                                    "Enable S3 Bucket Keys on this bucket to decrease AWS KMS request traffic by up to 99%, "
                                    "reducing KMS request charges on PUT/GET operations"
                                ),
                                estimated_monthly_saving=10.0,
                                metadata={"sse_algorithm": algo, "bucket_key_enabled": False},
                            )
                        )
                        break
            except ClientError as ce:
                err_code = ce.response.get("Error", {}).get("Code", "")
                if err_code not in ("ServerSideEncryptionConfigurationNotFoundError", "AccessDenied"):
                    self.handle_client_error(ce, f"encryption for bucket {b_name}")

        return findings
