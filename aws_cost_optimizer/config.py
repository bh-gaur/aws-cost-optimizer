"""
Centralized Configuration & Thresholds for AWS Cost Optimizer.
All thresholds can be overridden via environment variables or customized here.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, Tuple


@dataclass(frozen=True)
class CostConfig:
    # --- General / Engine ---
    MAX_WORKER_THREADS: int = int(os.getenv("AICO_MAX_THREADS", "8"))
    AWS_MAX_ATTEMPTS: int = int(os.getenv("AICO_AWS_MAX_ATTEMPTS", "10"))
    METRIC_LOOKBACK_DAYS: int = int(os.getenv("AICO_METRIC_DAYS", "14"))

    # --- EC2 Upgrades & Mappings ---
    PREV_GEN_UPGRADES: Dict[str, str] = field(
        default_factory=lambda: {
            "t2": "t3",
            "m4": "m5",
            "c4": "c5",
            "r4": "r5",
            "i3": "i4i",
        }
    )

    GRAVITON_UPGRADES: Dict[str, str] = field(
        default_factory=lambda: {
            "t3": "t4g",
            "t3a": "t4g",
            "m5": "m6g",
            "m5a": "m6g",
            "c5": "c6g",
            "c5a": "c6g",
            "r5": "r6g",
            "r5a": "r6g",
        }
    )

    # --- EC2 Idle & Detection Thresholds ---
    EC2_IDLE_CPU_AVG_THRESHOLD: float = float(os.getenv("AICO_EC2_CPU_AVG", "5.0"))
    EC2_IDLE_CPU_MAX_THRESHOLD: float = float(os.getenv("AICO_EC2_CPU_MAX", "20.0"))
    EC2_MIN_DATAPOINTS: int = int(os.getenv("AICO_EC2_MIN_DATAPOINTS", "3"))  # min days of data required
    EC2_NETWORK_BUSY_MB_DAILY: float = float(os.getenv("AICO_EC2_NET_MB", "50.0"))  # MB/day network guard

    # --- Guard Tags ---
    IGNORE_TAG_KEYS: Tuple[str, ...] = (
        "cost-optimizer:ignore",
        "cost-optimization:skip",
        "cost-optimizer:skip",
    )
    EKS_TAG_PREFIXES: Tuple[str, ...] = (
        "eks:cluster-name",
        "kubernetes.io/cluster/",
    )
    ASG_TAG_KEY: str = "aws:autoscaling:groupName"

    # --- EBS Thresholds ---
    EBS_GP2_SAVINGS_RATIO: float = 0.20
    EBS_LARGE_VOLUME_GB: int = int(os.getenv("AICO_EBS_LARGE_GB", "500"))
    EBS_STALE_SNAPSHOT_DAYS: int = int(os.getenv("AICO_EBS_SNAPSHOT_DAYS", "90"))
    EBS_STORAGE_COST_PER_GB: float = 0.08
    EBS_SNAPSHOT_COST_PER_GB: float = 0.05

    # --- VPC / Networking ---
    VPC_EIP_IDLE_HOURLY_COST: float = 0.005  # $0.005/hr = ~$3.65/mo
    VPC_PUBLIC_IPV4_HOURLY_COST: float = 0.005  # All public IPv4 charged since Feb 2024 ($0.005/hr = ~$3.65/mo)
    VPC_NAT_GATEWAY_HOURLY_BASE: float = 0.045  # $0.045/hr = ~$32.85/mo
    VPC_NAT_IDLE_TRAFFIC_MB_THRESHOLD: float = float(os.getenv("AICO_NAT_TRAFFIC_MB", "10.0"))
    VPC_INTERFACE_ENDPOINT_HOURLY_AZ: float = float(os.getenv("AICO_VPC_ENDPOINT_HOURLY", "0.01"))  # $0.01/AZ/hr = ~$7.30/AZ/mo
    VPC_VPN_HOURLY_BASE: float = float(os.getenv("AICO_VPC_VPN_HOURLY", "0.05"))  # $0.05/hr = ~$36.50/mo

    # --- ELB ---
    ELB_CLB_HOURLY_BASE: float = 0.025
    ELB_ALB_HOURLY_BASE: float = 0.0225
    ELB_NLB_HOURLY_BASE: float = 0.0225
    ELB_GLB_HOURLY_BASE: float = 0.0125
    ELB_LOOKBACK_DAYS: int = int(os.getenv("AICO_ELB_LOOKBACK_DAYS", "30"))
    ELB_GRACE_PERIOD_DAYS: int = int(os.getenv("AICO_ELB_GRACE_DAYS", "7"))
    ELB_CONSOLIDATION_DAILY_REQUESTS: float = float(
        os.getenv("AICO_ELB_CONSOLIDATION_REQ_DAILY", "1000.0")
    )

    # --- RDS ---
    RDS_IDLE_CONNECTIONS_THRESHOLD: int = int(os.getenv("AICO_RDS_IDLE_CONN", "0"))
    RDS_OLD_SNAPSHOT_DAYS: int = int(os.getenv("AICO_RDS_SNAPSHOT_DAYS", "30"))
    RDS_PREVIOUS_GEN_MAPPING: Dict[str, str] = field(
        default_factory=lambda: {
            "db.t2": "db.t3",
            "db.m4": "db.m5",
            "db.r4": "db.r5",
            "db.m5": "db.m6g",
            "db.r5": "db.r6g",
        }
    )
    RDS_GP2_STORAGE_RATE: float = 0.115  # $/GB-month in us-east-1
    RDS_GP3_STORAGE_RATE: float = 0.092  # $/GB-month (20% lower than gp2)
    RDS_EXTENDED_SUPPORT_VCPU_HOURLY: float = 0.10  # ~$73/vCPU-month in Years 1-2

    # --- S3 ---
    S3_MULTIPART_EXPIRATION_DAYS: int = 7
    S3_STANDARD_STORAGE_COST_PER_GB: float = 0.023  # us-east-1 reference rate ($/GB-mo)
    S3_STANDARD_IA_COST_PER_GB: float = 0.0125  # us-east-1 reference rate ($/GB-mo)
    S3_ASSUMED_COLD_DATA_FRACTION: float = float(os.getenv("AICO_S3_COLD_FRACTION", "0.50"))  # Assumed cold data share
    S3_MIN_AVG_OBJECT_SIZE_KB: float = 128.0  # Standard-IA minimum billable object size
    S3_MIN_MONTHLY_SAVING_THRESHOLD: float = float(os.getenv("AICO_S3_MIN_SAVINGS", "1.00"))  # Noise filter threshold

    # --- Lambda ---
    LAMBDA_INACTIVE_DAYS: int = int(os.getenv("AICO_LAMBDA_DAYS", "90"))
    LAMBDA_HIGH_MEMORY_MB: int = int(os.getenv("AICO_LAMBDA_MEM_MB", "1024"))
    LAMBDA_ARM_SAVINGS_PERCENT: float = 0.20
    LAMBDA_MIN_MONTHLY_SAVINGS: float = float(os.getenv("AICO_LAMBDA_MIN_SAVINGS", "0.50"))
    LAMBDA_PROVISIONED_GB_MONTHLY: float = 10.95  # ~$0.0000041667/GB-s * 3600 * 730
    LAMBDA_DEPRECATED_RUNTIMES: Tuple[str, ...] = (
        "python2.7",
        "python3.6",
        "python3.7",
        "python3.8",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "nodejs16.x",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "dotnet5.0",
        "java8",
        "ruby2.5",
        "ruby2.7",
    )

    # --- CloudWatch ---
    CLOUDWATCH_LOGS_COST_PER_GB: float = 0.03
    CLOUDWATCH_INGESTION_COST_PER_GB: float = 0.50
    CLOUDWATCH_IA_INGESTION_COST_PER_GB: float = 0.25
    CLOUDWATCH_HIGH_INGESTION_GB_THRESHOLD: float = float(os.getenv("AICO_CW_HIGH_INGEST_GB", "20.0"))

    # --- KMS ---
    KMS_KEY_MONTHLY_COST: float = 1.00
    KMS_LOOKBACK_DAYS: int = int(os.getenv("AICO_KMS_LOOKBACK_DAYS", "90"))
    KMS_MAX_CLOUDTRAIL_PAGES: int = int(os.getenv("AICO_KMS_CT_PAGES", "3"))


CONFIG = CostConfig()
