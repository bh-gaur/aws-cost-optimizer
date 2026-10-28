import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.price_book import PriceBook
from aws_cost_optimizer.reporters.console import print_console_report
from aws_cost_optimizer.reporters.csv_report import export_to_csv, export_to_json
from aws_cost_optimizer.scanners.cloudwatch import CloudWatchScanner
from aws_cost_optimizer.scanners.ebs import EBSScanner
from aws_cost_optimizer.scanners.ec2 import EC2Scanner, _parse_stopped_date
from aws_cost_optimizer.scanners.elb import ELBScanner
from aws_cost_optimizer.scanners.kms import KMSScanner
from aws_cost_optimizer.scanners.lambda_func import LambdaScanner
from aws_cost_optimizer.scanners.rds import RDSScanner
from aws_cost_optimizer.scanners.s3 import S3Scanner
from aws_cost_optimizer.scanners.vpc import VPCScanner
from aws_cost_optimizer.scanners.dynamodb import DynamoDBScanner


def test_finding_to_dict():
    f = Finding(
        service="Amazon EC2",
        resource_id="i-1234567890abcdef0",
        region="us-east-1",
        severity=Severity.HIGH,
        effort="Low",
        confidence="High",
        issue="Stopped instance",
        recommendation="Terminate instance",
        estimated_monthly_saving=30.0,
    )
    d = f.to_dict()
    assert d["resource_id"] == "i-1234567890abcdef0"
    assert d["severity"] == "HIGH"
    assert d["effort"] == "Low"
    assert d["confidence"] == "High"
    assert d["estimated_monthly_saving"] == 30.0


def test_parse_stopped_date():
    reason = "User initiated (2026-08-01 10:15:33 GMT)"
    dt = _parse_stopped_date(reason)
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 8
    assert dt.day == 1

    assert _parse_stopped_date("") is None
    assert _parse_stopped_date("Client.InternalError") is None


def test_price_book_real_time_and_fallbacks():
    mock_session = MagicMock()
    mock_pricing = MagicMock()
    mock_session.client.return_value = mock_pricing

    mock_pricing.get_products.return_value = {
        "PriceList": [
            """{
                "terms": {
                    "OnDemand": {
                        "TERM1": {
                            "priceDimensions": {
                                "DIM1": {
                                    "pricePerUnit": {"USD": "0.0960000000"},
                                    "unit": "Hrs"
                                }
                            }
                        }
                    }
                }
            }"""
        ]
    }

    pb = PriceBook(mock_session)
    price = pb.ec2_hourly("m5.large", "us-east-1")
    assert price == 0.096


def test_ec2_previous_gen_exact_family():
    scanner = EC2Scanner()
    pb = PriceBook(MagicMock())

    # 1. t2.large -> t3.large
    inst_t2 = {"InstanceId": "i-t2", "InstanceType": "t2.large", "Tags": []}
    finding_t2 = scanner._check_previous_gen(inst_t2, {}, "us-east-1", False, "", pb)
    assert finding_t2 is not None
    assert "t3.large" in finding_t2.recommendation

    # 2. i3.large -> i4i.large
    inst_i3 = {"InstanceId": "i-i3", "InstanceType": "i3.large", "Tags": []}
    finding_i3 = scanner._check_previous_gen(inst_i3, {}, "us-east-1", False, "", pb)
    assert finding_i3 is not None
    assert "i4i.large" in finding_i3.recommendation

    # 3. i3en.large should NOT match
    inst_i3en = {"InstanceId": "i-i3en", "InstanceType": "i3en.large", "Tags": []}
    finding_i3en = scanner._check_previous_gen(inst_i3en, {}, "us-east-1", False, "", pb)
    assert finding_i3en is None


def test_ebs_scanner_no_overlapping_and_no_floor():
    scanner = EBSScanner()
    mock_session = MagicMock()
    mock_ec2 = MagicMock()
    mock_cw = MagicMock()
    mock_pricing = MagicMock()
    mock_dlm = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_ec2 if svc == "ec2" else (
            mock_cw if svc == "cloudwatch" else (
                mock_dlm if svc == "dlm" else mock_pricing
            )
        )
    )

    mock_vol_paginator = MagicMock()
    mock_vol_paginator.paginate.return_value = [
        {
            "Volumes": [
                {
                    "VolumeId": "vol-small-orphan",
                    "Size": 8,
                    "VolumeType": "gp3",
                    "State": "available",
                    "Attachments": [],
                    "CreateTime": datetime(2026, 8, 1, tzinfo=timezone.utc),
                    "Tags": [],
                }
            ]
        }
    ]

    mock_snap_paginator = MagicMock()
    mock_snap_paginator.paginate.return_value = [{"Snapshots": []}]

    mock_ec2.get_paginator.side_effect = lambda op: mock_vol_paginator if op == "describe_volumes" else mock_snap_paginator
    mock_ec2.describe_images.return_value = {"Images": []}
    mock_ec2.describe_fast_snapshot_restores.return_value = {"FastSnapshotRestores": []}
    mock_dlm.get_lifecycle_policies.return_value = {"Policies": [{"PolicyId": "dlm-1"}]}

    findings = scanner.scan(mock_session, "us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == "vol-small-orphan"
    # 8 GB * $0.08 = $0.64 (No arbitrary $5 floor)
    assert findings[0].estimated_monthly_saving == 0.64


def test_cloudwatch_never_expire_no_floor_and_orphaned_lambda():
    scanner = CloudWatchScanner()
    mock_session = MagicMock()
    mock_logs = MagicMock()
    mock_cw = MagicMock()
    mock_lambda = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_logs if svc == "logs" else (mock_cw if svc == "cloudwatch" else mock_lambda)
    )

    # 1. Tiny group (2MB) created 100 days ago -> saving is < $0.50 -> should be SKIPPED (no $3 floor!)
    # 2. Large Lambda group (100 GB) created 100 days ago -> retention None -> flagged with 14d target
    # 3. Orphaned Lambda group for deleted function 'old-cron'
    mock_logs_paginator = MagicMock()
    mock_logs_paginator.paginate.return_value = [
        {
            "logGroups": [
                {
                    "logGroupName": "/app/tiny",
                    "retentionInDays": None,
                    "storedBytes": 2 * 1024 * 1024,  # 2MB
                    "creationTime": 1750000000000,
                },
                {
                    "logGroupName": "/aws/lambda/active-api",
                    "retentionInDays": None,
                    "storedBytes": 100 * 1024 * 1024 * 1024,  # 100 GB
                    "creationTime": (datetime.now(timezone.utc).timestamp() - (100 * 86400)) * 1000,
                },
                {
                    "logGroupName": "/aws/lambda/old-cron",
                    "retentionInDays": 30,
                    "storedBytes": 20 * 1024 * 1024 * 1024,  # 20 GB
                    "creationTime": 1750000000000,
                },
            ]
        }
    ]
    mock_logs.get_paginator.return_value = mock_logs_paginator
    mock_logs.describe_metric_filters.return_value = {"metricFilters": []}
    mock_logs.describe_subscription_filters.return_value = {"subscriptionFilters": []}

    # CloudWatch IncomingBytes mock
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [{"MetricDataResults": []}]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    # Lambda list_functions mock (only active-api is active, old-cron is deleted!)
    mock_lambda_paginator = MagicMock()
    mock_lambda_paginator.paginate.return_value = [
        {"Functions": [{"FunctionName": "active-api"}]}
    ]
    mock_lambda.get_paginator.return_value = mock_lambda_paginator

    findings = scanner.scan(mock_session, "us-east-1")

    # Group /app/tiny should be skipped (< $0.50 saving)
    assert not any(f.resource_id == "/app/tiny" for f in findings)

    # /aws/lambda/active-api should have never-expire finding with 14 days target
    active_finding = next(f for f in findings if f.resource_id == "/aws/lambda/active-api")
    assert "Never Expire" in active_finding.issue
    assert "14 days" in active_finding.recommendation
    # 100 GB * 0.03 * (1 - 14/100) = 3.00 * 0.86 = ~$2.58/mo (realistic delta, not flat $3)
    assert 2.0 <= active_finding.estimated_monthly_saving <= 3.0

    # /aws/lambda/old-cron should be flagged as orphaned
    orphaned_finding = next(f for f in findings if f.resource_id == "/aws/lambda/old-cron")
    assert "orphaned" in orphaned_finding.issue.lower()
    assert orphaned_finding.confidence == "High"


def test_elb_scanner_clb_and_v2():
    scanner = ELBScanner()
    mock_session = MagicMock()
    mock_elb_v1 = MagicMock()
    mock_elbv2 = MagicMock()
    mock_cw = MagicMock()
    mock_pricing = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_elb_v1
        if svc == "elb"
        else (
            mock_elbv2
            if svc == "elbv2"
            else (mock_cw if svc == "cloudwatch" else mock_pricing)
        )
    )

    # Mock Pricing API returning fallback/mock
    mock_pricing.get_products.return_value = {"PriceList": []}

    # 1. Classic LB 1: 0 instances -> HIGH severity
    # 2. Classic LB 2: registered instances active -> LOW severity ($1.83 saving)
    created_old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_clb_paginator = MagicMock()
    mock_clb_paginator.paginate.return_value = [
        {
            "LoadBalancerDescriptions": [
                {
                    "LoadBalancerName": "clb-empty",
                    "Instances": [],
                    "CreatedTime": created_old,
                    "Scheme": "internet-facing",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                },
                {
                    "LoadBalancerName": "clb-active",
                    "Instances": [{"InstanceId": "i-123"}],
                    "CreatedTime": created_old,
                    "Scheme": "internal",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                },
            ]
        }
    ]
    mock_elb_v1.get_paginator.return_value = mock_clb_paginator
    mock_elb_v1.describe_tags.return_value = {"TagDescriptions": []}
    mock_elb_v1.describe_instance_health.return_value = {
        "InstanceStates": [{"State": "InService"}]
    }

    # v2 Load Balancers:
    # 1. alb-redirect: 0 target groups, but ACTIVE traffic (e.g. 5000 requests) -> Should NOT be flagged!
    # 2. alb-outage: target group with all UNHEALTHY targets -> Should be MEDIUM alert, saving = 0.0
    # 3. alb-idle: healthy target, but 0 traffic in 30 days -> HIGH severity
    # 4. alb-k8s: managed by k8s controller, 0 targets -> HIGH severity with k8s recommendation
    alb_arn_redirect = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-redirect/111"
    alb_arn_outage = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-outage/222"
    alb_arn_idle = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-idle/333"
    alb_arn_k8s = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-k8s/444"

    mock_v2_paginator = MagicMock()
    mock_v2_paginator.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": alb_arn_redirect,
                    "LoadBalancerName": "alb-redirect",
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "CreatedTime": created_old,
                    "VpcId": "vpc-1",
                },
                {
                    "LoadBalancerArn": alb_arn_outage,
                    "LoadBalancerName": "alb-outage",
                    "Type": "application",
                    "Scheme": "internal",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "CreatedTime": created_old,
                    "VpcId": "vpc-1",
                },
                {
                    "LoadBalancerArn": alb_arn_idle,
                    "LoadBalancerName": "alb-idle",
                    "Type": "application",
                    "Scheme": "internal",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "CreatedTime": created_old,
                    "VpcId": "vpc-1",
                },
                {
                    "LoadBalancerArn": alb_arn_k8s,
                    "LoadBalancerName": "alb-k8s",
                    "Type": "application",
                    "Scheme": "internal",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "CreatedTime": created_old,
                    "VpcId": "vpc-1",
                },
            ]
        }
    ]

    tg_arn_outage = "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-outage/aaa"
    tg_arn_idle = "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-idle/bbb"
    tg_arn_k8s = "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-k8s/ccc"

    mock_tg_paginator = MagicMock()
    mock_tg_paginator.paginate.return_value = [
        {
            "TargetGroups": [
                {"TargetGroupArn": tg_arn_outage, "TargetGroupName": "tg-outage", "LoadBalancerArns": [alb_arn_outage]},
                {"TargetGroupArn": tg_arn_idle, "TargetGroupName": "tg-idle", "LoadBalancerArns": [alb_arn_idle]},
                {"TargetGroupArn": tg_arn_k8s, "TargetGroupName": "tg-k8s", "LoadBalancerArns": [alb_arn_k8s]},
            ]
        }
    ]

    mock_elbv2.get_paginator.side_effect = lambda op: mock_v2_paginator if op == "describe_load_balancers" else mock_tg_paginator

    # Mock listeners (all have listeners)
    mock_elbv2.describe_listeners.return_value = {"Listeners": [{"ListenerArn": "l-1"}]}
    mock_elbv2.describe_load_balancer_attributes.return_value = {"Attributes": []}

    # Mock tags
    mock_elbv2.describe_tags.return_value = {
        "TagDescriptions": [
            {
                "ResourceArn": alb_arn_k8s,
                "Tags": [{"Key": "elbv2.k8s.aws/cluster", "Value": "prod-cluster"}],
            }
        ]
    }

    # Mock target health:
    # tg-outage -> unhealthy
    # tg-idle -> healthy
    # tg-k8s -> empty targets []
    def mock_target_health(TargetGroupArn):
        if TargetGroupArn == tg_arn_outage:
            return {"TargetHealthDescriptions": [{"TargetHealth": {"State": "unhealthy"}}]}
        elif TargetGroupArn == tg_arn_idle:
            return {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]}
        return {"TargetHealthDescriptions": []}

    mock_elbv2.describe_target_health.side_effect = mock_target_health

    # Mock CloudWatch traffic:
    # clb-active has traffic
    # alb-redirect has traffic (5000 requests)
    # alb-idle has 0 traffic
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "q_clb_0", "Values": [0.0]},
                {"Id": "q_clb_1", "Values": [1000000.0]},
                {"Id": "q_0", "Values": [5000.0]},  # alb-redirect
                {"Id": "q_1", "Values": [100.0]},   # alb-outage
                {"Id": "q_2", "Values": [0.0]},     # alb-idle
                {"Id": "q_3", "Values": [0.0]},     # alb-k8s
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    findings = scanner.scan(mock_session, "us-east-1")

    # 1. clb-empty -> HIGH severity, full saving
    f_clb_empty = next(f for f in findings if f.resource_id == "clb-empty")
    assert f_clb_empty.severity == Severity.HIGH
    assert f_clb_empty.estimated_monthly_saving > 18.0

    # 2. clb-active -> LOW severity, ~$1.83 saving
    f_clb_active = next(f for f in findings if f.resource_id == "clb-active")
    assert f_clb_active.severity == Severity.LOW
    assert 1.0 <= f_clb_active.estimated_monthly_saving <= 2.5

    # 3. alb-redirect: Active traffic -> should NOT be flagged as empty/idle!
    assert not any(f.resource_id == alb_arn_redirect for f in findings)

    # 4. alb-outage: All targets unhealthy -> MEDIUM alert, $0 saving, warning NOT to delete
    f_alb_outage = next(f for f in findings if f.resource_id == alb_arn_outage)
    assert f_alb_outage.severity == Severity.MEDIUM
    assert f_alb_outage.estimated_monthly_saving == 0.0
    assert "DO NOT delete" in f_alb_outage.recommendation

    # 5. alb-idle: Healthy targets, 0 requests -> HIGH severity idle
    f_alb_idle = next(f for f in findings if f.resource_id == alb_arn_idle)
    assert f_alb_idle.severity == Severity.HIGH
    assert f_alb_idle.estimated_monthly_saving > 15.0

    # 6. alb-k8s: Managed by k8s -> recommendation points to Kubernetes
    f_alb_k8s = next(f for f in findings if f.resource_id == alb_arn_k8s)
    assert f_alb_k8s.severity == Severity.HIGH
    assert "Kubernetes" in f_alb_k8s.recommendation


def test_kms_scanner_skip_aws_managed_and_evidence_of_use():
    scanner = KMSScanner()
    mock_session = MagicMock()
    mock_kms = MagicMock()
    mock_ct = MagicMock()
    mock_ce = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_kms
        if svc == "kms"
        else (mock_ct if svc == "cloudtrail" else mock_ce)
    )

    # 1. Alias map:
    # key-aws-managed has alias/aws/s3 -> should be skipped before describe_key
    # key-pending-del has alias/app/pending
    # key-disabled has alias/app/disabled
    # key-with-grants has alias/app/ebs-key
    # key-with-crypto has alias/app/s3-key
    # key-idle has alias/app/old-unused
    alias_paginator = MagicMock()
    alias_paginator.paginate.return_value = [
        {
            "Aliases": [
                {"TargetKeyId": "key-aws-managed", "AliasName": "alias/aws/s3"},
                {"TargetKeyId": "key-pending-del", "AliasName": "alias/app/pending"},
                {"TargetKeyId": "key-disabled", "AliasName": "alias/app/disabled"},
                {"TargetKeyId": "key-with-grants", "AliasName": "alias/app/ebs-key"},
                {"TargetKeyId": "key-with-crypto", "AliasName": "alias/app/s3-key"},
                {"TargetKeyId": "key-idle", "AliasName": "alias/app/old-unused"},
            ]
        }
    ]

    keys_paginator = MagicMock()
    keys_paginator.paginate.return_value = [
        {
            "Keys": [
                {"KeyId": "key-aws-managed", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-aws-managed"},
                {"KeyId": "key-pending-del", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-pending-del"},
                {"KeyId": "key-disabled", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-disabled"},
                {"KeyId": "key-with-grants", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-with-grants"},
                {"KeyId": "key-with-crypto", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-with-crypto"},
                {"KeyId": "key-idle", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-idle"},
                {"KeyId": "key-denied", "KeyArn": "arn:aws:kms:us-east-1:123:key/key-denied"},
            ]
        }
    ]

    mock_kms.get_paginator.side_effect = lambda op: alias_paginator if op == "list_aliases" else keys_paginator

    # Mock describe_key responses
    from botocore.exceptions import ClientError
    def mock_describe_key(KeyId):
        if KeyId == "key-denied":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}, "DescribeKey")
        if KeyId == "key-aws-managed":
            raise AssertionError("AWS-managed keys should be skipped BEFORE describe_key!")
        
        state_map = {
            "key-pending-del": ("PendingDeletion", False),
            "key-disabled": ("Disabled", False),
            "key-with-grants": ("Enabled", False),
            "key-with-crypto": ("Enabled", False),
            "key-idle": ("Enabled", False),
        }
        state, is_replica = state_map.get(KeyId, ("Enabled", False))
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "KeyManager": "CUSTOMER",
                "KeyState": state,
                "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc),
                "Description": f"Test {KeyId}",
                "MultiRegion": is_replica,
            }
        }

    mock_kms.describe_key.side_effect = mock_describe_key

    # Mock list_grants: key-with-grants has an active grant; others do not
    grant_paginator = MagicMock()
    def mock_grant_paginate(KeyId=None, **kw):
        if KeyId == "key-with-grants":
            return [{"Grants": [{"GrantId": "g-1"}]}]
        return [{"Grants": []}]

    grant_paginator.paginate.side_effect = mock_grant_paginate

    mock_kms.get_paginator.side_effect = lambda op: (
        alias_paginator if op == "list_aliases"
        else (keys_paginator if op == "list_keys" else grant_paginator)
    )

    # Mock CloudTrail lookup_events:
    # key-with-crypto has Decrypt event -> active!
    # key-idle has 0 crypto events -> idle!
    ct_paginator = MagicMock()
    def mock_ct_paginate(LookupAttributes=None, **kw):
        res_val = LookupAttributes[0]["AttributeValue"] if LookupAttributes else ""
        if "key-with-crypto" in res_val:
            return [{"Events": [{"EventName": "Decrypt"}]}]
        return [{"Events": []}]

    ct_paginator.paginate.side_effect = mock_ct_paginate
    mock_ct.get_paginator.return_value = ct_paginator

    # Cost Explorer: requests do not dominate key fees in this test
    mock_ce.get_cost_and_usage.return_value = {
        "ResultsByTime": [{"Groups": [{"Keys": ["USE1-KMS-Keys"], "Metrics": {"UnblendedCost": {"Amount": "5.00"}}}]}]
    }

    findings = scanner.scan(mock_session, "us-east-1")

    # Verification:
    # 1. key-pending-del: ZERO savings claimed (AWS does not bill pending deletion keys)
    f_pending = next((f for f in findings if "Pending Deletion" in f.issue), None)
    assert f_pending is not None
    assert f_pending.estimated_monthly_saving == 0.0

    # 2. key-disabled: Flagged with $1.00 saving
    f_disabled = next((f for f in findings if "disabled Customer Managed" in f.issue), None)
    assert f_disabled is not None
    assert f_disabled.estimated_monthly_saving == 1.00
    assert "WARNING" in f_disabled.recommendation

    # 3. key-with-grants: NOT in idle finding (evidence of use via grants)
    # 4. key-with-crypto: NOT in idle finding (evidence of use via CloudTrail)
    # 5. key-idle: Included in inactive keys finding with safe recommendation
    f_idle = next((f for f in findings if "0 active grants and 0 cryptographic operations" in f.issue), None)
    assert f_idle is not None
    assert f_idle.estimated_monthly_saving == 1.00
    idle_key_ids = [k["key_id"] for k in f_idle.metadata["keys"]]
    assert "key-idle" in idle_key_ids
    assert "key-with-grants" not in idle_key_ids
    assert "key-with-crypto" not in idle_key_ids
    assert "Disable the key first" in f_idle.recommendation

    # 6. key-denied: Tracked in unauditable summary finding
    f_denied = next((f for f in findings if "could not be described due to IAM permissions" in f.issue), None)
    assert f_denied is not None
    assert "key-denied" in f_denied.metadata["unaudited_key_ids"]


def test_s3_bucket_keys_detection():
    scanner = S3Scanner()
    mock_session = MagicMock()
    mock_s3 = MagicMock()
    mock_session.client.return_value = mock_s3

    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "kms-unoptimized-bucket"}]}
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    mock_s3.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [{"Status": "Enabled", "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]
    }
    mock_s3.get_bucket_versioning.return_value = {"Status": "Suspended"}

    # Mock SSE-KMS without BucketKeyEnabled
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                    },
                    "BucketKeyEnabled": False,
                }
            ]
        }
    }

    findings = scanner.scan(mock_session, "us-east-1")
    f_bkey = next((f for f in findings if "S3 Bucket Keys" in f.issue), None)
    assert f_bkey is not None
    assert f_bkey.severity == Severity.MEDIUM
    assert "99%" in f_bkey.recommendation


def test_lambda_scanner_real_savings_and_provisioned_concurrency():
    scanner = LambdaScanner()
    mock_session = MagicMock()
    mock_lam = MagicMock()
    mock_cw = MagicMock()
    mock_tagging = MagicMock()
    mock_co = MagicMock()
    mock_logs = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_lam if svc == "lambda"
        else (mock_cw if svc == "cloudwatch"
              else (mock_tagging if svc == "resourcegroupstaggingapi"
                    else (mock_co if svc == "compute-optimizer" else mock_logs)))
    )

    # 1. Functions:
    # fn-active: x86_64, 512 MB, active traffic, Compute Optimizer memory overprovisioned -> merged finding
    # fn-idle-old: 0 invocations, modified 120 days ago, has 10 GB log group -> real log saving (~$0.30), no $1 compute
    # fn-idle-recent: 0 invocations, modified 5 days ago (newly deployed) -> skipped (grace period)!
    # fn-prov-idle: has provisioned concurrency with 1% utilization -> HIGH severity finding ($10.95/GB/mo)
    fn_active = {
        "FunctionName": "fn-active",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-active",
        "Runtime": "python3.11",
        "MemorySize": 512,
        "Timeout": 30,
        "Architectures": ["x86_64"],
        "PackageType": "Zip",
        "LastModified": "2026-01-01T00:00:00.000+0000",
    }
    fn_idle_old = {
        "FunctionName": "fn-idle-old",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-idle-old",
        "Runtime": "python3.11",
        "MemorySize": 128,
        "Timeout": 10,
        "Architectures": ["arm64"],
        "PackageType": "Zip",
        "LastModified": "2025-01-01T00:00:00.000+0000",
    }
    fn_idle_recent = {
        "FunctionName": "fn-idle-recent",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-idle-recent",
        "Runtime": "nodejs18.x",
        "MemorySize": 256,
        "Timeout": 10,
        "Architectures": ["x86_64"],
        "PackageType": "Zip",
        "LastModified": datetime.now(timezone.utc).isoformat(),
    }
    fn_prov_idle = {
        "FunctionName": "fn-prov-idle",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-prov-idle",
        "Runtime": "python3.11",
        "MemorySize": 1024,
        "Timeout": 30,
        "Architectures": ["arm64"],
        "PackageType": "Zip",
        "LastModified": "2026-01-01T00:00:00.000+0000",
    }

    fn_paginator = MagicMock()
    fn_paginator.paginate.return_value = [
        {"Functions": [fn_active, fn_idle_old, fn_idle_recent, fn_prov_idle]}
    ]
    mock_lam.get_paginator.return_value = fn_paginator
    mock_lam.get_policy.return_value = {}

    # Provisioned concurrency config for fn-prov-idle
    def mock_list_prov(FunctionName):
        if FunctionName == "fn-prov-idle":
            return {
                "ProvisionedConcurrencyConfigs": [
                    {
                        "AllocatedProvisionedConcurrentExecutions": 5,
                        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-prov-idle:live",
                    }
                ]
            }
        return {"ProvisionedConcurrencyConfigs": []}

    mock_lam.list_provisioned_concurrency_configs.side_effect = mock_list_prov

    # CloudWatch get_metric_statistics for ProvisionedConcurrencyUtilization (1% utilization)
    mock_cw.get_metric_statistics.return_value = {"Datapoints": [{"Average": 0.01}]}

    # Tagging API mock: fn-active is managed by CloudFormation
    tag_paginator = MagicMock()
    tag_paginator.paginate.return_value = [
        {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:lambda:us-east-1:123:function:fn-active",
                    "Tags": [{"Key": "aws:cloudformation:stack-name", "Value": "prod-api-stack"}],
                }
            ]
        }
    ]
    mock_tagging.get_paginator.return_value = tag_paginator

    # CloudWatch batched get_metric_data mock:
    # fn-active: 100,000 invocations, 2,000,000,000 ms duration
    # fn-prov-idle: 10,000 invocations, 5,000,000 ms duration
    cw_paginator = MagicMock()
    cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "inv_0", "Values": [100000.0]},
                {"Id": "dur_0", "Values": [2000000000.0]},
                {"Id": "err_0", "Values": [0.0]},
                {"Id": "inv_1", "Values": [0.0]},
                {"Id": "dur_1", "Values": [0.0]},
                {"Id": "err_1", "Values": [0.0]},
                {"Id": "inv_2", "Values": [0.0]},
                {"Id": "dur_2", "Values": [0.0]},
                {"Id": "err_2", "Values": [0.0]},
                {"Id": "inv_3", "Values": [10000.0]},
                {"Id": "dur_3", "Values": [5000000.0]},
                {"Id": "err_3", "Values": [0.0]},
            ]
        }
    ]
    mock_cw.get_paginator.return_value = cw_paginator

    # Compute Optimizer recommendations: fn-active memory overprovisioned (saves $4.50/mo)
    co_paginator = MagicMock()
    co_paginator.paginate.return_value = [
        {
            "lambdaFunctionRecommendations": [
                {
                    "functionArn": "arn:aws:lambda:us-east-1:123:function:fn-active",
                    "findingReasonCodes": ["MemoryOverprovisioned"],
                    "memorySizeRecommendationOptions": [
                        {
                            "memorySize": 256,
                            "savingsOpportunity": {
                                "estimatedMonthlySavings": {"value": 4.50}
                            },
                        }
                    ],
                }
            ]
        }
    ]
    mock_co.get_paginator.return_value = co_paginator

    # CloudWatch Logs stored bytes: fn-idle-old has 10 GB logs
    logs_paginator = MagicMock()
    logs_paginator.paginate.return_value = [
        {
            "logGroups": [
                {
                    "logGroupName": "/aws/lambda/fn-idle-old",
                    "storedBytes": 10 * 1024 * 1024 * 1024,  # 10 GB = $0.30/mo
                }
            ]
        }
    ]
    mock_logs.get_paginator.return_value = logs_paginator

    findings = scanner.scan(mock_session, "us-east-1")

    # 1. fn-active: Should produce merged finding combining Compute Optimizer memory rightsizing + Graviton arm64
    f_active = next(f for f in findings if f.resource_name == "fn-active")
    assert f_active is not None
    assert f_active.estimated_monthly_saving > 4.50
    assert "CloudFormation" in f_active.recommendation
    assert "Rightsize memory" in f_active.recommendation
    assert "arm64" in f_active.recommendation

    # 2. fn-idle-recent: Recently modified (5 days ago) with 0 invocations -> MUST NOT BE FLAGGED!
    assert not any(f.resource_name == "fn-idle-recent" for f in findings)

    # 3. fn-idle-old: Old inactive function -> flagged for log storage (~$0.30), NOT fake $1 compute!
    f_idle_old = next(f for f in findings if f.resource_name == "fn-idle-old")
    assert f_idle_old is not None
    assert 0.25 <= f_idle_old.estimated_monthly_saving <= 0.35
    assert "Inactive Lambda function" in f_idle_old.issue

    # 4. fn-prov-idle: Idle provisioned concurrency (5 units * 1GB * $10.95 = $54.75/mo)
    f_prov = next(f for f in findings if "Provisioned Concurrency" in f.issue)
    assert f_prov is not None
    assert f_prov.severity == Severity.HIGH
    assert f_prov.estimated_monthly_saving > 50.0


def test_rds_scanner_exact_tokens_and_real_savings():
    scanner = RDSScanner()
    mock_session = MagicMock()
    mock_rds = MagicMock()
    mock_cw = MagicMock()
    mock_ce = MagicMock()
    mock_pricing = MagicMock()

    mock_session.client.side_effect = lambda svc, **kw: (
        mock_rds if svc == "rds"
        else (mock_cw if svc == "cloudwatch"
              else (mock_ce if svc == "ce" else mock_pricing))
    )

    mock_pricing.get_products.return_value = {"PriceList": []}

    # DBs:
    # 1. db-prod-false-positive: Tag env="devops-prod" -> NOT non-prod! Multi-AZ should NOT be flagged as non-prod!
    # 2. db-qa-multi-az: Tag env="qa" -> exact non-prod match! Multi-AZ flagged with real price + storage mirroring.
    # 3. db-idle: status="available", 0 connections over 30 days, age 100 days -> HIGH severity idle finding with 7-day warning.
    # 4. db-stopped: status="stopped" -> MEDIUM severity with 7-day auto-restart warning.
    # 5. db-ext-support: MySQL 5.7 -> Extended Support surcharge flagged!
    created_old = datetime(2025, 1, 1, tzinfo=timezone.utc)

    db_prod = {
        "DBInstanceIdentifier": "db-prod-false-positive",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-prod-false-positive",
        "DBInstanceClass": "db.m5.large",
        "Engine": "mysql",
        "EngineVersion": "8.0.35",
        "MultiAZ": True,
        "DBInstanceStatus": "available",
        "AllocatedStorage": 100,
        "StorageType": "gp3",
        "InstanceCreateTime": created_old,
        "TagList": [{"Key": "env", "Value": "devops-prod"}],
    }

    db_qa = {
        "DBInstanceIdentifier": "db-qa-multi-az",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-qa-multi-az",
        "DBInstanceClass": "db.t3.medium",
        "Engine": "mysql",
        "EngineVersion": "8.0.35",
        "MultiAZ": True,
        "DBInstanceStatus": "available",
        "AllocatedStorage": 100,
        "StorageType": "gp2",
        "InstanceCreateTime": created_old,
        "TagList": [{"Key": "environment", "Value": "qa"}],
    }

    db_idle = {
        "DBInstanceIdentifier": "db-idle",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-idle",
        "DBInstanceClass": "db.t3.micro",
        "Engine": "postgres",
        "EngineVersion": "15.4",
        "MultiAZ": False,
        "DBInstanceStatus": "available",
        "AllocatedStorage": 20,
        "StorageType": "gp3",
        "InstanceCreateTime": created_old,
        "TagList": [{"Key": "env", "Value": "dev"}],
    }

    db_stopped = {
        "DBInstanceIdentifier": "db-stopped",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-stopped",
        "DBInstanceClass": "db.m5.large",
        "Engine": "postgres",
        "EngineVersion": "15.4",
        "MultiAZ": False,
        "DBInstanceStatus": "stopped",
        "AllocatedStorage": 200,
        "StorageType": "gp3",
        "InstanceCreateTime": created_old,
        "TagList": [{"Key": "env", "Value": "test"}],
    }

    db_ext = {
        "DBInstanceIdentifier": "db-ext-support",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-ext-support",
        "DBInstanceClass": "db.t3.medium",
        "Engine": "mysql",
        "EngineVersion": "5.7.44",
        "MultiAZ": False,
        "DBInstanceStatus": "available",
        "AllocatedStorage": 50,
        "StorageType": "gp3",
        "InstanceCreateTime": created_old,
        "TagList": [{"Key": "env", "Value": "prod"}],
    }

    db_paginator = MagicMock()
    db_paginator.paginate.return_value = [
        {"DBInstances": [db_prod, db_qa, db_idle, db_stopped, db_ext]}
    ]
    mock_rds.get_paginator.return_value = db_paginator

    # Blue/green deployments mock
    mock_rds.describe_blue_green_deployments.return_value = {"BlueGreenDeployments": []}

    # CloudWatch batched metrics mock
    cw_paginator = MagicMock()
    cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "conn_0", "Values": [25.0]},  # db_prod
                {"Id": "cpu_avg_0", "Values": [15.0]},
                {"Id": "cpu_max_0", "Values": [40.0]},
                {"Id": "conn_1", "Values": [10.0]},  # db_qa
                {"Id": "cpu_avg_1", "Values": [5.0]},
                {"Id": "cpu_max_1", "Values": [15.0]},
                {"Id": "conn_2", "Values": [0.0] * 14},  # db_idle: 0 connections over 14 days
                {"Id": "cpu_avg_2", "Values": [0.5] * 14},
                {"Id": "cpu_max_2", "Values": [1.0] * 14},
                {"Id": "conn_3", "Values": []},      # db_stopped
                {"Id": "cpu_avg_3", "Values": []},
                {"Id": "cpu_max_3", "Values": []},
                {"Id": "conn_4", "Values": [5.0]},   # db_ext
                {"Id": "cpu_avg_4", "Values": [10.0]},
                {"Id": "cpu_max_4", "Values": [20.0]},
            ]
        }
    ]
    mock_cw.get_paginator.return_value = cw_paginator

    # Cost Explorer mock: $0 billed backup usage (honest backup savings = 0)
    mock_ce.get_cost_and_usage.return_value = {"ResultsByTime": []}

    # Snapshots mock: 1 orphaned snapshot
    snap_paginator = MagicMock()
    snap_paginator.paginate.return_value = [
        {
            "DBSnapshots": [
                {
                    "DBSnapshotIdentifier": "rds:old-orphan-snap",
                    "DBInstanceIdentifier": "deleted-db-from-2024",
                    "SnapshotCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "TagList": [],
                }
            ]
        }
    ]

    cluster_snap_paginator = MagicMock()
    cluster_snap_paginator.paginate.return_value = [{"DBClusterSnapshots": []}]

    cluster_paginator = MagicMock()
    cluster_paginator.paginate.return_value = [{"DBClusters": []}]

    mock_rds.get_paginator.side_effect = lambda op: (
        db_paginator if op == "describe_db_instances"
        else (snap_paginator if op == "describe_db_snapshots"
              else (cluster_snap_paginator if op == "describe_db_cluster_snapshots"
                    else cluster_paginator))
    )

    findings = scanner.scan(mock_session, "us-east-1")

    # 1. db-prod-false-positive: Tag env="devops-prod" MUST NOT be flagged for Multi-AZ non-prod!
    assert not any(f.resource_name == "db-prod-false-positive" and "Multi-AZ" in f.recommendation for f in findings)

    # 2. db-qa-multi-az: Tag env="qa" IS non-prod -> MUST be flagged with Single-AZ conversion + gp3 migration
    f_qa = next(f for f in findings if f.resource_name == "db-qa-multi-az")
    assert f_qa is not None
    assert "Single-AZ" in f_qa.recommendation
    assert "gp3" in f_qa.recommendation

    # 3. db-idle: 0 connections over lookback window -> HIGH severity idle finding with 7-day auto-restart warning
    f_idle = next(f for f in findings if f.resource_name == "db-idle")
    assert f_idle is not None
    assert f_idle.severity == Severity.HIGH
    assert "restarts" in f_idle.recommendation

    # 4. db-stopped: Stopped instance -> MEDIUM severity storage savings and 7-day auto-restart warning
    f_stopped = next(f for f in findings if f.resource_name == "db-stopped")
    assert f_stopped is not None
    assert f_stopped.severity == Severity.MEDIUM
    assert "restarts" in f_stopped.issue

    # 5. db-ext-support: MySQL 5.7 -> Extended Support surcharge flagged!
    f_ext = next(f for f in findings if f.resource_name == "db-ext-support")
    assert f_ext is not None
    assert "Extended Support" in f_ext.recommendation

    # 6. Honest Snapshot finding: Account has $0 billed backup usage -> savings is $0.00
    f_snap = next(f for f in findings if "Old Manual Snapshots" in f.resource_name)
    assert f_snap is not None
    assert f_snap.estimated_monthly_saving == 0.0
    assert "orphaned" in f_snap.issue


def test_console_reporter_cards_and_table():
    findings = [
        Finding(
            service="Amazon S3",
            resource_id="cost-audit-test-bucket",
            region="us-east-1",
            severity=Severity.MEDIUM,
            issue="No S3 Lifecycle policy configured",
            recommendation="Configure lifecycle rules to transition older objects to Glacier / expire temp data",
            estimated_monthly_saving=15.0,
        ),
        Finding(
            service="Amazon EBS",
            resource_id="vol-43d58add743f51d9",
            region="us-east-1",
            severity=Severity.LOW,
            issue="Unattached (orphaned) gp2 volume (20 GB)",
            recommendation="Create a final backup snapshot if needed and delete unattached volume to stop charges",
            estimated_monthly_saving=2.0,
        ),
    ]

    # Test Cards View
    print_console_report(findings, mode="cards")

    # Test Table View
    print_console_report(findings, mode="table")

    # Test Empty Findings
    print_console_report([], mode="cards")


def test_export_reports():
    findings = [
        Finding(
            service="Amazon EC2",
            resource_id="i-test",
            region="us-east-1",
            severity=Severity.HIGH,
            issue="Test issue",
            recommendation="Test rec",
            estimated_monthly_saving=25.0,
        )
    ]
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf_csv:
        csv_path = tf_csv.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_json:
        json_path = tf_json.name

    try:
        export_to_csv(findings, csv_path)
        assert os.path.exists(csv_path)
        with open(csv_path) as f:
            assert "i-test" in f.read()

        export_to_json(findings, json_path)
        assert os.path.exists(json_path)
        with open(json_path) as f:
            assert "i-test" in f.read()
    finally:
        for p in (csv_path, json_path):
            if os.path.exists(p):
                os.remove(p)


def test_vpc_scanner_elastic_ips():
    session = MagicMock()
    mock_ec2 = MagicMock()
    mock_cw = MagicMock()

    scanner = VPCScanner()
    scanner.get_client = lambda s, service, r: mock_ec2 if service == "ec2" else mock_cw

    # 1 unassociated EIP, 1 EIP on stopped instance, 1 EIP on running instance, 1 BYOIP
    mock_ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-unassociated",
                "PublicIp": "54.210.1.1",
                "PublicIpv4Pool": "amazon",
            },
            {
                "AllocationId": "eipalloc-stopped",
                "PublicIp": "54.210.1.2",
                "InstanceId": "i-stopped-123",
                "AssociationId": "eipassoc-1",
                "PublicIpv4Pool": "amazon",
            },
            {
                "AllocationId": "eipalloc-running",
                "PublicIp": "54.210.1.3",
                "InstanceId": "i-running-123",
                "AssociationId": "eipassoc-2",
                "PublicIpv4Pool": "amazon",
            },
            {
                "AllocationId": "eipalloc-byoip",
                "PublicIp": "198.51.100.1",
                "PublicIpv4Pool": "ipv4pool-ec2-custom",
            },
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {"InstanceId": "i-stopped-123", "State": {"Name": "stopped"}},
                    {"InstanceId": "i-running-123", "State": {"Name": "running"}},
                ]
            }
        ]
    }

    # Empty responses for remaining VPC sections
    mock_ec2.describe_nat_gateways.return_value = {"NatGateways": []}
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    mock_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}
    mock_ec2.describe_vpn_connections.return_value = {"VpnConnections": []}

    findings = scanner.scan(session, "us-east-1")
    assert len(findings) == 2

    # Unassociated EIP
    f_unassoc = next(f for f in findings if f.resource_id == "eipalloc-unassociated")
    assert f_unassoc.severity == Severity.HIGH
    assert f_unassoc.estimated_monthly_saving == 3.65

    # Stopped instance EIP
    f_stopped = next(f for f in findings if f.resource_id == "eipalloc-stopped")
    assert f_stopped.severity == Severity.MEDIUM
    assert "stopped EC2 instance" in f_stopped.issue
    assert f_stopped.estimated_monthly_saving == 3.65


def test_vpc_scanner_nat_gateways():
    session = MagicMock()
    mock_ec2 = MagicMock()
    mock_cw = MagicMock()

    scanner = VPCScanner()
    scanner.get_client = lambda s, service, r: mock_ec2 if service == "ec2" else mock_cw

    old_time = datetime(2025, 1, 1, tzinfo=timezone.utc)
    new_time = datetime.now(timezone.utc)  # Age guard should skip this

    mock_ec2.describe_addresses.return_value = {"Addresses": []}
    mock_ec2.describe_nat_gateways.return_value = {
        "NatGateways": [
            {
                "NatGatewayId": "nat-orphan-01",
                "VpcId": "vpc-prod-01",
                "State": "available",
                "CreateTime": old_time,
                "NatGatewayAddresses": [{"AllocationId": "eipalloc-nat1"}],
            },
            {
                "NatGatewayId": "nat-idle-02",
                "VpcId": "vpc-prod-01",
                "State": "available",
                "CreateTime": old_time,
                "NatGatewayAddresses": [{"AllocationId": "eipalloc-nat2"}],
            },
            {
                "NatGatewayId": "nat-recent-03",
                "VpcId": "vpc-prod-01",
                "State": "available",
                "CreateTime": new_time,
            },
        ]
    }

    # Route tables: only nat-idle-02 is in a route table. nat-orphan-01 is in zero route tables!
    mock_rtb_paginator = MagicMock()
    mock_rtb_paginator.paginate.return_value = [
        {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-private-1",
                    "VpcId": "vpc-prod-01",
                    "Routes": [{"NatGatewayId": "nat-idle-02"}],
                }
            ]
        }
    ]
    mock_ec2.get_paginator.side_effect = lambda name: mock_rtb_paginator if name == "describe_route_tables" else mock_cw_paginator

    mock_ec2.describe_vpcs.return_value = {
        "Vpcs": [{"VpcId": "vpc-prod-01", "Tags": [{"Key": "Environment", "Value": "production"}]}]
    }

    # CloudWatch metrics for nat-idle-02: return low traffic
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "m_out_0", "Values": [1024 * 1024]},  # 1 MB
                {"Id": "m_in_0", "Values": [2 * 1024 * 1024]},  # 2 MB (Total 3 MB < 10 MB threshold)
                {"Id": "m_conn_0", "Values": [0.0]},
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}
    mock_ec2.describe_vpc_endpoints.return_value = {
        "VpcEndpoints": [
            {"VpcEndpointType": "Gateway", "ServiceName": "com.amazonaws.us-east-1.s3"},
            {"VpcEndpointType": "Gateway", "ServiceName": "com.amazonaws.us-east-1.dynamodb"},
        ]
    }
    mock_ec2.describe_vpn_connections.return_value = {"VpnConnections": []}

    findings = scanner.scan(session, "us-east-1")

    # Should find Orphaned NAT and Idle NAT (recent NAT skipped by age guard)
    orphan = next((f for f in findings if f.resource_id == "nat-orphan-01"), None)
    assert orphan is not None
    assert "Orphaned NAT Gateway" in orphan.issue
    assert orphan.effort == "Low"
    assert orphan.estimated_monthly_saving == 36.50

    idle = next((f for f in findings if f.resource_id == "nat-idle-02"), None)
    assert idle is not None
    assert "Idle NAT Gateway" in idle.issue
    assert idle.effort == "Medium"
    assert idle.estimated_monthly_saving == 36.50


def test_vpc_scanner_missing_gateway_endpoints_and_enis():
    session = MagicMock()
    mock_ec2 = MagicMock()
    mock_cw = MagicMock()

    scanner = VPCScanner()
    scanner.get_client = lambda s, service, r: mock_ec2 if service == "ec2" else mock_cw

    mock_ec2.describe_addresses.return_value = {"Addresses": []}
    mock_ec2.describe_nat_gateways.return_value = {
        "NatGateways": [
            {
                "NatGatewayId": "nat-busy-01",
                "VpcId": "vpc-app-01",
                "State": "available",
                "CreateTime": datetime(2025, 1, 1, tzinfo=timezone.utc),
            }
        ]
    }

    mock_rtb_paginator = MagicMock()
    mock_rtb_paginator.paginate.return_value = [
        {"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-app-01", "Routes": [{"NatGatewayId": "nat-busy-01"}]}]}
    ]
    mock_ec2.get_paginator.return_value = mock_rtb_paginator
    mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-app-01", "Tags": []}]}

    # High traffic on NAT so it's not idle
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "m_out_0", "Values": [500 * 1024 * 1024]},  # 500 MB
                {"Id": "m_in_0", "Values": [500 * 1024 * 1024]},
                {"Id": "m_conn_0", "Values": [25.0]},
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    # VPC missing S3 and DynamoDB gateway endpoints
    mock_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}

    # ENIs: 1 available unattached ENI ($0 saving), 1 available with EIP ($3.65 saving), 1 requester-managed (skipped)
    mock_ec2.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-clean-01",
                "Description": "Custom interface",
                "InterfaceType": "interface",
                "RequesterManaged": False,
                "Status": "available",
                "SubnetId": "subnet-01",
            },
            {
                "NetworkInterfaceId": "eni-with-eip-02",
                "Description": "Interface with IP",
                "InterfaceType": "interface",
                "RequesterManaged": False,
                "Status": "available",
                "Association": {"PublicIp": "54.210.99.99", "AllocationId": "eipalloc-eni-99"},
            },
            {
                "NetworkInterfaceId": "eni-lambda-managed",
                "Description": "AWS Lambda VPC ENI-xyz",
                "InterfaceType": "lambda",
                "RequesterManaged": True,
                "Status": "available",
            },
        ]
    }
    mock_ec2.describe_vpn_connections.return_value = {"VpnConnections": []}

    findings = scanner.scan(session, "us-east-1")

    # Missing gateway endpoints finding
    f_gw = next((f for f in findings if "missing free Gateway VPC Endpoint" in f.issue), None)
    assert f_gw is not None
    assert f_gw.estimated_monthly_saving == 0.0

    # Clean unattached ENI ($0 honest saving)
    f_eni_clean = next((f for f in findings if f.resource_id == "eni-clean-01"), None)
    assert f_eni_clean is not None
    assert f_eni_clean.estimated_monthly_saving == 0.0
    assert f_eni_clean.severity == Severity.LOW

    # Available ENI holding an EIP ($3.65 saving)
    f_eni_eip = next((f for f in findings if f.resource_id == "eni-with-eip-02"), None)
    assert f_eni_eip is not None
    assert f_eni_eip.estimated_monthly_saving == 3.65
    assert f_eni_eip.severity == Severity.HIGH


def test_vpc_scanner_privatelink_and_vpn():
    session = MagicMock()
    mock_ec2 = MagicMock()
    mock_cw = MagicMock()

    scanner = VPCScanner()
    scanner.get_client = lambda s, service, r: mock_ec2 if service == "ec2" else mock_cw

    mock_ec2.describe_addresses.return_value = {"Addresses": []}
    mock_ec2.describe_nat_gateways.return_value = {"NatGateways": []}
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": []}

    # Interface endpoint across 2 AZs with 0 bytes processed
    old_time = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_ec2.describe_vpc_endpoints.return_value = {
        "VpcEndpoints": [
            {
                "VpcEndpointId": "vpce-privatelink-01",
                "VpcEndpointType": "Interface",
                "ServiceName": "com.amazonaws.us-east-1.ecr.api",
                "State": "available",
                "SubnetIds": ["subnet-az1", "subnet-az2"],
                "CreationTimestamp": old_time,
            }
        ]
    }

    # VPN connection with 0 bytes transferred
    mock_ec2.describe_vpn_connections.return_value = {
        "VpnConnections": [
            {
                "VpnConnectionId": "vpn-corp-dc-01",
                "State": "available",
                "CustomerGatewayId": "cgw-dc-01",
            }
        ]
    }

    # CloudWatch get_metric_statistics returns 0 datapoints (or sum = 0)
    mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

    findings = scanner.scan(session, "us-east-1")
    assert len(findings) == 2

    # Interface endpoint finding (2 AZs * $0.01 * 730 = $14.60/month)
    f_vpce = next(f for f in findings if f.resource_id == "vpce-privatelink-01")
    assert f_vpce.severity == Severity.MEDIUM
    assert f_vpce.estimated_monthly_saving == 14.60
    assert "2 AZ(s)" in f_vpce.issue

    # Idle VPN connection finding ($0.05 * 730 = $36.50/month)
    f_vpn = next(f for f in findings if f.resource_id == "vpn-corp-dc-01")
    assert f_vpn.severity == Severity.HIGH
    assert f_vpn.estimated_monthly_saving == 36.50
    assert "Idle Site-to-Site VPN" in f_vpn.issue


def test_s3_scanner_access_denied_unauditable_rollup():
    session = MagicMock()
    mock_s3 = MagicMock()
    mock_cw = MagicMock()
    mock_ce = MagicMock()

    scanner = S3Scanner()
    scanner.get_client = lambda s, service, r="us-east-1": (
        mock_s3 if service == "s3" else (mock_cw if service == "cloudwatch" else mock_ce)
    )

    old_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {"Name": "bucket-denied-1", "CreationDate": old_date},
            {"Name": "bucket-denied-2", "CreationDate": old_date},
        ]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    mock_s3.get_bucket_tagging.return_value = {"TagSet": []}

    # Simulate AccessDenied when querying lifecycle configuration
    from botocore.exceptions import ClientError
    denied_err = ClientError({"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "GetBucketLifecycleConfiguration")
    mock_s3.get_bucket_lifecycle_configuration.side_effect = denied_err

    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = []
    mock_cw.get_paginator.return_value = mock_cw_paginator
    mock_ce.get_cost_and_usage.side_effect = Exception("CE unavailable")

    findings = scanner.scan(session, "us-east-1")

    # Should NOT have false missing lifecycle findings
    assert not any("No S3 Lifecycle policy" in f.issue for f in findings)
    assert not any("No 'AbortIncompleteMultipartUpload'" in f.issue for f in findings)

    # Must roll up into an unauditable summary finding
    f_denied = next((f for f in findings if "unauditable-accessdenied" in f.resource_id), None)
    assert f_denied is not None
    assert f_denied.severity == Severity.LOW
    assert "2 S3 bucket(s) could not be fully audited due to IAM permissions (AccessDenied)" in f_denied.issue
    assert "bucket-denied-1" in f_denied.metadata["unaudited_buckets"]
    assert "bucket-denied-2" in f_denied.metadata["unaudited_buckets"]


def test_s3_scanner_single_merged_lifecycle_and_cloudwatch_sizing():
    session = MagicMock()
    mock_s3 = MagicMock()
    mock_cw = MagicMock()
    mock_ce = MagicMock()

    scanner = S3Scanner()
    scanner.get_client = lambda s, service, r="us-east-1": (
        mock_s3 if service == "s3" else (mock_cw if service == "cloudwatch" else mock_ce)
    )

    old_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "prod-data-bucket", "CreationDate": old_date}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    mock_s3.get_bucket_tagging.return_value = {
        "TagSet": [{"Key": "aws:cloudformation:stack-name", "Value": "prod-storage-stack"}]
    }
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

    # Return NoSuchLifecycleConfiguration
    from botocore.exceptions import ClientError
    no_lc_err = ClientError({"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "Not found"}}, "GetBucketLifecycleConfiguration")
    mock_s3.get_bucket_lifecycle_configuration.side_effect = no_lc_err
    mock_s3.get_bucket_encryption.return_value = {}
    mock_s3.get_bucket_accelerate_configuration.return_value = {"Status": "Suspended"}
    mock_s3.get_bucket_replication.side_effect = ClientError({"Error": {"Code": "ReplicationConfigurationNotFoundError"}}, "GetBucketReplication")

    # CloudWatch metrics: 500 GB standard storage and 1,000 objects
    # 500 GB * ($0.023 - $0.0125) * 0.50 cold fraction = 500 * $0.0105 * 0.5 = $2.625 -> $2.62/mo
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "sz_0", "Values": [500 * (1024**3)]},  # 500 GB
                {"Id": "ob_0", "Values": [1000.0]},            # 1,000 objects
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator
    mock_ce.get_cost_and_usage.side_effect = Exception("CE unavailable")

    findings = scanner.scan(session, "us-east-1")

    # MUST emit exactly ONE consolidated finding for this bucket (not 3 separate ones!)
    bucket_findings = [f for f in findings if f.resource_id == "prod-data-bucket"]
    assert len(bucket_findings) == 1

    f = bucket_findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == "Low"
    assert f.estimated_monthly_saving == 2.62
    assert "holds 500.0 GB" in f.issue
    assert "Update CloudFormation stack 'prod-storage-stack'" in f.recommendation
    assert f.metadata["managed_by"] == "CloudFormation"


def test_s3_scanner_early_deletion_traps():
    session = MagicMock()
    mock_s3 = MagicMock()
    mock_cw = MagicMock()
    mock_ce = MagicMock()

    scanner = S3Scanner()
    scanner.get_client = lambda s, service, r="us-east-1": (
        mock_s3 if service == "s3" else (mock_cw if service == "cloudwatch" else mock_ce)
    )

    old_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "trap-bucket", "CreationDate": old_date}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    mock_s3.get_bucket_tagging.return_value = {"TagSet": []}
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {"Status": "Disabled"}

    # Lifecycle rule: transitions to GLACIER at Day 30, but expires at Day 60 (GLACIER min is 90 days!)
    mock_s3.get_bucket_lifecycle_configuration.side_effect = None
    mock_s3.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [
            {
                "ID": "bad-glacier-rule",
                "Status": "Enabled",
                "Filter": {},
                "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
                "Expiration": {"Days": 60},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
            }
        ]
    }
    mock_s3.get_bucket_encryption.return_value = {}
    mock_s3.get_bucket_accelerate_configuration.return_value = {"Status": "Suspended"}
    mock_s3.get_bucket_replication.side_effect = Exception("No replication")
    mock_cw.get_paginator.return_value.paginate.return_value = []
    mock_ce.get_cost_and_usage.side_effect = Exception("CE unavailable")

    findings = scanner.scan(session, "us-east-1")
    f_trap = next((f for f in findings if "Early deletion penalty" in f.issue), None)
    assert f_trap is not None
    assert f_trap.severity == Severity.MEDIUM
    assert f_trap.metadata["storage_class"] == "GLACIER"
    assert f_trap.metadata["min_duration_days"] == 90
    assert "Extend the expiration rule from 60 days to at least 120 days" in f_trap.recommendation


def test_s3_scanner_small_object_guard():
    session = MagicMock()
    mock_s3 = MagicMock()
    mock_cw = MagicMock()
    mock_ce = MagicMock()

    scanner = S3Scanner()
    scanner.get_client = lambda s, service, r="us-east-1": (
        mock_s3 if service == "s3" else (mock_cw if service == "cloudwatch" else mock_ce)
    )

    old_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "small-files-bucket", "CreationDate": old_date}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    mock_s3.get_bucket_tagging.return_value = {"TagSet": []}
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {"Status": "Disabled"}

    # No lifecycle rules
    from botocore.exceptions import ClientError
    no_lc_err = ClientError({"Error": {"Code": "NoSuchLifecycleConfiguration"}}, "GetBucketLifecycleConfiguration")
    mock_s3.get_bucket_lifecycle_configuration.side_effect = no_lc_err
    mock_s3.get_bucket_encryption.return_value = {}
    mock_s3.get_bucket_accelerate_configuration.return_value = {"Status": "Suspended"}
    mock_s3.get_bucket_replication.side_effect = Exception("No replication")

    # CloudWatch metrics: 50 MB total across 10,000 objects (avg size = 5 KB << 128 KB)
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "sz_0", "Values": [50 * 1024 * 1024]},  # 50 MB
                {"Id": "ob_0", "Values": [10000.0]},            # 10,000 objects
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator
    mock_ce.get_cost_and_usage.side_effect = Exception("CE unavailable")

    findings = scanner.scan(session, "us-east-1")
    f_small = next((f for f in findings if f.resource_id == "small-files-bucket"), None)
    assert f_small is not None
    assert f_small.estimated_monthly_saving == 0.0  # Zero fake savings
    assert "small-object bucket" in f_small.issue
    assert "Standard-IA minimum billable size is 128 KB" in f_small.issue
    assert "Avoid transitioning to Standard-IA" in f_small.recommendation


def test_dynamodb_scanner_idle_provisioned_capacity():
    session = MagicMock()
    mock_ddb = MagicMock()
    mock_cw = MagicMock()

    scanner = DynamoDBScanner()
    scanner.get_client = lambda s, service, r="us-east-1": mock_ddb if service == "dynamodb" else mock_cw

    # List 1 table
    mock_ddb_paginator = MagicMock()
    mock_ddb_paginator.paginate.return_value = [{"TableNames": ["idle-app-table"]}]
    mock_ddb.get_paginator.return_value = mock_ddb_paginator

    # Describe table: PROVISIONED with 50 RCU and 50 WCU
    mock_ddb.describe_table.return_value = {
        "Table": {
            "TableName": "idle-app-table",
            "TableArn": "arn:aws:dynamodb:us-east-1:123:table/idle-app-table",
            "BillingModeSummary": {"BillingMode": "PROVISIONED"},
            "ProvisionedThroughput": {"ReadCapacityUnits": 50, "WriteCapacityUnits": 50},
            "TableSizeBytes": 1024 * 1024 * 1024,  # 1 GB
            "ItemCount": 1000,
            "TableClassSummary": {"TableClass": "STANDARD"},
        }
    }
    mock_ddb.list_tags_of_resource.return_value = {"Tags": []}
    mock_ddb.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {}}
    mock_ddb.describe_time_to_live.return_value = {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED"}}

    # CloudWatch metrics: 0 reads and 0 writes
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "tr_0", "Values": [0.0]},
                {"Id": "tw_0", "Values": [0.0]},
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    findings = scanner.scan(session, "us-east-1")
    assert len(findings) == 1

    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "Underutilized Provisioned DynamoDB table" in f.issue
    assert "Switch table capacity mode from PROVISIONED to PAY_PER_REQUEST" in f.recommendation
    assert f.estimated_monthly_saving == 28.47


def test_dynamodb_scanner_stale_gsi_and_pitr():
    session = MagicMock()
    mock_ddb = MagicMock()
    mock_cw = MagicMock()

    scanner = DynamoDBScanner()
    scanner.get_client = lambda s, service, r="us-east-1": mock_ddb if service == "dynamodb" else mock_cw

    mock_ddb_paginator = MagicMock()
    mock_ddb_paginator.paginate.return_value = [{"TableNames": ["dev-users-table"]}]
    mock_ddb.get_paginator.return_value = mock_ddb_paginator

    # Describe table: On-demand with a GSI and non-prod name
    mock_ddb.describe_table.return_value = {
        "Table": {
            "TableName": "dev-users-table",
            "TableArn": "arn:aws:dynamodb:us-east-1:123:table/dev-users-table",
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "TableSizeBytes": 100 * (1024**3),  # 100 GB
            "ItemCount": 500000,
            "TableClassSummary": {"TableClass": "STANDARD"},
            "GlobalSecondaryIndexes": [
                {
                    "IndexName": "email-index",
                    "ProvisionedThroughput": {"ReadCapacityUnits": 20, "WriteCapacityUnits": 20},
                }
            ],
        }
    }
    mock_ddb.list_tags_of_resource.return_value = {
        "Tags": [{"Key": "Environment", "Value": "dev"}]
    }

    # PITR enabled on dev table (100 GB * $0.20/GB = $20.00/mo)
    mock_ddb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED"}
        }
    }
    mock_ddb.describe_time_to_live.return_value = {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED"}}

    # GSI has 0 read units consumed over 14 days
    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = [
        {
            "MetricDataResults": [
                {"Id": "tr_0", "Values": [1000.0]},
                {"Id": "tw_0", "Values": [1000.0]},
                {"Id": "gsi_1", "Values": [0.0]},  # Stale GSI
            ]
        }
    ]
    mock_cw.get_paginator.return_value = mock_cw_paginator

    findings = scanner.scan(session, "us-east-1")

    # Should find stale GSI and PITR on dev table
    f_gsi = next((f for f in findings if "email-index" in f.resource_id), None)
    assert f_gsi is not None
    assert "Unused Global Secondary Index" in f_gsi.issue
    assert f_gsi.estimated_monthly_saving == 11.39

    f_pitr = next((f for f in findings if "Point-in-Time Recovery" in f.issue), None)
    assert f_pitr is not None
    assert f_pitr.estimated_monthly_saving == 20.00
    assert "Disable Point-in-Time Recovery on non-production table" in f_pitr.recommendation


def test_dynamodb_scanner_standard_ia_and_ttl():
    session = MagicMock()
    mock_ddb = MagicMock()
    mock_cw = MagicMock()

    scanner = DynamoDBScanner()
    scanner.get_client = lambda s, service, r="us-east-1": mock_ddb if service == "dynamodb" else mock_cw

    mock_ddb_paginator = MagicMock()
    mock_ddb_paginator.paginate.return_value = [{"TableNames": ["prod-audit-logs"]}]
    mock_ddb.get_paginator.return_value = mock_ddb_paginator

    # 100 GB audit log table in STANDARD class with TTL DISABLED
    mock_ddb.describe_table.return_value = {
        "Table": {
            "TableName": "prod-audit-logs",
            "TableArn": "arn:aws:dynamodb:us-east-1:123:table/prod-audit-logs",
            "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "TableSizeBytes": 100 * (1024**3),  # 100 GB
            "ItemCount": 2000000,
            "TableClassSummary": {"TableClass": "STANDARD"},
        }
    }
    mock_ddb.list_tags_of_resource.return_value = {"Tags": []}
    mock_ddb.describe_continuous_backups.return_value = {"ContinuousBackupsDescription": {}}
    mock_ddb.describe_time_to_live.return_value = {
        "TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}
    }

    mock_cw_paginator = MagicMock()
    mock_cw_paginator.paginate.return_value = []
    mock_cw.get_paginator.return_value = mock_cw_paginator

    findings = scanner.scan(session, "us-east-1")

    # Should recommend Standard-IA 60% discount ($15.00/mo saving on 100 GB)
    f_ia = next((f for f in findings if "STANDARD storage class" in f.issue), None)
    assert f_ia is not None
    assert f_ia.estimated_monthly_saving == 15.00
    assert "DynamoDB Standard-IA (Infrequent Access) to save 60% on storage" in f_ia.recommendation

    # Should recommend enabling TTL for audit log table
    f_ttl = next((f for f in findings if "Time to Live (TTL) DISABLED" in f.issue), None)
    assert f_ttl is not None
    assert f_ttl.estimated_monthly_saving == 0.0
    assert "Configure a TTL attribute" in f_ttl.recommendation
