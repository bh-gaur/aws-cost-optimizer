# Production AWS Cost Optimization Engine

A fast, accurate, and modular AWS cost optimization engine in Python for identifying waste, idle resources, architectural inefficiencies, and right-sizing opportunities across multiple AWS services and regions.

Built from the ground up to eliminate flat estimates, false positives, N+1 API bottlenecks, and dangerous recommendations.

---

## 🌟 Key Features & Service Coverage

```
                                AWS Cost Optimizer Engine
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Real-Time AWS Price List Service API (PriceBook) + In-Memory Thread-Safe Cache  │
  └──────────────────────────────────────┬───────────────────────────────────────────┘
                                         │
     ┌──────────────┬──────────────┬─────┴────────┬──────────────┬──────────────┐
     ▼              ▼              ▼              ▼              ▼              ▼
  Amazon EC2    Amazon EBS    Elastic Load    Amazon RDS    AWS Lambda    CloudWatch
  Compute & IP   Volumes &     Balancers     & Aurora DB    Serverless    Logs & Metrics
   Instances     Snapshots     (v1 & v2)      Instances      Functions     & Ingestion
```

### 1. Amazon EC2 (`ec2.py`)
- **Batched CloudWatch API Calls**: Batches metric queries (`get_metric_data`) with up to 400 queries per call for Average and Maximum CPU utilization and Network I/O.
- **Dynamic Pricing via PriceBook**: Queries the AWS Price List Service API (`pricing:GetProducts` in `us-east-1`) in real time, backed by local in-memory caching and regional offline fallbacks.
- **Storage-Based Stopped Instance Costing**: Stopped instances pay only for attached EBS volumes and Elastic IPs (not compute). Calculates exact attached volume costs ($\sum \text{Size}_{\text{GB}} \times \text{StorageRate}$).
- **State Transition Age Tracking**: Parses `StateTransitionReason` to calculate how many days an instance has been stopped.
- **Exact Family Matching (No False Positives)**: Family partition lookup (`t2` $\to$ `t3`, `i3` $\to$ `i4i`) prevents bugs (e.g. current-generation `i3en` is untouched).
- **No Double Counting**: When an instance is flagged as idle, duplicate generation upgrade and Graviton recommendations for that instance are suppressed.
- **Public IPv4 Audit**: Evaluates the mandatory \$0.005/hr (\$3.65/mo) public IPv4 fee introduced in 2024.
- **Infrastructure Guards**: Protects Auto Scaling Group members (`aws:autoscaling:groupName`), Kubernetes/EKS worker nodes (`eks:cluster-name`), and instances with ignore tags (`cost-optimizer:ignore`).

### 2. Amazon EBS (`ebs.py`)
- **Eliminated Overlapping Findings**: Unattached volumes (`state == "available"`) generate a single finding and immediately skip redundant `gp2` or oversize checks.
- **No Flat $5 Floors**: Uses real-time per-GB storage rates for each volume type (`gp3`, `gp2`, `io1`, `io2`, `st1`, `sc1`). An 8 GB volume is accurately reported at \$0.64/mo, not inflated to \$5.
- **IOPS-Aware `gp2` $\to$ `gp3` Calculations**: Accounts for `gp2`'s 3 IOPS/GB scaling vs `gp3`'s 3,000 baseline included IOPS. Deducts \$0.005 per extra provisioned IOPS above 3,000; never recommends `gp3` if provisioned IOPS costs exceed storage savings.
- **Snapshot Protection (Zero False Positives)**:
  - Scans `ec2.describe_images(Owners=["self"])` and protects any snapshot backing an active AMI.
  - Skips snapshots managed by AWS Backup or Data Lifecycle Manager (`aws:backup:*`, `aws:dlm:*`).
- **Orphaned Snapshot Detection**: Identifies snapshots whose source volume was deleted; reports them as higher-confidence opportunities.
- **Honest Incremental Snapshot Savings**: Deleting an incremental snapshot only frees unreferenced delta blocks (estimates 30% of source volume size with `confidence="Low"`).
- **Idle Attached Volumes**: Batches CloudWatch `VolumeReadOps` and `VolumeWriteOps` over 14 days to find in-use volumes with zero I/O activity.
- **Fast Snapshot Restore (FSR) Detection**: Flags active FSR configurations that cost \$0.75/hr per AZ (\$547.50/month per AZ).

### 3. Elastic Load Balancing (`elb.py`)
- **Public IPv4 Charges Included**: Accounts for the \$0.005/hr (\$3.65/mo) per-AZ fee for internet-facing load balancers.
- **Classic Load Balancers (CLBs)**:
  - 0 registered instances $\to$ `HIGH` severity with full base savings.
  - Registered instances all `OutOfService` $\to$ `MEDIUM` reliability alert.
  - Active instances with zero 30-day traffic $\to$ `HIGH` severity idle waste.
  - Active CLBs $\to$ `LOW` severity modernization finding calculating the real base delta ($\approx \$1.83$/month) rather than the entire CLB cost.
- **v2 Load Balancers (ALB / NLB / GWLB)**:
  - `no_listeners` $\to$ Unambiguously unused (`HIGH` severity).
  - `no_target_groups` $\to$ Recognizes valid HTTP $\to$ HTTPS redirect and fixed-response ALBs; checks 30-day traffic instead of false-positive deletion.
  - `no_targets` $\to$ Target groups exist but 0 registered targets (`HIGH` severity).
  - `all_unhealthy` $\to$ Outage alert (`MEDIUM` severity, \$0 savings, explicit warning **DO NOT delete**).
  - `has_targets` with 0 traffic $\to$ Healthy targets, but zero requests over 30 days (`HIGH` severity idle waste).
- **ALB Consolidation**: Detects multiple low-traffic ALBs ($< 1,000$ requests/day) in the same VPC and recommends consolidating them using host- and path-based routing rules, saving $(N - 1) \times \text{monthly\_base}$.
- **NLB Cross-Zone Data Transfer**: Flags NLBs processing $> 1\text{ TB}$ with cross-zone load balancing enabled incurring \$0.01/GB transfer charges.
- **Controller & IaC Protection**: Recognizes Kubernetes AWS Load Balancer Controller (`elbv2.k8s.aws`), Elastic Beanstalk, and CloudFormation. Audits `deletion_protection.enabled`.

### 4. Amazon RDS & Aurora (`rds.py`)
- **Bug Fix**: Uses `<=` for connection thresholds (`max_connections <= CONFIG.RDS_IDLE_CONNECTIONS_THRESHOLD`), preventing missed idle databases.
- **Exact Non-Prod Token Matching**: Replaced brittle substring matching with exact token matching (`{"dev", "test", "qa", "uat", "stage", "staging", "sandbox", "nonprod"}`), eliminating false positives like `"devops-prod"`.
- **Dynamic Pricing & Multi-AZ Storage Mirroring**: Computes exact hourly deltas and includes secondary AZ storage mirroring costs when calculating Multi-AZ savings.
- **RDS Extended Support Charges**: Detects end-of-standard-support major engine versions (MySQL 5.7, PostgreSQL 11 & 12, Aurora MySQL 2) incurring \$0.10+/vCPU-hour extended support surcharges (\$73+/vCPU/month).
- **Storage Optimization (`gp2` $\to$ `gp3`)**: Recommends live zero-downtime migration to `gp3` (20% cost reduction plus 3,000 IOPS and 125 MB/s baseline throughput included for free).
- **Honest Snapshot Auditing**: Checks Cost Explorer for real billed backup usage (`ChargedBackupUsage`). If billed backup usage is \$0 (covered by the free 100% provisioned storage allowance), reported savings are marked as **\$0.00**.
- **Aurora Cluster Audits**: Audits `describe_db_cluster_snapshots`, detects redundant non-prod reader instances, and flags high `MinCapacity` on Aurora Serverless v2 clusters.
- **Guards**: Enforces instance age and minimum datapoints, protects Blue/Green deployments, checks read replicas, and warns about the 7-day automatic restart of stopped RDS instances.

### 5. AWS Lambda (`lambda_func.py`)
- **Measured Cost Math (No Flat Savings)**: Computes exact compute spend from CloudWatch duration and memory:
  $$\text{GB-seconds} = \left(\frac{\text{Duration\_ms}}{1000}\right) \times \left(\frac{\text{Memory\_MB}}{1024}\right) \times \left(\frac{30}{\text{days}}\right)$$
  Computes exact Graviton2 (arm64) savings ($\approx 20\%$) on measured GB-seconds; filters out noise below \$0.50/mo.
- **Idle Provisioned Concurrency Audit**: Audits `list_provisioned_concurrency_configs` and CloudWatch `ProvisionedConcurrencyUtilization`. Flags idle provisioned concurrency ($< 5\%$ utilization) costing $\approx \$10.95$/GB-month.
- **Smarter Inactive Function Detection**: Enforces a 90-day `LastModified` grace period. Inspects `get_policy` for infrequent/failover event triggers (EventBridge, S3, SNS, Cognito, CloudFormation custom resources). Reports true CloudWatch Log Group storage waste (\$0.03/GB) instead of fictitious compute savings.
- **AWS Compute Optimizer Integration**: Adopts official `MemoryOverprovisioned` recommendations and calculated monthly savings.
- **arm64 Compatibility Checks**: Inspects container images (`PackageType == "Image"`) and attached layers for `CompatibleArchitectures`.
- **Merged Findings**: Merges memory rightsizing and Graviton upgrades into one coherent finding per function without double-counting.
- **Error Rate Waste & Deprecated Runtimes**: Flags functions with $> 20\%$ error rates and identifies end-of-life runtimes.

### 6. Amazon CloudWatch Logs (`cloudwatch.py`)
- **No Arbitrary $3 Floor**: Drops findings below \$0.50 as negligible noise.
- **Realistic Retention Delta Math**: Estimates historical data reduction based on age and target retention:
  $$\text{Saving} = \text{Stored}_{\text{GB}} \times \$0.03 \times \max\left(0, 1 - \frac{\text{TargetRetentionDays}}{\text{AgeDays}}\right)$$
- **Prefix-Aware Tailored Policies**: 14 days for Lambda & VPC flow logs; 30 days for API Gateway, EKS, RDS; 365 days for CloudTrail audit logs.
- **Ingestion Volume Tracking**: Batches `IncomingBytes` queries over 30 days to measure real ingestion (\$0.50/GB vs \$0.03/GB storage).
- **Infrequent Access (IA) Migration**: Recommends IA class for high-ingestion groups with no metric/subscription filters (saving 50% on ingestion).
- **Orphaned & Dead Groups**: Flags log groups from deleted Lambda functions (`/aws/lambda/*`) and empty/dormant log groups.

### 7. AWS KMS (`kms.py`)
- **Evidence of Use (No Blind Age Checks)**: Checks active grants (`list_grants` for EBS, RDS, Redshift) and CloudTrail cryptographic operations (`lookup_events` for `Decrypt`, `Encrypt`, `GenerateDataKey`). Only flags keys with **0 grants AND 0 crypto events** in 90 days.
- **`PendingDeletion` Fix**: Keys in `PendingDeletion` or `PendingReplicaDeletion` are excluded from savings (billed at \$0 by AWS). Surfaces as an informational hygiene alert to monitor CloudWatch for accidental decryption attempts.
- **Pre-Filtered Aliases**: Pre-fetches all aliases with `list_aliases` and skips AWS-managed keys (`alias/aws/*`) upfront, saving dozens of N+1 API calls.
- **Account-Level Spend Sizing**: Queries Cost Explorer to compare key fees vs request fees; flags when API requests dominate and recommends S3 Bucket Keys or client-side caching.
- **Safety-First Recommendations**: Recommends disabling the key first, monitoring CloudTrail for `DisabledException` for 30–60 days, and only then scheduling deletion with a 30-day waiting period.
- **Noise Roll-Up**: Rolls up multiple \$1/mo findings into consolidated regional findings. Tracks `AccessDeniedException` into a dedicated summary finding.
- **Custom Key Stores & Multi-Region**: Flags dedicated CloudHSM Custom Key Stores and multi-region replica keys.

### 8. Amazon S3 (`s3.py`)
- **S3 SSE-KMS Bucket Keys**: Flags buckets with SSE-KMS encryption where S3 Bucket Keys are disabled, unlocking up to **99% reduction in KMS request fees**.
- **Lifecycle Configuration**: Identifies buckets missing transition/expiration rules.
- **Multipart Upload Expiration**: Detects missing `AbortIncompleteMultipartUpload` rules to stop accumulating hidden storage fees.
- **Non-Current Version Expiration**: Flags versioned buckets without expiration rules on old object versions.

---

## 💻 CLI Usage & Commands

### Prerequisites
- Python 3.9+
- AWS credentials configured via `~/.aws/credentials`, `~/.aws/config`, or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).

### Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Scan Specific Services in a Region
```bash
./venv/bin/python aws_cost_optimizer.py --services ec2,ebs,rds,lambda --regions us-east-1
```

### Discover and Scan All Enabled AWS Regions Concurrently
```bash
./venv/bin/python aws_cost_optimizer.py --all-regions --threads 12
```

### Export Findings to CSV or JSON
```bash
# Export all findings to a CSV spreadsheet
./venv/bin/python aws_cost_optimizer.py --output cost_audit.csv

# Export findings as JSON
./venv/bin/python aws_cost_optimizer.py --services elb,kms,rds --format json --output rds_elb.json
```

### Use a Specific AWS Named Profile
```bash
./venv/bin/python aws_cost_optimizer.py --profile production --regions us-east-1,us-west-2
```

### List Supported Services
```bash
./venv/bin/python aws_cost_optimizer.py --list-services
```

---

## ⚙️ Configuration & Thresholds

All thresholds can be customized via environment variables or in [`aws_cost_optimizer/config.py`](file:///Users/vishnu/learning/b_github/aws_cost_optimizer/config.py):

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `AICO_MAX_THREADS` | `8` | Parallel worker threads for multi-region / multi-service scanning |
| `AICO_AWS_MAX_ATTEMPTS` | `10` | Adaptive retry attempts with exponential backoff on AWS APIs |
| `AICO_METRIC_DAYS` | `14` | Lookback window for CloudWatch metric evaluations |
| `AICO_EC2_CPU_AVG` | `5.0` | Maximum average CPU % threshold to classify an EC2 instance as idle |
| `AICO_EC2_CPU_MAX` | `20.0` | Maximum peak CPU % threshold to classify an EC2 instance as idle |
| `AICO_EBS_LARGE_GB` | `500` | Storage threshold for flagging large attached EBS volumes |
| `AICO_EBS_SNAPSHOT_DAYS` | `90` | Minimum snapshot age in days before flagging as stale |
| `AICO_ELB_LOOKBACK_DAYS` | `30` | Lookback window in days for auditing load balancer traffic |
| `AICO_RDS_SNAPSHOT_DAYS` | `30` | Minimum age in days for manual RDS snapshots before auditing |
| `AICO_LAMBDA_DAYS` | `90` | Inactivity window in days for Lambda invocations |
| `AICO_LAMBDA_MIN_SAVINGS`| `0.50` | Minimum monthly savings threshold before surfacing a Lambda finding |
| `AICO_KMS_LOOKBACK_DAYS` | `90` | Lookback window for checking CloudTrail KMS crypto operations |

---

## 🧪 Testing

The test suite covers unit and integration tests across all scanners, ensuring zero false positives, pricing math accuracy, and safety guards.

Run tests using pytest:
```bash
PYTHONPATH=. ./venv/bin/pytest tests/test_aws_cost_optimizer.py
```
```
============================== 12 passed in 0.20s ==============================
```

---

## 🛡️ Safety & Reliability Principles

1. **Non-Destructive by Default**: The scanner is read-only. It never deletes, stops, modifies, or terminates resources automatically.
2. **Infrastructure-as-Code First**: When resources are managed by CloudFormation, AWS CDK, AWS SAM, Serverless Framework, or the Kubernetes AWS Load Balancer Controller, the scanner explicitly advises updating the owning template rather than making manual console changes that will be overwritten.
3. **Outage vs Waste Distinction**: If all targets on a load balancer are unhealthy, it flags a **reliability outage alert** with \$0 savings and warns **NOT to delete** the load balancer.
4. **Data Protection Safeguards**: Always recommends a final snapshot step before terminating databases or deleting keys, and warns about AWS-specific behaviors (such as the automatic 7-day restart of stopped RDS databases and permanent KMS key destruction).
