# Production AWS Cost Optimization Engine

A fast, accurate, and modular AWS cost optimization engine in Python for identifying waste, idle resources, architectural inefficiencies, and right-sizing opportunities across multiple AWS services and regions.

Built from the ground up to eliminate flat estimates, arbitrary floors, false positives, N+1 API bottlenecks, and dangerous recommendations.

---

## 🌟 Architecture & Engine Overview

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
     │              │              │              │              │              │
     └──────────────┴──────────────┼──────────────┴──────────────┴──────────────┘
                                   ▼
                       ┌───────────────────────┐
                       │   AWS KMS & Encryption│
                       │   Amazon S3 Storage   │
                       │   Amazon VPC & Network│
                       └───────────────────────┘
```

### Core Design Principles
1. **Zero Fictional Dollars**: No flat dollar guesses ($5, $15, $75) or arbitrary minimum floors ($3 floors). Savings are derived from real-time pricing via the AWS Price List Service API (`PriceBook`) or exact metric duration formulas.
2. **Batch Multi-Metric CloudWatch Querying**: Replaces slow, rate-limited single metric lookups with batched `get_metric_data` paginators (up to 400 queries per call), querying days of CPU, I/O, network, and invocation data in seconds.
3. **Outage vs. Waste Distinction**: If all targets on a load balancer fail health checks, the tool emits a **reliability outage alert** with $0.00 savings and an explicit warning **DO NOT delete**.
4. **Infrastructure as Code (IaC) Protection**: Detects CloudFormation (`aws:cloudformation:stack-name`), AWS CDK (`cdk-*-assets-*`), AWS SAM, Elastic Beanstalk, and the Kubernetes AWS Load Balancer Controller (`elbv2.k8s.aws`). Recommends updating the source template rather than manual console changes.
5. **Permission Resilience**: Never treats `AccessDenied` as "resource has no configuration." Unauditable resources are rolled up into an informational summary finding rather than polluting reports with false-positive alerts.

---

## 🔍 In-Depth Service-by-Service Explanations

### 1. Amazon EC2 Compute & Public IPv4 (`ec2.py`)

#### What the Scanner Audits
* **Instance States & Lifecycle**: Evaluates `running`, `stopped`, and `shutting-down` instances.
* **CPU & Network Utilization**: Batches CloudWatch `CPUUtilization` (Average and Maximum) and `NetworkIn`/`NetworkOut` over 14 days (`CONFIG.METRIC_LOOKBACK_DAYS`).
* **Hardware Generation Upgrades**: Identifies previous-generation instances (`t2`, `m4`, `c4`, `r4`, `i3`) with direct modern equivalents (`t3`, `m5`, `c5`, `r5`, `i4i`).
* **AWS Graviton (arm64) Upgrades**: Identifies x86 instances eligible for high-efficiency Graviton instances (`t4g`, `m6g`, `c6g`, `r6g`).
* **Public IPv4 Allocation**: Audits public IPv4 addresses attached to running or stopped EC2 instances.

#### Cost Traps & Flaws in Common Scanners
* *The Stopped Instance Trap*: Common scripts assume stopped instances cost $0.00. However, attached EBS root and data volumes continue accruing storage charges every second.
* *The False Family Partition Bug*: Naive substring matching (e.g. `instance_type.startswith("i3")`) incorrectly flags modern storage-optimized `i3en` instances as obsolete `i3` instances.
* *Double-Counting*: Flagging an instance as idle to terminate while simultaneously recommending a modern family upgrade and Graviton migration creates triple-counted, fictional savings.

#### Production Solution & Mathematical Model
* **Attached Storage Costing**: Computes exact EBS storage costs for stopped instances based on volume sizes and real-time per-GB pricing:
  $$\text{Monthly Cost} = \sum_{v \in \text{Volumes}} \text{Size}_{\text{GB}}(v) \times \text{Rate}_{\text{EBS}}(v.\text{type}) + \$3.65 \text{ (if Public IPv4 allocated)}$$
* **Parsed Stopped Duration**: Extracts timestamps from `StateTransitionReason` (e.g. `User initiated (2026-08-01 10:15:33 GMT)`) to accurately track stopped days.
* **Exact Family Partitioning**: Uses dictionary lookups (`{"t2": "t3", "i3": "i4i"}`) protecting `i3en` instances.
* **Guardrails**: Ignores Auto Scaling Group members (`aws:autoscaling:groupName`) and Kubernetes worker nodes (`eks:cluster-name`).

---

### 2. Amazon EBS Storage, Snapshots & FSR (`ebs.py`)

#### What the Scanner Audits
* **Unattached Volumes**: Queries `describe_volumes` with filter `status == "available"`.
* **gp2 to gp3 Storage Migration**: Evaluates volumes utilizing legacy General Purpose SSD (`gp2`).
* **Attached Volume I/O Activity**: Batches CloudWatch `VolumeReadOps` and `VolumeWriteOps` over 14 days to identify attached but completely idle volumes.
* **EBS Snapshots**: Audits account-owned snapshots (`describe_snapshots(OwnerIds=["self"])`) for age, volume attachment, and AMI association.
* **Fast Snapshot Restore (FSR)**: Audits active FSR configurations via `describe_fast_snapshot_restores`.

#### Cost Traps & Flaws in Common Scanners
* *The $5 Flat Floor Bug*: Naive tools report an unattached 8 GB volume as a flat $5.00 saving. At $0.08/GB, the real monthly saving is only $0.64.
* *The gp3 IOPS Penalty Trap*: `gp2` scales baseline IOPS with volume size ($3 \times \text{Size}_{\text{GB}}$). Migrating a 2,000 GB `gp2` volume (6,000 baseline IOPS) to `gp3` requires provisioning 3,000 extra IOPS ($3,000 \times \$0.005 = \$15.00/\text{mo}$), which wipes out the $16/mo storage savings.
* *Deleting Live AMI Snapshots*: Deleting snapshots backing active AMIs or managed by AWS Backup (`aws:backup:*`) causes catastrophic deployment failures.
* *Incremental Snapshot Illusion*: Deleting one incremental snapshot in a chain only frees blocks unique to that snapshot; claiming 100% of the volume size as savings is mathematically false.

#### Production Solution & Mathematical Model
* **Dynamic Per-Type Pricing**: Pulls exact regional rates for `gp3`, `gp2`, `io1`, `io2`, `st1`, and `sc1`.
* **IOPS-Aware `gp2` $\to$ `gp3` Math**:
  $$\text{Storage Savings} = \text{Size}_{\text{GB}} \times (\text{Rate}_{\text{gp2}} - \text{Rate}_{\text{gp3}}) = \text{Size}_{\text{GB}} \times \$0.02$$
  $$\text{IOPS Surcharge} = \max(0, 3 \times \text{Size}_{\text{GB}} - 3000) \times \$0.005$$
  $$\text{Net Savings} = \text{Storage Savings} - \text{IOPS Surcharge}$$
  If Net Savings $\le 0$, the upgrade is automatically suppressed.
* **AMI & Backup Protection**: Pre-fetches `ec2.describe_images(Owners=["self"])` and registers all backing snapshots in an exclusion set.
* **Fast Snapshot Restore Audit**: Flags FSR configurations costing **$0.75/hr per AZ ($547.50/AZ-month)**.

---

### 3. Elastic Load Balancing (`elb.py`)

#### What the Scanner Audits
* **Classic Load Balancers (v1)**: Queries `describe_load_balancers` and `describe_instance_health`.
* **Application, Network & Gateway Load Balancers (v2)**: Evaluates listeners, target groups, target health (`describe_target_health`), and CloudWatch 30-day traffic (`RequestCount`, `ActiveConnectionCount`).
* **ALB Consolidation**: Analyzes low-traffic ALBs ($< 1,000$ requests/day) in the same VPC.
* **NLB Cross-Zone Transfer**: Audits cross-zone data transfer on Network Load Balancers.

#### Cost Traps & Flaws in Common Scanners
* *The Redirect ALB False Positive*: ALBs configured solely for HTTP $\to$ HTTPS redirects or fixed responses have 0 target groups. Naive tools flag them for immediate termination, breaking domain routing.
* *The Unhealthy Outage Bug*: When all targets in a target group fail health checks, naive tools treat the load balancer as "idle" and recommend deletion—turning an ongoing application outage into permanent infrastructure destruction.
* *Classic LB Flat Base Cost*: Migrating an active CLB ($0.025/hr) to an ALB ($0.0225/hr) saves only the difference ($\approx \$1.83/\text{mo}$), not the entire $18.25/mo CLB fee.

#### Production Solution & Mathematical Model
* **Accurate Base Rates & Public IPv4**:
  $$\text{Monthly Base} = (\text{Hourly Base} + \text{Num AZs} \times \$0.005) \times 730$$
* **v2 State Classification Engine**:
  * `no_listeners` $\to$ `HIGH` severity (unambiguously unused).
  * `no_target_groups` with zero traffic $\to$ `HIGH` severity.
  * `no_target_groups` with active traffic $\to$ Valid redirect ALB (safe, untouched).
  * `all_unhealthy` $\to$ `MEDIUM` reliability outage alert ($0.00 savings, explicit "DO NOT delete" warning).
  * `no_targets` $\to$ `HIGH` severity waste.
  * `has_targets` with 0 requests over 30 days $\to$ `HIGH` severity idle waste.
* **ALB Consolidation Math**: If $N$ ALBs in the same VPC process $< 1,000$ requests/day:
  $$\text{Consolidation Savings} = (N - 1) \times \text{ALB Monthly Base}$$

---

### 4. Amazon RDS & Aurora Databases (`rds.py`)

#### What the Scanner Audits
* **Database Instances & Clusters**: Evaluates standard RDS instances and Aurora DB clusters.
* **Connection & CPU Metrics**: Batches CloudWatch `DatabaseConnections` and `CPUUtilization` (Avg/Max).
* **Extended Support Surcharges**: Identifies end-of-support major engine versions (MySQL 5.7, PostgreSQL 11/12, Aurora MySQL 2).
* **Storage Volumes (`gp2` $\to$ `gp3`)**: Audits provisioned storage type, IOPS, and throughput.
* **Snapshots & Billed Backup**: Cross-references manual snapshots against Cost Explorer `ChargedBackupUsage`.

#### Cost Traps & Flaws in Common Scanners
* *The Connection Threshold Bug*: Naive code uses `max_connections == CONFIG.RDS_IDLE_CONNECTIONS_THRESHOLD`. If the threshold is configured to 1 or 2, a database with 0 connections is completely missed!
* *The Substring Non-Prod Bug*: Checking `if "dev" in tag_value` matches `"devops-production"` and flags production Multi-AZ databases for downscaling.
* *Fictional Snapshot Savings*: AWS grants a free backup storage allowance equal to 100% of total provisioned database storage. Deleting manual snapshots when total backup storage is within the free allowance saves $0.00.
* *The 7-Day Auto-Restart Trap*: Stopping an RDS instance only pauses it for 7 days; AWS automatically restarts stopped RDS instances to apply maintenance updates.

#### Production Solution & Mathematical Model
* **Threshold Fix**: Uses `<=` (`max_connections <= CONFIG.RDS_IDLE_CONNECTIONS_THRESHOLD`).
* **Exact Token Non-Prod Matching**: Matches exact tokens (`{"dev", "test", "qa", "uat", "stage", "staging", "sandbox", "nonprod"}`).
* **Multi-AZ Math with Secondary Storage Mirroring**:
  $$\text{Multi-AZ Delta} = (\text{Single-AZ Hourly Rate} \times 730) + (\text{AllocatedStorage}_{\text{GB}} \times \text{StorageRate})$$
* **RDS Extended Support Detection**: Identifies engines incurring **$0.10+/vCPU-hour ($73+/vCPU-month)** in Years 1–2, rising to $0.20/vCPU-hour in Year 3.
* **Honest Snapshot Auditing**: Checks Cost Explorer for real billed backup usage; if billed usage is $0.00, reported savings are marked as **$0.00**.

---

### 5. AWS Lambda Serverless Functions (`lambda_func.py`)

#### What the Scanner Audits
* **Function Invocations & Duration**: Batches CloudWatch `Invocations`, `Duration` (Average), and `Errors`.
* **Provisioned Concurrency**: Audits `list_provisioned_concurrency_configs` and CloudWatch `ProvisionedConcurrencyUtilization`.
* **Compute Optimizer Recommendations**: Ingests AWS Compute Optimizer `MemoryOverprovisioned` recommendations.
* **Architecture Modernization**: Evaluates x86_64 functions for 20% Graviton2 (arm64) cost reduction.
* **Deprecated Runtimes**: Detects unsupported language runtimes (Node 10/12/14/16, Python 2.7/3.6/3.7/3.8, Java 8, Ruby 2.5/2.7).

#### Cost Traps & Flaws in Common Scanners
* *Flat Guess Dollar Savings*: Reporting flat $5 or $10 savings for idle functions. Under the AWS Free Tier (1M requests, 400,000 GB-seconds/month), low-traffic accounts pay $0.00 for Lambda.
* *Breaking Native Binaries via Blind arm64 Advice*: Recommending arm64 on container images (`PackageType == "Image"`) or functions with x86-compiled C/C++ native layers breaks production code.
* *The Idle Provisioned Concurrency Leak*: Over-provisioning concurrency costs ~$10.95/GB-month 24/7 regardless of traffic.

#### Production Solution & Mathematical Model
* **Measured GB-Second Cost Math**:
  $$\text{GB-seconds} = \left(\frac{\text{Duration}_{\text{ms}}}{1000}\right) \times \left(\frac{\text{Memory}_{\text{MB}}}{1024}\right) \times \text{Invocations}$$
  $$\text{Graviton Savings} = \text{GB-seconds} \times \$0.0000133334 \times 0.20$$
  Filters out negligible findings below $0.50/mo.
* **Idle Provisioned Concurrency Math**:
  $$\text{Concurrency Waste} = \text{Allocated}_{\text{MB}} \times \text{ProvisionedInstances} \times \$0.0000041667 \times 3600 \times 730$$
* **Layer & Container Image Compatibility**: Inspects `CompatibleArchitectures` on attached layers and warns when container images require cross-compilation.

---

### 6. Amazon CloudWatch Logs & Ingestion (`cloudwatch.py`)

#### What the Scanner Audits
* **Log Group Retention**: Identifies log groups set to *Never Expire*.
* **Ingestion Volume**: Batches 30-day `IncomingBytes` queries via `get_metric_data`.
* **Infrequent Access (IA) Migration**: Identifies high-ingestion log groups with no metric/subscription filters.
* **Orphaned Log Groups**: Cross-references `/aws/lambda/*` log groups against active Lambda functions.

#### Cost Traps & Flaws in Common Scanners
* *The $3 Minimum Floor Bug*: A 2 MB log group costs well under a cent per month, but naive tools floor it at $3.00, reporting $1,500/month of non-existent savings across 500 Lambda functions.
* *Total Size vs. Historical Delta*: Setting a 30-day retention on a log group created 7 days ago saves $0.00.
* *Ignoring Ingestion Charges*: Storage is $0.03/GB-month, but ingestion is $0.50/GB (over 16x higher). Naive tools never analyze ingestion volume.

#### Production Solution & Mathematical Model
* **Realistic Historical Retention Delta Math**:
  $$\text{Estimated Storage Saving} = \text{Stored}_{\text{GB}} \times \$0.03 \times \max\left(0, 1 - \frac{\text{TargetRetentionDays}}{\text{LogGroupAgeDays}}\right)$$
* **Tailored Prefix Policies**:
  * `14 days`: `/aws/lambda/*`, `/aws/kinesis/*`, `vpc-flow-logs`
  * `30 days`: `/aws/apigateway/*`, `/aws/eks/*`, `/aws/rds/*`
  * `365 days`: `cloudtrail`, `audit`, `security`
* **Infrequent Access (IA) Class Savings**:
  $$\text{Ingestion Savings} = \text{Monthly Ingestion}_{\text{GB}} \times (\$0.50 - \$0.25) = \text{Ingestion}_{\text{GB}} \times \$0.25$$

---

### 7. AWS Key Management Service (KMS) (`kms.py`)

#### What the Scanner Audits
* **Customer Managed Keys (CMKs)**: Audits key state, key manager, origin, and creation date.
* **Cryptographic Usage Evidence**: Queries active grants (`list_grants`) and CloudTrail cryptographic events (`lookup_events` for `Decrypt`, `Encrypt`, `GenerateDataKey`).
* **Cost Explorer Spend Sizing**: Compares monthly Key Storage fees ($1/key) vs. API Request fees ($0.03/10k requests).
* **Pending Deletion Keys**: Verifies keys in `PendingDeletion` or `PendingReplicaDeletion`.

#### Cost Traps & Flaws in Common Scanners
* *Blind Age Checks*: Flagging long-lived keys as waste. In KMS, long-lived keys typically encrypt stable, mission-critical RDS, S3, or EBS volumes.
* *The PendingDeletion Bug*: AWS bills $0.00 for keys in `PendingDeletion`. Naive scanners flag them as $1.00/month savings.
* *N+1 API Throttling*: Calling `describe_key` on hundreds of AWS-managed keys (`alias/aws/*`) triggers rate limiting.
* *Catastrophic Deletion Advice*: Recommending `schedule_key_deletion` directly can cause unrecoverable permanent data loss.

#### Production Solution & Mathematical Model
* **Usage Evidence Workflow**: Only flags keys with **0 active grants AND 0 CloudTrail cryptographic events** over 90 days (`CONFIG.KMS_LOOKBACK_DAYS`).
* **Pre-Filtered Aliases**: Pre-fetches `list_aliases` to skip all AWS-managed keys upfront before making detailed calls.
* **Safety-First 3-Step Procedure**:
  1. Disable the key first (`DisableKey`).
  2. Monitor CloudTrail for 30–60 days for `DisabledException` alerts.
  3. Only schedule key deletion with a 30-day waiting window once verified.

---

### 8. Amazon S3 Storage & Lifecycle Configuration (`s3.py`)

#### What the Scanner Audits
* **Lifecycle Rules**: Analyzes transition rules, expiration rules, multipart upload abort rules, and noncurrent version expiry.
* **Daily CloudWatch Storage & Object Metrics**: Batches `BucketSizeBytes` (StandardStorage) and `NumberOfObjects` (AllStorageTypes).
* **S3 SSE-KMS & S3 Bucket Keys**: Audits default encryption for `aws:kms` and `BucketKeyEnabled`.
* **Cost Traps**: Server access log targets without expiration, Transfer Acceleration, cross-region replication, and early-deletion penalties.

#### Cost Traps & Flaws in Common Scanners
* *The AccessDenied False Positive*: When reading a lifecycle policy fails with `AccessDenied`, naive tools assume no policy exists and report the bucket as non-compliant.
* *Small-Object Heavy IA Disasters*: Standard-IA bills a **128 KB minimum per object** and charges transition request fees (~$0.01/1,000 objects). Transitioning millions of 5–20 KB files to Standard-IA inflates the storage bill.
* *Finding Sprawl*: Emitting 3 separate findings for missing lifecycle, missing multipart abort, and noncurrent version expiry ($40/mo total) when one single configuration fixes all three.
* *Bucket Keys Encryption Context Breakage*: S3 Bucket Keys change the KMS encryption context from the object ARN (`arn:aws:s3:::bucket/key`) to the bucket ARN (`arn:aws:s3:::bucket`), which breaks IAM or KMS policies that match on object ARNs.

#### Production Solution & Mathematical Model
* **Permission Resilience**: Separates `NoSuchLifecycleConfiguration` (empty config) from `AccessDenied`. Rolls up unauditable buckets into an informational summary finding (`s3-unauditable-accessdenied`).
* **Single Merged Lifecycle Finding**: Consolidates all lifecycle gaps into **one finding per bucket**.
* **CloudWatch Differential Sizing**:
  $$\text{Estimated Monthly Saving} = \text{std\_gb} \times (\$0.023 - \$0.0125) \times \text{COLD\_FRACTION}$$
* **Small-Object Guard**: If average object size $< 128\text{ KB}$, flags with $0.00 savings and warns against Standard-IA transitions.
* **Early-Deletion Trap Detection**: Identifies rules expiring objects before the storage class minimum retention expires (e.g. Glacier 90 days, Deep Archive 180 days), paying prorated penalty charges.

---

### 9. Amazon VPC & Networking (`vpc.py`)

#### What the Scanner Audits
* **Public IPv4 & Elastic IP Addresses**: Audits unassociated EIPs and EIPs attached to stopped EC2 instances.
* **NAT Gateways**: Audits route tables (`describe_route_tables`), age, and batched 14-day CloudWatch metrics (`BytesOutToDestination`, `BytesInFromDestination`, `ActiveConnectionCount`).
* **Gateway VPC Endpoints**: Identifies VPCs with active NAT Gateways missing free S3 and DynamoDB Gateway Endpoints.
* **Network Interfaces (ENIs)**: Audits available ENIs, filtering out AWS service-managed interfaces.
* **AWS PrivateLink Interface Endpoints**: Audits endpoints across AZs for zero traffic (`BytesProcessed`).
* **Site-to-Site VPN Connections**: Audits VPN connections for zero tunnel data transfer.

#### Cost Traps & Flaws in Common Scanners
* *The $1 ENI Lie*: AWS charges $0.00 for unattached network interfaces. Claiming a $1 saving per ENI is completely fictional.
* *Deleting Active NATs*: Deleting a NAT Gateway whose route tables point `0.0.0.0/0` to it blackholes private subnet traffic.
* *Missing IPv4 Charges on Stopped Instances*: Since February 2024, AWS charges $0.005/hr ($3.65/mo) for all public IPv4 addresses, including those attached to stopped EC2 instances.
* *Multi-AZ NAT Overkill in Non-Prod*: Provisioning 2 or 3 NAT Gateways in dev/test/staging VPCs wastes $73–$110/month.

#### Production Solution & Mathematical Model
* **Public IPv4 Audit**: Flags unassociated EIPs and EIPs on stopped EC2 instances ($3.65/mo each). Skips BYOIP customer pools (`PublicIpv4Pool != "amazon"`).
* **True NAT Gateway Cost**: Combines NAT base ($32.85/mo) + allocated public IPv4 ($3.65/mo) = **$36.50/month**.
* **Route Table Cross-Referencing**:
  * *Orphaned NATs*: 0 route tables route to the NAT $\to$ `HIGH` severity, `Low` effort (safe to delete immediately).
  * *Idle NATs*: Batches CloudWatch traffic over 14 days ($< 10\text{ MB}$ threshold) and explicitly lists pointing route tables (`rtb-xxx`) in the recommendation.
* **Free S3/DynamoDB Gateway Endpoints**: Recommends free Gateway Endpoints to route S3/DynamoDB traffic internally, bypassing the $0.045/GB NAT data processing fee.
* **Honest ENI Pricing**: Reports unattached ENIs as **$0.00 hygiene findings** to prevent private IP exhaustion, while catching unattached ENIs holding billed Elastic IPs.
* **PrivateLink Interface Endpoints**: Flags idle endpoints with 0 bytes processed saving **$7.30/AZ-month**.
* **Site-to-Site VPNs**: Flags idle VPN connections with 0 tunnel traffic saving **$36.50/month**.

---

## 💻 CLI Usage & Commands

### Prerequisites
* Python 3.9+
* AWS credentials configured via `~/.aws/credentials`, `~/.aws/config`, or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).

### Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Basic Scans
```bash
# Scan default services in current region with high-contrast visual cards (default)
./venv/bin/python aws_cost_optimizer.py

# Scan specific services in a specific region
./venv/bin/python aws_cost_optimizer.py --services ec2,ebs,rds,vpc,s3 --regions us-east-1

# Display findings in a responsive, auto-wrapping grid table
./venv/bin/python aws_cost_optimizer.py --format table
```

### Multi-Region & High-Throughput Scans
```bash
# Automatically discover and scan all enabled regions in the account concurrently
./venv/bin/python aws_cost_optimizer.py --all-regions --threads 12

# Scan with an AWS named profile
./venv/bin/python aws_cost_optimizer.py --profile production --regions us-east-1,us-west-2
```

### Report Exports
```bash
# Export all findings to a CSV spreadsheet
./venv/bin/python aws_cost_optimizer.py --output cost_audit.csv

# Export findings as machine-readable JSON
./venv/bin/python aws_cost_optimizer.py --format json --output cost_audit.json
```

---

## ⚙️ Configuration Reference

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
| `AICO_RDS_IDLE_CONN` | `0` | Database connection threshold for idle RDS instances (`<=`) |
| `AICO_RDS_SNAPSHOT_DAYS` | `30` | Minimum age in days for manual RDS snapshots before auditing |
| `AICO_LAMBDA_DAYS` | `90` | Inactivity window in days for Lambda invocations |
| `AICO_LAMBDA_MIN_SAVINGS`| `0.50` | Minimum monthly savings threshold before surfacing a Lambda finding |
| `AICO_CW_HIGH_INGEST_GB` | `20.0` | Monthly ingestion threshold (GB) to evaluate CloudWatch Infrequent Access |
| `AICO_KMS_LOOKBACK_DAYS` | `90` | Lookback window for checking CloudTrail KMS crypto operations |
| `AICO_NAT_TRAFFIC_MB` | `10.0` | 14-day data transfer threshold (MB) to classify a NAT Gateway as idle |
| `AICO_S3_COLD_FRACTION` | `0.50` | Assumed fraction of S3 Standard data eligible for Standard-IA migration |
| `AICO_S3_MIN_SAVINGS` | `1.00` | Minimum monthly savings threshold for S3 findings to drop noise |

---

## 🧪 Testing & Verification

The test suite validates pricing math, CloudWatch batch paginators, guardrails, and error resilience without incurring any AWS charges.

Run the test suite using `pytest`:
```bash
PYTHONPATH=. ./venv/bin/pytest tests/test_aws_cost_optimizer.py
```
```
============================== 21 passed in 0.20s ==============================
```

---

## 🛡️ Safety & Reliability Principles

1. **Strictly Read-Only**: The engine performs zero write, update, delete, or terminate operations.
2. **Infrastructure-as-Code First**: When resources are managed by CloudFormation, AWS CDK, AWS SAM, Serverless Framework, or Kubernetes Controllers, findings instruct operators to update the source template.
3. **Grace Periods**: New resources (instances, NATs, S3 buckets, functions younger than 3–7 days) are automatically bypassed to allow CloudWatch metrics to stabilize and avoid false positives on new deployments.
4. **Data Protection Safeguards**: Always recommends a final snapshot before database/volume decommissioning, warns of the automatic 7-day RDS restart, and provides a 3-step safety procedure before KMS key deletion.
