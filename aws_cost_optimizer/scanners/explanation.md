1. End-to-End Architecture & File Flow
Execution Flow Step-by-Step
Invocation: You execute aws_cost_optimizer.py (which calls aws_cost_optimizer.cli:main).
Configuration & Credentials:
CLI flags are parsed (--services, --regions, --all-regions, --threads, --output).
aws_cost_optimizer/config.py loads configurable thresholds (CPU idle %, snapshot age days, pricing constants).
boto3.Session initializes credentials via the standard AWS provider chain (Environment variables 
→
→ ~/.aws/credentials 
→
→ IAM Role).
Region Discovery:
If --all-regions is supplied, it calls ec2:DescribeRegions(AllRegions=False) to fetch only the active, enabled regions in your account.
Concurrent ThreadPool Execution:
Instead of scanning sequentially (which can take 10+ minutes over multiple regions), ThreadPoolExecutor(max_workers=threads) executes tasks in parallel.
For global services (like S3), it executes a single task. For regional services (EC2, EBS, RDS, etc.), it spawns a worker per (service, region) tuple.
Adaptive Retry Client:
Each scanner invokes BaseScanner.get_client(), which configures botocore.config.Config(retries={'mode': 'adaptive', 'max_attempts': 5}). This automatically handles AWS CloudWatch rate limits and throttling via exponential backoff.
Findings Aggregation & Reporting:
Every waste item produces a standardized Finding dataclass.
Findings are funneled into the reporters:
Console: Displays categorized findings with priority badges and an executive summary table.
CSV / JSON: If --output <filename> is provided, it exports an audit file.


2. Service-by-Service Deep Dive

Below is the breakdown of what each service file inspects, how it retrieves data via boto3, and how estimated monthly savings are calculated.

1. Amazon EC2 (scanners/ec2.py)
AWS APIs Called:
ec2.get_paginator('describe_instances')
cw.get_metric_statistics(Namespace='AWS/EC2', MetricName='CPUUtilization')
Waste Patterns Detected:
Stopped Instances (State == 'stopped'): Stopped instances stop compute billing, but their attached root EBS volumes and static allocations continue accumulating costs every hour.
Previous-Generation Instances (t2.*, m4.*, c4.*, r4.*): Older instance families cost ~10% to 20% more per hour than modern equivalent families (t3, m5) and up to 40% more than AWS Graviton (t4g, m6g).
Idle Instances (CPU < 5%): Samples average CPU utilization over the configured lookback window (CONFIG.METRIC_LOOKBACK_DAYS = 14 days). Instances hovering under 5% CPU are flagged for downsizing or automated stopping.
Estimated Savings: ~$25–$40/month per instance.

2. Amazon EBS (scanners/ebs.py)
AWS APIs Called:
ec2.get_paginator('describe_volumes')
ec2.get_paginator('describe_snapshots') (filtering OwnerIds=['self'])
Waste Patterns Detected:
Unattached Volumes (State == 'available' or Attachments == []): When an EC2 instance is terminated without DeleteOnTermination=True, its EBS volume remains orphaned. AWS bills full storage rates forever until manually deleted.
Legacy gp2 Volumes: gp3 is 20% cheaper per GB than gp2 ($0.08/GB vs $0.10/GB) and includes 3,000 baseline IOPS and 125 MB/s throughput for free without having to scale volume size. The conversion can be done in-place with zero downtime using AWS Elastic Volumes.
Stale Snapshots: Backups older than 90 days (age_days > 90) created manually or left behind from decommissioned workloads ($0.05/GB/month).
Estimated Savings:
Monthly Saving
gp2
→
gp3
=
Size
GB
×
$
0.02
/
GB
Monthly Saving
gp2→gp3
	​

=Size
GB
	​

×$0.02/GB
Monthly Saving
orphaned
=
Size
GB
×
$
0.08
/
GB
Monthly Saving
orphaned
	​

=Size
GB
	​

×$0.08/GB

3. Amazon VPC & Networking (scanners/vpc.py)
AWS APIs Called:
ec2.describe_addresses() (Elastic IPs)
ec2.describe_nat_gateways()
cw.get_metric_statistics(Namespace='AWS/NATGateway', MetricName='BytesOutToDestination')
ec2.describe_network_interfaces() (ENIs)
Waste Patterns Detected:
Unassociated Elastic IPs: An allocated Elastic IP that has no AssociationId incurs an hourly fee ($0.005/hr = $3.65/month).
Idle NAT Gateways: NAT Gateways cost $0.045/hr base ($32.85/month) before data processing charges. If traffic processed over 7 days is under 10 MB, it is flagged as idle. (Recommendation: replace with free Gateway VPC Endpoints for S3/DynamoDB).
Unattached ENIs: Network interfaces in available state without attachment.

4. Elastic Load Balancing (scanners/elb.py)
AWS APIs Called:
elb.describe_load_balancers() (Classic v1)
elbv2.describe_load_balancers(), describe_target_groups(), describe_target_health()
Waste Patterns Detected:
Classic Load Balancers (CLBs): Deprecated v1 load balancers that should be migrated to modern ALBs/NLBs.
Empty / Idle Load Balancers: ALBs or NLBs with zero registered targets, or where all target groups have zero healthy hosts. These incur a base charge of ~$0.0225/hr ($16.42–$22.50/month) plus LCU charges while serving no traffic.

5. Amazon RDS (scanners/rds.py)
AWS APIs Called:
rds.get_paginator('describe_db_instances')
cw.get_metric_statistics(Namespace='AWS/RDS', MetricName='DatabaseConnections')
rds.get_paginator('describe_db_snapshots')
Waste Patterns Detected:
Multi-AZ on Non-Production Instances: Checks if MultiAZ == True on databases tagged with env: dev, test, or staging. Multi-AZ doubles instance and storage costs. Converting dev databases to Single-AZ cuts costs by 50% (~$75+/month).
Zero Database Connections: Queries CloudWatch DatabaseConnections metric (Maximum over 14 days). If maximum active connections equals 0, the database is abandoned.
Previous-Generation DB Classes: db.t2.* or db.m4.* flagged for Graviton (db.t4g.*) upgrades.
Aged Manual DB Snapshots: Manual snapshots older than 30 days ($0.095/GB/month).

6. Amazon S3 (scanners/s3.py)
AWS APIs Called:
s3.list_buckets(), s3.get_bucket_location()
s3.get_bucket_lifecycle_configuration()
s3.get_bucket_versioning()
Waste Patterns Detected:
Missing Lifecycle Policies: Buckets with no lifecycle rules to transition objects to S3 Standard-IA, Glacier Instant Retrieval, or Glacier Flexible Archive.
Missing AbortIncompleteMultipartUpload: When large file uploads fail or are canceled midway, parts remain hidden in S3 storage indefinitely unless an abort rule (e.g. 7 days) is configured.
Unmanaged Versioning: Buckets with versioning enabled but no NoncurrentVersionExpiration rule, leading to duplicate storage accumulation for every edited or overwritten object.

7. AWS Lambda (scanners/lambda_func.py)
AWS APIs Called:
lambda.get_paginator('list_functions')
cw.get_metric_statistics(Namespace='AWS/Lambda', MetricName='Invocations')
Waste Patterns Detected:
Architecture Migration (x86_64 
→
→ arm64 Graviton2): Flags functions running on x86 that can be converted to ARM64 for an instant 20% compute savings.
Inactive Functions: Functions with 0 invocations over the last 30 days.
High Memory Allocation: Functions allocated 
>
1024
 MB
>1024 MB that may be overprovisioned.

8. CloudWatch Logs (scanners/cloudwatch.py)
AWS APIs Called:
logs.get_paginator('describe_log_groups')
Waste Patterns Detected:
"Never Expire" Log Groups (retentionInDays is None): By default, AWS CloudWatch stores logs indefinitely at $0.03/GB/month. Development and staging log groups often accumulate hundreds of gigabytes over time. Setting retention to 30, 60, or 90 days prevents runaway storage costs.

9. AWS KMS (scanners/kms.py)
AWS APIs Called:
kms.get_paginator('list_keys'), kms.describe_key()
Waste Patterns Detected:
Disabled or Unused Customer Managed Keys (CMKs): AWS charges $1.00/month per Customer Managed Key. If a key is disabled or older than 1 year and no longer referenced by applications, it can be scheduled for deletion.

3. What Makes This Production-Grade
Adaptive Retries & Exponential Backoff: Uses botocore.config.Config(retries={'mode': 'adaptive', 'max_attempts': 5}) to prevent throttling errors on high-volume accounts.
True Concurrency: ThreadPoolExecutor parallelizes API queries across all AWS services and regions simultaneously.
Externalized Config: Thresholds (lookback days, CPU %, snapshot age, pricing rates) live in config.py and can be overridden via environment variables without changing code.
Rich Export Formats:
Terminal summary table with executive KPIs.
Interactive HTML Dashboard (html_report.py) ready for executive review.
Standard CSV and JSON files for integration with FinOps spreadsheets or Slack/Jira automations.
Unit Tested: Fully covered with automated tests in tests/test_aws_cost_optimizer.py.