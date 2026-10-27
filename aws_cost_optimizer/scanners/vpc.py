import logging
from datetime import datetime, timedelta, timezone
from typing import List
import boto3
from botocore.exceptions import ClientError
from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding, Severity
from aws_cost_optimizer.scanners.base import BaseScanner

logger = logging.getLogger("aws_cost_optimizer")


class VPCScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "vpc"

    @property
    def display_name(self) -> str:
        return "Amazon VPC & Networking"

    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ec2 = self.get_client(session, "ec2", region)
            cw = self.get_client(session, "cloudwatch", region)
        except Exception as e:
            logger.error(f"[VPC] Failed to initialize client in {region}: {e}")
            return findings

        # 1. Unassociated Elastic IP Addresses (EIPs)
        try:
            addresses = ec2.describe_addresses().get("Addresses", [])
            for addr in addresses:
                allocation_id = addr.get("AllocationId", addr.get("PublicIp", "unknown"))
                public_ip = addr.get("PublicIp", "")
                association_id = addr.get("AssociationId")

                if not association_id:
                    # AWS charges $0.005/hr for idle IPv4 addresses = ~$3.65/month
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=allocation_id,
                            resource_name=public_ip,
                            region=region,
                            severity=Severity.HIGH,
                            issue=f"Unattached Elastic IP ({public_ip}) incurring idle IPv4 hourly charge",
                            recommendation="Release the unassociated Elastic IP address",
                            estimated_monthly_saving=CONFIG.VPC_EIP_IDLE_HOURLY_COST * 730,
                            metadata={"public_ip": public_ip},
                        )
                    )
        except ClientError as ce:
            self.handle_client_error(ce, f"Elastic IPs in {region}")

        # 2. Idle NAT Gateways
        try:
            nat_gateways = ec2.describe_nat_gateways().get("NatGateways", [])
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=7)

            for nat in nat_gateways:
                nat_id = nat.get("NatGatewayId")
                state = nat.get("State")

                if state == "available":
                    try:
                        metric = cw.get_metric_statistics(
                            Namespace="AWS/NATGateway",
                            MetricName="BytesOutToDestination",
                            Dimensions=[{"Name": "NatGatewayId", "Value": nat_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=["Sum"],
                        )
                        datapoints = metric.get("Datapoints", [])
                        total_bytes = sum(d["Sum"] for d in datapoints) if datapoints else 0
                        total_mb = total_bytes / (1024 * 1024)

                        if total_mb < CONFIG.VPC_NAT_IDLE_TRAFFIC_MB_THRESHOLD:
                            findings.append(
                                Finding(
                                    service=self.display_name,
                                    resource_id=nat_id,
                                    resource_name=nat.get("VpcId", ""),
                                    region=region,
                                    severity=Severity.HIGH,
                                    issue=f"Idle NAT Gateway (processed only {total_mb:.2f} MB in the last 7 days)",
                                    recommendation="Delete the NAT Gateway or replace with Gateway VPC Endpoints (S3/DynamoDB) which are completely free",
                                    estimated_monthly_saving=CONFIG.VPC_NAT_GATEWAY_HOURLY_BASE * 730,
                                    metadata={"traffic_mb_7d": round(total_mb, 2)},
                                )
                            )
                    except ClientError as ce:
                        self.handle_client_error(ce, f"NAT Gateway CloudWatch metric for {nat_id}")
        except ClientError as ce:
            self.handle_client_error(ce, f"NAT Gateways in {region}")

        # 3. Unattached Elastic Network Interfaces (ENIs)
        try:
            enis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
            for eni in enis:
                eni_id = eni.get("NetworkInterfaceId")
                status = eni.get("Status")
                if status == "available":
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=eni_id,
                            resource_name=eni.get("Description", ""),
                            region=region,
                            severity=Severity.LOW,
                            issue="Unattached Network Interface (ENI) in 'available' status",
                            recommendation="Delete unused ENI to prevent accidental private IP exhaustion or lingering interface dependencies",
                            estimated_monthly_saving=1.0,
                            metadata={"status": status},
                        )
                    )
        except ClientError as ce:
            self.handle_client_error(ce, f"ENIs in {region}")

        return findings
