import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set, Tuple

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


class VPCScanner(BaseScanner):
    """
    Production-Grade AWS VPC & Networking Cost & Architecture Scanner.

    Comprehensive Audit Areas:
    1. Elastic IPs (EIPs) & Public IPv4 Charges:
       - Audits all public IPv4 addresses charged at $0.005/hr ($3.65/mo) since Feb 2024.
       - Detects unassociated EIPs.
       - Detects EIPs associated with stopped EC2 instances.
       - Skips BYOIP (Bring Your Own IP) customer pools which are exempt from IPv4 fees.
       - Prevents double-counting across NAT Gateways and ENIs.
    2. NAT Gateways (Base $32.85/mo + EIP $3.65/mo = $36.50/mo):
       - Route Table Analysis: identifies truly orphaned NATs (zero VPC route tables point to them).
       - Traffic Analysis: batches CloudWatch metrics (BytesOutToDestination, BytesInFromDestination,
         and ActiveConnectionCount) over 14 days to identify idle NATs.
       - Age Guard: skips NATs provisioned within the last 7 days.
       - Redundant Multi-AZ NATs: identifies dev/test/staging VPCs with multiple NAT Gateways
         where multi-AZ high availability is unnecessary cost.
    3. Missing Free Gateway Endpoints (S3 & DynamoDB):
       - Identifies VPCs with active NAT Gateways that lack free Gateway VPC Endpoints for S3/DynamoDB.
       - Eliminates unnecessary $0.045/GB NAT data processing charges for AWS API traffic.
    4. Network Interfaces (ENIs):
       - Honest pricing: unattached ENIs incur $0 storage charge (eliminates invented $1 saving).
       - Flags orphaned ENIs for IP exhaustion hygiene and governance.
       - Catches available ENIs that still hold a billed Elastic IP.
       - Filters out AWS service-managed interfaces (Lambda, ELB, RDS, EKS).
    5. AWS PrivateLink Interface Endpoints ($7.30/AZ-month):
       - Audits interface endpoints across AZs for zero traffic (BytesProcessed = 0 over 14 days).
    6. Site-to-Site VPN Connections ($36.50/month):
       - Audits available VPN connections with zero tunnel data transfer.
    """

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

        now = datetime.now(timezone.utc)
        counted_eips: Set[str] = set()
        active_nat_vpc_ids: Set[str] = set()

        # 1. Elastic IPs & Public IPv4
        eip_findings, counted_eips = self._scan_elastic_ips(ec2, region, counted_eips)
        findings.extend(eip_findings)

        # 2. NAT Gateways
        nat_findings, nat_vpc_ids, counted_eips = self._scan_nat_gateways(
            ec2, cw, region, now, counted_eips
        )
        findings.extend(nat_findings)
        active_nat_vpc_ids.update(nat_vpc_ids)

        # 3. Missing S3/DynamoDB Gateway Endpoints in VPCs with NAT
        if active_nat_vpc_ids:
            gw_findings = self._scan_missing_gateway_endpoints(ec2, region, active_nat_vpc_ids)
            findings.extend(gw_findings)

        # 4. Unattached Network Interfaces (ENIs)
        eni_findings, counted_eips = self._scan_network_interfaces(ec2, region, counted_eips)
        findings.extend(eni_findings)

        # 5. Idle Interface VPC Endpoints (AWS PrivateLink)
        privatelink_findings = self._scan_interface_endpoints(ec2, cw, region, now)
        findings.extend(privatelink_findings)

        # 6. Idle Site-to-Site VPN Connections
        vpn_findings = self._scan_vpn_connections(ec2, cw, region, now)
        findings.extend(vpn_findings)

        return findings

    # -------------------------------------------------------------------------
    # 1. Elastic IP Addresses & Public IPv4
    # -------------------------------------------------------------------------
    def _scan_elastic_ips(
        self, ec2: Any, region: str, counted_eips: Set[str]
    ) -> Tuple[List[Finding], Set[str]]:
        findings: List[Finding] = []
        try:
            addresses = ec2.describe_addresses().get("Addresses", [])
        except ClientError as ce:
            self.handle_client_error(ce, f"Elastic IPs in {region}")
            return findings, counted_eips

        unassociated_eips: List[Dict[str, Any]] = []
        stopped_instance_eips: List[Dict[str, Any]] = []
        instance_ids_to_check: Set[str] = set()
        eip_to_instance: Dict[str, Dict[str, Any]] = {}

        for addr in addresses:
            alloc_id = addr.get("AllocationId", addr.get("PublicIp", "unknown"))
            public_ip = addr.get("PublicIp", "")
            pool = addr.get("PublicIpv4Pool", "amazon")

            # Skip BYOIP pools (not charged the standard AWS IPv4 fee)
            if pool != "amazon" and not str(pool).startswith("amazon"):
                continue

            assoc_id = addr.get("AssociationId")
            instance_id = addr.get("InstanceId")
            eni_id = addr.get("NetworkInterfaceId")

            if not assoc_id and not instance_id and not eni_id:
                unassociated_eips.append(
                    {"allocation_id": alloc_id, "public_ip": public_ip, "raw": addr}
                )
            elif instance_id:
                instance_ids_to_check.add(instance_id)
                eip_to_instance[instance_id] = {
                    "allocation_id": alloc_id,
                    "public_ip": public_ip,
                    "raw": addr,
                }

        # Check instance states for EIPs attached to EC2 instances
        if instance_ids_to_check:
            stopped_instances = self._fetch_stopped_instances(ec2, list(instance_ids_to_check))
            for iid in stopped_instances:
                if iid in eip_to_instance:
                    stopped_instance_eips.append(eip_to_instance[iid])

        monthly_rate = CONFIG.VPC_PUBLIC_IPV4_HOURLY_COST * 730  # ~$3.65/month

        # Findings for unassociated EIPs
        if unassociated_eips:
            if len(unassociated_eips) <= 2:
                for item in unassociated_eips:
                    alloc_id = item["allocation_id"]
                    ip = item["public_ip"]
                    counted_eips.add(alloc_id)
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=alloc_id,
                            resource_name=ip,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="High",
                            issue=f"Unassociated Elastic IP ({ip}) incurring idle IPv4 charge ($0.005/hr)",
                            recommendation="Release the unassociated Elastic IP address via ec2.release_address().",
                            estimated_monthly_saving=round(monthly_rate, 2),
                            metadata={"public_ip": ip, "allocation_id": alloc_id},
                        )
                    )
            else:
                total_saving = len(unassociated_eips) * monthly_rate
                ip_list = [item["public_ip"] for item in unassociated_eips]
                alloc_list = [item["allocation_id"] for item in unassociated_eips]
                for aid in alloc_list:
                    counted_eips.add(aid)

                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=f"eip-unassociated-summary-{region}",
                        resource_name=f"{len(unassociated_eips)} Unassociated EIPs",
                        region=region,
                        severity=Severity.HIGH,
                        effort="Low",
                        confidence="High",
                        issue=f"{len(unassociated_eips)} unassociated Elastic IPs incurring idle IPv4 charges ($0.005/hr each)",
                        recommendation="Release unassociated Elastic IP addresses via ec2.release_address() to eliminate unnecessary charges.",
                        estimated_monthly_saving=round(total_saving, 2),
                        metadata={"count": len(unassociated_eips), "public_ips": ip_list, "allocation_ids": alloc_list},
                    )
                )

        # Findings for EIPs attached to stopped instances
        for item in stopped_instance_eips:
            alloc_id = item["allocation_id"]
            ip = item["public_ip"]
            iid = item["raw"].get("InstanceId", "")
            counted_eips.add(alloc_id)
            findings.append(
                Finding(
                    service=self.display_name,
                    resource_id=alloc_id,
                    resource_name=ip,
                    region=region,
                    severity=Severity.MEDIUM,
                    effort="Low",
                    confidence="High",
                    issue=f"Elastic IP ({ip}) attached to stopped EC2 instance ({iid}) incurring IPv4 hourly charge",
                    recommendation=f"Disassociate Elastic IP from stopped instance ({iid}), or terminate instance if no longer needed.",
                    estimated_monthly_saving=round(monthly_rate, 2),
                    metadata={"public_ip": ip, "instance_id": iid, "allocation_id": alloc_id},
                )
            )

        return findings, counted_eips

    def _fetch_stopped_instances(self, ec2: Any, instance_ids: List[str]) -> Set[str]:
        """Queries describe_instances in chunks of 100 to find instances in 'stopped' state."""
        stopped: Set[str] = set()
        chunk_size = 100
        for i in range(0, len(instance_ids), chunk_size):
            chunk = instance_ids[i : i + chunk_size]
            try:
                res = ec2.describe_instances(InstanceIds=chunk)
                for resv in res.get("Reservations", []):
                    for inst in resv.get("Instances", []):
                        if inst.get("State", {}).get("Name") == "stopped":
                            stopped.add(inst.get("InstanceId"))
            except ClientError as ce:
                self.handle_client_error(ce, "describe_instances for EIP state check")
        return stopped

    # -------------------------------------------------------------------------
    # 2. NAT Gateways
    # -------------------------------------------------------------------------
    def _scan_nat_gateways(
        self, ec2: Any, cw: Any, region: str, now: datetime, counted_eips: Set[str]
    ) -> Tuple[List[Finding], Set[str], Set[str]]:
        findings: List[Finding] = []
        nat_vpc_ids: Set[str] = set()

        try:
            nat_gateways = ec2.describe_nat_gateways().get("NatGateways", [])
        except ClientError as ce:
            self.handle_client_error(ce, f"NAT Gateways in {region}")
            return findings, nat_vpc_ids, counted_eips

        available_nats = [n for n in nat_gateways if n.get("State") == "available"]
        if not available_nats:
            return findings, nat_vpc_ids, counted_eips

        # Mark active NAT VPCs and track their EIPs
        for nat in available_nats:
            vpc_id = nat.get("VpcId")
            if vpc_id:
                nat_vpc_ids.add(vpc_id)
            for addr in nat.get("NatGatewayAddresses", []):
                aid = addr.get("AllocationId")
                if aid:
                    counted_eips.add(aid)

        # 1. Fetch Route Tables to check if any route table routes to each NAT
        nat_to_routes, vpc_to_routes = self._fetch_route_table_mappings(ec2, region)

        # 2. Fetch VPC metadata (for non-prod detection)
        vpc_metadata = self._fetch_vpc_metadata(ec2, list(nat_vpc_ids), region)

        # Group NATs by VPC
        vpc_to_nats: Dict[str, List[Dict[str, Any]]] = {}
        for nat in available_nats:
            v_id = nat.get("VpcId", "unknown")
            vpc_to_nats.setdefault(v_id, []).append(nat)

        # Monthly total cost for a NAT Gateway = base hourly ($32.85) + public IPv4 ($3.65) = ~$36.50
        nat_monthly_saving = (
            CONFIG.VPC_NAT_GATEWAY_HOURLY_BASE + CONFIG.VPC_PUBLIC_IPV4_HOURLY_COST
        ) * 730

        nats_to_metric_check: List[Dict[str, Any]] = []
        handled_nat_ids: Set[str] = set()

        for nat in available_nats:
            nat_id = nat.get("NatGatewayId")
            vpc_id = nat.get("VpcId", "")

            # Age Guard: Skip NATs created within the last 7 days
            create_time = nat.get("CreateTime")
            if create_time and (now - create_time).days < 7:
                handled_nat_ids.add(nat_id)
                continue

            # Check if any route table routes to this NAT Gateway
            pointing_routes = nat_to_routes.get(nat_id, [])
            if not pointing_routes:
                # 100% Orphaned NAT Gateway - safe to delete immediately!
                handled_nat_ids.add(nat_id)
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=nat_id,
                        resource_name=vpc_id,
                        region=region,
                        severity=Severity.HIGH,
                        effort="Low",
                        confidence="High",
                        issue=f"Orphaned NAT Gateway ({nat_id}) with zero VPC route tables directing traffic to it",
                        recommendation="Delete the orphaned NAT Gateway. No subnets or route tables route traffic through it, so deletion causes zero traffic disruption and releases its Elastic IP.",
                        estimated_monthly_saving=round(nat_monthly_saving, 2),
                        metadata={"vpc_id": vpc_id, "nat_gateway_id": nat_id, "orphan": True},
                    )
                )
            else:
                nats_to_metric_check.append(nat)

        # Query metrics for NATs that have routes pointing to them
        if nats_to_metric_check:
            lookback_days = CONFIG.METRIC_LOOKBACK_DAYS
            start_time = now - timedelta(days=lookback_days)
            metrics = self._fetch_batched_nat_metrics(
                cw, [n.get("NatGatewayId") for n in nats_to_metric_check], start_time, now
            )

            for nat in nats_to_metric_check:
                nat_id = nat.get("NatGatewayId")
                vpc_id = nat.get("VpcId", "")
                pointing_routes = nat_to_routes.get(nat_id, [])

                data = metrics.get(nat_id, {"bytes_out": 0.0, "bytes_in": 0.0, "active_conn": 0.0})
                total_bytes = data["bytes_out"] + data["bytes_in"]
                total_mb = total_bytes / (1024 * 1024)
                avg_conn = data["active_conn"]

                if total_mb < CONFIG.VPC_NAT_IDLE_TRAFFIC_MB_THRESHOLD and avg_conn < 1.0:
                    handled_nat_ids.add(nat_id)
                    rtb_str = ", ".join(pointing_routes[:3])
                    if len(pointing_routes) > 3:
                        rtb_str += f" (+{len(pointing_routes) - 3} more)"

                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=nat_id,
                            resource_name=vpc_id,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Medium",
                            confidence="High",
                            issue=f"Idle NAT Gateway ({nat_id}) processed only {total_mb:.2f} MB across past {lookback_days} days (avg {avg_conn:.1f} active conn)",
                            recommendation=f"Route table(s) [{rtb_str}] route default traffic (0.0.0.0/0) to this NAT. Verify workload internet egress needs, update route tables, and delete the NAT Gateway. Consider free Gateway VPC Endpoints for S3/DynamoDB.",
                            estimated_monthly_saving=round(nat_monthly_saving, 2),
                            metadata={
                                "vpc_id": vpc_id,
                                "traffic_mb": round(total_mb, 2),
                                "active_connections": round(avg_conn, 2),
                                "route_tables": pointing_routes,
                            },
                        )
                    )

        # Check for Redundant Multi-AZ NAT Gateways in Non-Production VPCs
        for vpc_id, nats in vpc_to_nats.items():
            is_non_prod = vpc_metadata.get(vpc_id, {}).get("is_non_prod", False)
            if is_non_prod and len(nats) > 1:
                # Flag NATs beyond the first one that weren't already flagged
                unflagged_nats = [n for n in nats if n.get("NatGatewayId") not in handled_nat_ids]
                # If all were unflagged, leave 1 active and flag the rest as redundant
                redundant_nats = unflagged_nats[1:] if len(unflagged_nats) == len(nats) else unflagged_nats

                for red_nat in redundant_nats:
                    r_id = red_nat.get("NatGatewayId")
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=r_id,
                            resource_name=vpc_id,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Medium",
                            confidence="High",
                            issue=f"Redundant NAT Gateway in non-production VPC ({vpc_id}) with {len(nats)} NAT Gateways",
                            recommendation=f"Non-production VPC ({vpc_id}) has multiple NAT Gateways for multi-AZ redundancy. Consolidate private subnets to route through a single shared NAT Gateway to save $36.50/mo per decommissioned NAT.",
                            estimated_monthly_saving=round(nat_monthly_saving, 2),
                            metadata={"vpc_id": vpc_id, "total_nats_in_vpc": len(nats)},
                        )
                    )

        return findings, nat_vpc_ids, counted_eips

    def _fetch_route_table_mappings(
        self, ec2: Any, region: str
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """Maps NAT Gateway ID to route table IDs, and VPC ID to route table IDs."""
        nat_to_routes: Dict[str, List[str]] = {}
        vpc_to_routes: Dict[str, List[str]] = {}
        try:
            paginator = ec2.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                for rtb in page.get("RouteTables", []):
                    rtb_id = rtb.get("RouteTableId", "")
                    vpc_id = rtb.get("VpcId", "")
                    if vpc_id:
                        vpc_to_routes.setdefault(vpc_id, []).append(rtb_id)

                    for route in rtb.get("Routes", []):
                        nat_id = route.get("NatGatewayId")
                        if nat_id:
                            nat_to_routes.setdefault(nat_id, []).append(rtb_id)
        except ClientError as ce:
            self.handle_client_error(ce, f"Route tables in {region}")
        return nat_to_routes, vpc_to_routes

    def _fetch_vpc_metadata(
        self, ec2: Any, vpc_ids: List[str], region: str
    ) -> Dict[str, Dict[str, Any]]:
        """Checks VPC tags and names for non-production keywords."""
        meta: Dict[str, Dict[str, Any]] = {}
        if not vpc_ids:
            return meta
        try:
            vpcs = ec2.describe_vpcs(VpcIds=vpc_ids).get("Vpcs", [])
            for v in vpcs:
                v_id = v.get("VpcId")
                tags = {t.get("Key", ""): t.get("Value", "") for t in v.get("Tags", [])}
                is_non_prod = False
                for k, val in tags.items():
                    k_lower = k.lower()
                    val_lower = val.lower()
                    if k_lower in ENV_TAG_KEYS:
                        if val_lower in NON_PROD_TOKENS:
                            is_non_prod = True
                            break
                        # Also check if token is part of a compound string like "dev-vpc" or "test_env"
                        for token in NON_PROD_TOKENS:
                            if re.search(rf"\b{re.escape(token)}\b", val_lower):
                                is_non_prod = True
                                break
                    if is_non_prod:
                        break
                meta[v_id] = {"is_non_prod": is_non_prod, "tags": tags}
        except ClientError as ce:
            self.handle_client_error(ce, f"describe_vpcs in {region}")
        return meta

    def _fetch_batched_nat_metrics(
        self, cw: Any, nat_ids: List[str], start_time: datetime, end_time: datetime
    ) -> Dict[str, Dict[str, float]]:
        """
        Batches CloudWatch get_metric_data calls for NAT Gateway traffic and connections:
        - BytesOutToDestination (Sum)
        - BytesInFromDestination (Sum)
        - ActiveConnectionCount (Average)
        """
        results: Dict[str, Dict[str, float]] = {
            nid: {"bytes_out": 0.0, "bytes_in": 0.0, "active_conn": 0.0} for nid in nat_ids
        }
        if not nat_ids:
            return results

        chunk_size = 80  # 3 queries * 80 = 240 queries per get_metric_data call
        for i in range(0, len(nat_ids), chunk_size):
            chunk = nat_ids[i : i + chunk_size]
            queries: List[Dict[str, Any]] = []
            id_map: Dict[str, Tuple[str, str]] = {}

            for idx, nid in enumerate(chunk):
                q_out = f"m_out_{idx}"
                q_in = f"m_in_{idx}"
                q_conn = f"m_conn_{idx}"

                id_map[q_out] = (nid, "bytes_out")
                id_map[q_in] = (nid, "bytes_in")
                id_map[q_conn] = (nid, "active_conn")

                queries.append(
                    {
                        "Id": q_out,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/NATGateway",
                                "MetricName": "BytesOutToDestination",
                                "Dimensions": [{"Name": "NatGatewayId", "Value": nid}],
                            },
                            "Period": 86400,
                            "Stat": "Sum",
                        },
                    }
                )
                queries.append(
                    {
                        "Id": q_in,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/NATGateway",
                                "MetricName": "BytesInFromDestination",
                                "Dimensions": [{"Name": "NatGatewayId", "Value": nid}],
                            },
                            "Period": 86400,
                            "Stat": "Sum",
                        },
                    }
                )
                queries.append(
                    {
                        "Id": q_conn,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/NATGateway",
                                "MetricName": "ActiveConnectionCount",
                                "Dimensions": [{"Name": "NatGatewayId", "Value": nid}],
                            },
                            "Period": 86400,
                            "Stat": "Average",
                        },
                    }
                )

            try:
                paginator = cw.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=queries, StartTime=start_time, EndTime=end_time
                ):
                    for res in page.get("MetricDataResults", []):
                        qid = res.get("Id")
                        if qid in id_map:
                            nid, metric_key = id_map[qid]
                            values = res.get("Values", [])
                            if metric_key == "active_conn":
                                results[nid]["active_conn"] = (
                                    sum(values) / len(values) if values else 0.0
                                )
                            else:
                                results[nid][metric_key] = sum(values) if values else 0.0
            except ClientError as ce:
                self.handle_client_error(ce, "batch get_metric_data for NAT Gateways")

        return results

    # -------------------------------------------------------------------------
    # 3. Missing Gateway Endpoints (S3 & DynamoDB) in VPCs with NAT
    # -------------------------------------------------------------------------
    def _scan_missing_gateway_endpoints(
        self, ec2: Any, region: str, active_nat_vpc_ids: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        for vpc_id in active_nat_vpc_ids:
            try:
                endpoints = ec2.describe_vpc_endpoints(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                ).get("VpcEndpoints", [])

                gateway_services: Set[str] = set()
                for ep in endpoints:
                    if ep.get("VpcEndpointType") == "Gateway":
                        svc = ep.get("ServiceName", "")
                        if svc.endswith(".s3"):
                            gateway_services.add("s3")
                        elif svc.endswith(".dynamodb"):
                            gateway_services.add("dynamodb")

                missing: List[str] = []
                if "s3" not in gateway_services:
                    missing.append("S3")
                if "dynamodb" not in gateway_services:
                    missing.append("DynamoDB")

                if missing:
                    svc_names = " & ".join(missing)
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=f"vpce-missing-gw-{vpc_id}",
                            resource_name=vpc_id,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Low",
                            confidence="High",
                            issue=f"VPC ({vpc_id}) has NAT Gateway but is missing free Gateway VPC Endpoint for {svc_names}",
                            recommendation=f"Provision free Gateway VPC Endpoint(s) for {svc_names} in VPC {vpc_id} and associate with route tables. S3 and DynamoDB traffic will route directly without passing through the NAT Gateway, eliminating $0.045/GB NAT data processing charges.",
                            estimated_monthly_saving=0.0,
                            metadata={"vpc_id": vpc_id, "missing_endpoints": missing},
                        )
                    )
            except ClientError as ce:
                self.handle_client_error(ce, f"Gateway VPC endpoints for {vpc_id}")

        return findings

    # -------------------------------------------------------------------------
    # 4. Unattached Network Interfaces (ENIs)
    # -------------------------------------------------------------------------
    def _scan_network_interfaces(
        self, ec2: Any, region: str, counted_eips: Set[str]
    ) -> Tuple[List[Finding], Set[str]]:
        findings: List[Finding] = []
        try:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "status", "Values": ["available"]}]
            ).get("NetworkInterfaces", [])
        except ClientError as ce:
            self.handle_client_error(ce, f"ENIs in {region}")
            return findings, counted_eips

        for eni in enis:
            eni_id = eni.get("NetworkInterfaceId")
            description = eni.get("Description", "")
            interface_type = eni.get("InterfaceType", "interface")
            is_req_managed = eni.get("RequesterManaged", False)

            # Skip AWS service-managed interfaces (ELBs, RDS, Lambda, EKS)
            if is_req_managed or interface_type != "interface":
                continue

            # Skip common AWS managed patterns in description
            desc_lower = description.lower()
            if any(
                pattern in desc_lower
                for pattern in ["aws lambda", "elb", "eks", "nat gateway", "vpc endpoint"]
            ):
                continue

            # Check if ENI holds an associated Elastic IP
            association = eni.get("Association", {})
            public_ip = association.get("PublicIp")
            alloc_id = association.get("AllocationId")

            if public_ip and alloc_id:
                if alloc_id not in counted_eips:
                    counted_eips.add(alloc_id)
                    monthly_saving = CONFIG.VPC_PUBLIC_IPV4_HOURLY_COST * 730
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=eni_id,
                            resource_name=public_ip,
                            region=region,
                            severity=Severity.HIGH,
                            effort="Low",
                            confidence="High",
                            issue=f"Unattached Network Interface ({eni_id}) holds active Elastic IP ({public_ip}) incurring IPv4 charge",
                            recommendation=f"Disassociate and release Elastic IP {public_ip}, then delete the unattached ENI.",
                            estimated_monthly_saving=round(monthly_saving, 2),
                            metadata={
                                "eni_id": eni_id,
                                "public_ip": public_ip,
                                "allocation_id": alloc_id,
                            },
                        )
                    )
            else:
                # Standard unattached ENI: honest $0 storage charge, pure hygiene/governance
                subnet_id = eni.get("SubnetId", "")
                findings.append(
                    Finding(
                        service=self.display_name,
                        resource_id=eni_id,
                        resource_name=description or eni_id,
                        region=region,
                        severity=Severity.LOW,
                        effort="Low",
                        confidence="High",
                        issue=f"Unattached Network Interface ({eni_id}) in 'available' status",
                        recommendation=f"Delete unused ENI to prevent private IP exhaustion in subnet {subnet_id} and maintain clean networking hygiene. (ENIs incur $0 storage charges in AWS).",
                        estimated_monthly_saving=0.0,
                        metadata={
                            "eni_id": eni_id,
                            "subnet_id": subnet_id,
                            "description": description,
                            "billing_charge": False,
                        },
                    )
                )

        return findings, counted_eips

    # -------------------------------------------------------------------------
    # 5. Idle Interface VPC Endpoints (AWS PrivateLink)
    # -------------------------------------------------------------------------
    def _scan_interface_endpoints(
        self, ec2: Any, cw: Any, region: str, now: datetime
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            endpoints = ec2.describe_vpc_endpoints(
                Filters=[{"Name": "vpc-endpoint-type", "Values": ["Interface"]}]
            ).get("VpcEndpoints", [])
        except ClientError as ce:
            self.handle_client_error(ce, f"Interface VPC endpoints in {region}")
            return findings

        available_eps = [ep for ep in endpoints if ep.get("State") == "available"]
        if not available_eps:
            return findings

        start_time = now - timedelta(days=CONFIG.METRIC_LOOKBACK_DAYS)

        for ep in available_eps:
            ep_id = ep.get("VpcEndpointId")
            svc_name = ep.get("ServiceName", "unknown")
            subnets = ep.get("SubnetIds", [])
            num_azs = max(len(subnets), 1)

            # Age guard: skip endpoints provisioned within last 7 days
            create_time = ep.get("CreationTimestamp")
            if create_time and (now - create_time).days < 7:
                continue

            try:
                metric = cw.get_metric_statistics(
                    Namespace="AWS/PrivateLinkEndpoints",
                    MetricName="BytesProcessed",
                    Dimensions=[{"Name": "EndpointId", "Value": ep_id}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=86400 * CONFIG.METRIC_LOOKBACK_DAYS,
                    Statistics=["Sum"],
                )
                datapoints = metric.get("Datapoints", [])
                total_bytes = sum(d.get("Sum", 0.0) for d in datapoints) if datapoints else 0.0

                if total_bytes == 0.0:
                    monthly_saving = num_azs * CONFIG.VPC_INTERFACE_ENDPOINT_HOURLY_AZ * 730
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=ep_id,
                            resource_name=svc_name,
                            region=region,
                            severity=Severity.MEDIUM,
                            effort="Low",
                            confidence="High",
                            issue=f"Idle Interface VPC Endpoint ({svc_name}) with 0 bytes processed across {num_azs} AZ(s) in past {CONFIG.METRIC_LOOKBACK_DAYS} days",
                            recommendation=f"Delete unused Interface VPC Endpoint if private connectivity to {svc_name} is no longer required, saving $7.30/AZ/month.",
                            estimated_monthly_saving=round(monthly_saving, 2),
                            metadata={
                                "endpoint_id": ep_id,
                                "service_name": svc_name,
                                "num_azs": num_azs,
                            },
                        )
                    )
            except ClientError as ce:
                self.handle_client_error(ce, f"CloudWatch metrics for VPC Endpoint {ep_id}")

        return findings

    # -------------------------------------------------------------------------
    # 6. Idle Site-to-Site VPN Connections
    # -------------------------------------------------------------------------
    def _scan_vpn_connections(
        self, ec2: Any, cw: Any, region: str, now: datetime
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            vpns = ec2.describe_vpn_connections(
                Filters=[{"Name": "state", "Values": ["available"]}]
            ).get("VpnConnections", [])
        except ClientError as ce:
            self.handle_client_error(ce, f"VPN connections in {region}")
            return findings

        if not vpns:
            return findings

        start_time = now - timedelta(days=CONFIG.METRIC_LOOKBACK_DAYS)
        monthly_vpn_cost = CONFIG.VPC_VPN_HOURLY_BASE * 730  # ~$36.50/month

        for vpn in vpns:
            vpn_id = vpn.get("VpnConnectionId")
            try:
                # Query tunnel traffic
                m_in = cw.get_metric_statistics(
                    Namespace="AWS/VPN",
                    MetricName="TunnelDataIn",
                    Dimensions=[{"Name": "VpnId", "Value": vpn_id}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=86400 * CONFIG.METRIC_LOOKBACK_DAYS,
                    Statistics=["Sum"],
                )
                m_out = cw.get_metric_statistics(
                    Namespace="AWS/VPN",
                    MetricName="TunnelDataOut",
                    Dimensions=[{"Name": "VpnId", "Value": vpn_id}],
                    StartTime=start_time,
                    EndTime=now,
                    Period=86400 * CONFIG.METRIC_LOOKBACK_DAYS,
                    Statistics=["Sum"],
                )

                d_in = sum(d.get("Sum", 0.0) for d in m_in.get("Datapoints", []))
                d_out = sum(d.get("Sum", 0.0) for d in m_out.get("Datapoints", []))

                if (d_in + d_out) == 0.0:
                    findings.append(
                        Finding(
                            service=self.display_name,
                            resource_id=vpn_id,
                            resource_name=vpn.get("CustomerGatewayId", vpn_id),
                            region=region,
                            severity=Severity.HIGH,
                            effort="Medium",
                            confidence="High",
                            issue=f"Idle Site-to-Site VPN connection ({vpn_id}) with 0 bytes transferred across tunnels in past {CONFIG.METRIC_LOOKBACK_DAYS} days",
                            recommendation="Delete inactive Site-to-Site VPN connection to save $36.50/month ($0.05/hr base fee).",
                            estimated_monthly_saving=round(monthly_vpn_cost, 2),
                            metadata={"vpn_id": vpn_id, "data_transferred_bytes": 0.0},
                        )
                    )
            except ClientError as ce:
                self.handle_client_error(ce, f"VPN metrics for {vpn_id}")

        return findings
