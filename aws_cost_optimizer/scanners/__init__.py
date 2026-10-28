from typing import Dict, List, Type

from aws_cost_optimizer.scanners.base import BaseScanner
from aws_cost_optimizer.scanners.cloudwatch import CloudWatchScanner
from aws_cost_optimizer.scanners.dynamodb import DynamoDBScanner
from aws_cost_optimizer.scanners.ebs import EBSScanner
from aws_cost_optimizer.scanners.ec2 import EC2Scanner
from aws_cost_optimizer.scanners.elb import ELBScanner
from aws_cost_optimizer.scanners.kms import KMSScanner
from aws_cost_optimizer.scanners.lambda_func import LambdaScanner
from aws_cost_optimizer.scanners.rds import RDSScanner
from aws_cost_optimizer.scanners.s3 import S3Scanner
from aws_cost_optimizer.scanners.vpc import VPCScanner

ALL_SCANNERS: Dict[str, Type[BaseScanner]] = {
    "ec2": EC2Scanner,
    "ebs": EBSScanner,
    "vpc": VPCScanner,
    "elb": ELBScanner,
    "rds": RDSScanner,
    "s3": S3Scanner,
    "lambda": LambdaScanner,
    "cloudwatch": CloudWatchScanner,
    "kms": KMSScanner,
    "dynamodb": DynamoDBScanner,
}


def get_available_services() -> List[str]:
    return list(ALL_SCANNERS.keys())


def get_scanner(service_name: str) -> BaseScanner:
    service_name = service_name.lower().strip()
    if service_name not in ALL_SCANNERS:
        raise ValueError(f"Unknown service '{service_name}'. Available services: {', '.join(get_available_services())}")
    return ALL_SCANNERS[service_name]()
