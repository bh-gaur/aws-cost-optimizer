#!/usr/bin/env python3
"""
Convenience entry point for AWS Cost Optimizer.
Usage:
  python aws_cost_optimizer.py --help
  python aws_cost_optimizer.py --services ec2,ebs,rds --region us-east-1
"""
from aws_cost_optimizer.cli import main

if __name__ == "__main__":
    main()
