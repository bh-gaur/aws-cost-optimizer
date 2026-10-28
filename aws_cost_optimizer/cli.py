import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import sys
from typing import List, Tuple
import boto3
from botocore.exceptions import ClientError, ProfileNotFound

from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding
from aws_cost_optimizer.scanners import ALL_SCANNERS, get_available_services, get_scanner
from aws_cost_optimizer.reporters.console import print_console_report
from aws_cost_optimizer.reporters.csv_report import export_to_csv, export_to_json

logger = logging.getLogger("aws_cost_optimizer")


def configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def get_active_regions(session: boto3.Session) -> List[str]:
    """Retrieves all enabled EC2 regions for the account."""
    import os

    try:
        kwargs = {"region_name": "us-east-1"}
        endpoint_url = os.getenv("AWS_ENDPOINT_URL")
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        ec2 = session.client("ec2", **kwargs)
        resp = ec2.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in resp.get("Regions", [])]
    except Exception as e:
        logger.warning(f"Could not auto-detect regions ({e}), defaulting to ['us-east-1', 'us-west-2']")
        return ["us-east-1", "us-west-2"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Production AWS Cost Optimization Scanner (Service-by-Service)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aws_cost_optimizer.py --services ec2,ebs,rds
  python aws_cost_optimizer.py --profile my-profile --regions us-east-1,us-west-2
  python aws_cost_optimizer.py --all-regions --output cost_audit.csv
  python aws_cost_optimizer.py --services s3,lambda --format json --output serverless.json
        """,
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS profile name from ~/.aws/credentials (default: AWS default credential chain)",
    )
    parser.add_argument(
        "--services",
        type=str,
        default="all",
        help=f"Comma-separated services to scan, or 'all'. Available: {', '.join(get_available_services())}",
    )
    parser.add_argument(
        "--regions",
        type=str,
        default=None,
        help="Comma-separated AWS regions to scan (e.g., us-east-1,us-west-2). Default: current session region or us-east-1.",
    )
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="Automatically query and scan all enabled regions in the account.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=CONFIG.MAX_WORKER_THREADS,
        help=f"Number of parallel worker threads for scanning (default: {CONFIG.MAX_WORKER_THREADS})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="File path to save the findings report (supports .csv, .json)",
    )
    parser.add_argument(
        "--format",
        choices=["cards", "table", "csv", "json"],
        default="cards",
        help="Console output format: 'cards' (high-contrast cards, default) or 'table' (responsive grid)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable informative progress logging",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable full debug logging for AWS SDK requests",
    )
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="List all supported services and exit",
    )
    return parser.parse_args()


def _scan_target(scanner, session: boto3.Session, region: str) -> Tuple[str, str, List[Finding]]:
    """Helper worker task for ThreadPoolExecutor."""
    try:
        findings = scanner.scan(session, region)
        return (scanner.display_name, region, findings)
    except Exception as e:
        logger.error(f"Unhandled error in {scanner.name} on {region}: {e}")
        return (scanner.display_name, region, [])


def main() -> None:
    args = parse_args()
    configure_logging(args.verbose, args.debug)

    if args.list_services:
        print("\nSupported AWS Cost Optimization Services:")
        for s in get_available_services():
            sc = get_scanner(s)
            print(f"  • {s:12} - {sc.display_name}")
        print()
        sys.exit(0)

    # 1. Initialize AWS Session
    try:
        if args.profile:
            session = boto3.Session(profile_name=args.profile)
            print(f"🔑 Using AWS profile: '{args.profile}'")
        else:
            session = boto3.Session()
            print("🔑 Using standard AWS credential provider chain")
    except ProfileNotFound as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    # 2. Determine Services to Scan
    if args.services.lower() == "all":
        selected_services = get_available_services()
    else:
        selected_services = [s.strip().lower() for s in args.services.split(",") if s.strip()]

    for s in selected_services:
        if s not in ALL_SCANNERS:
            print(f"❌ Unknown service '{s}'. Available: {', '.join(get_available_services())}")
            sys.exit(1)

    # 3. Determine Regions
    if args.all_regions:
        print("🌍 Discovering all active regions in your account...")
        regions = get_active_regions(session)
    elif args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        def_reg = session.region_name or "us-east-1"
        regions = [def_reg]

    print(f"🚀 Scanning {len(selected_services)} service(s) across {len(regions)} region(s) using {args.threads} threads...\n")

    # 4. Schedule concurrent tasks
    all_findings: List[Finding] = []
    tasks = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for svc_name in selected_services:
            scanner = get_scanner(svc_name)
            if scanner.is_global:
                tasks.append(executor.submit(_scan_target, scanner, session, "global"))
            else:
                for reg in regions:
                    tasks.append(executor.submit(_scan_target, scanner, session, reg))

        for future in as_completed(tasks):
            svc_name, reg, res = future.result()
            if res:
                all_findings.extend(res)
                print(f"  ⚡ [{svc_name}] ({reg}): Found {len(res)} opportunity(s)")

    # 5. Console Report
    console_mode = args.format if args.format in ("cards", "table") else "cards"
    print_console_report(all_findings, mode=console_mode)

    # 6. File Export (CSV or JSON)
    if args.output:
        out_path = args.output
        if out_path.endswith(".json") or args.format == "json":
            export_to_json(all_findings, out_path)
            print(f"💾 Report exported to JSON: {out_path}")
        else:
            export_to_csv(all_findings, out_path)
            print(f"💾 Report exported to CSV: {out_path}")


if __name__ == "__main__":
    main()
