from collections import defaultdict
from typing import List
from aws_cost_optimizer.models import Finding, Severity

# ANSI Color codes for clean terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_console_report(findings: List[Finding]) -> None:
    """Renders formatted console output for cost findings."""
    print("\n" + "=" * 95)
    print(f"{BOLD}📊 AWS COST OPTIMIZATION REPORT{RESET}")
    print("=" * 95)

    if not findings:
        print(f"\n{GREEN}✅ No cost optimization issues detected across scanned services and regions!{RESET}\n")
        return

    # Severity ordering
    sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 99), -f.estimated_monthly_saving))

    try:
        from tabulate import tabulate

        table_rows = []
        for idx, f in enumerate(sorted_findings, 1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_str in ("HIGH", "CRITICAL"):
                sev_colored = f"{RED}{sev_str}{RESET}"
            elif sev_str == "MEDIUM":
                sev_colored = f"{YELLOW}{sev_str}{RESET}"
            else:
                sev_colored = f"{BLUE}{sev_str}{RESET}"

            table_rows.append([
                idx,
                sev_colored,
                f.service,
                f.region,
                f.resource_id[:20],
                f.issue[:34],
                f.recommendation[:36],
                f.effort,
                f"${f.estimated_monthly_saving:,.2f}",
            ])

        headers = ["#", "Severity", "Service", "Region", "Resource ID", "Issue", "Recommendation", "Effort", "Save/mo"]
        print(tabulate(table_rows, headers=headers, tablefmt="rounded_grid"))

    except ImportError:
        # Fallback formatting without tabulate dependency
        for idx, f in enumerate(sorted_findings, 1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            color = RED if sev_str in ("HIGH", "CRITICAL") else (YELLOW if sev_str == "MEDIUM" else BLUE)
            print(f"[{idx}] {color}[{sev_str}]{RESET} {BOLD}{f.service}{RESET} ({f.region}) - {f.resource_id} [Effort: {f.effort}, Confidence: {f.confidence}]")
            print(f"    ⚠️  Issue: {f.issue}")
            print(f"    💡 Recommendation: {f.recommendation}")
            if f.estimated_monthly_saving > 0:
                print(f"    💰 Est. Monthly Savings: {GREEN}${f.estimated_monthly_saving:,.2f}/mo{RESET}")
            print("-" * 80)

    # Summary Statistics
    total_savings = sum(f.estimated_monthly_saving for f in findings)
    high_count = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)

    service_counts = defaultdict(int)
    service_savings = defaultdict(float)
    for f in findings:
        service_counts[f.service] += 1
        service_savings[f.service] += f.estimated_monthly_saving

    print("\n" + "=" * 95)
    print(f"{BOLD}📈 EXECUTIVE SUMMARY{RESET}")
    print("=" * 95)
    print(f"  • Total Findings: {len(findings)}")
    print(f"  • {RED}High/Critical Priority:{RESET} {high_count}")
    print(f"  • {YELLOW}Medium Priority:{RESET}        {med_count}")
    print(f"  • {BLUE}Low/Hygiene Priority:{RESET}   {low_count}")
    print(f"  • {BOLD}{GREEN}Total Estimated Monthly Savings: ${total_savings:,.2f} / month{RESET}")
    print(f"  • {BOLD}{GREEN}Total Estimated Annual Savings:  ${total_savings * 12:,.2f} / year{RESET}")

    print(f"\n{BOLD}🏢 Breakdown by Service:{RESET}")
    for svc, count in sorted(service_counts.items(), key=lambda x: -x[1]):
        sav = service_savings[svc]
        print(f"  • {svc:30} : {count:2} finding(s) | Est. savings: ${sav:8,.2f}/mo")
    print("=" * 95 + "\n")
