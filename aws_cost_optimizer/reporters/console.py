"""
Production Console Reporter for AWS Cost Optimizer.

Renders rich, readable, non-truncated visual reports with:
- Executive Summary KPI Cards (Monthly & Annualized Projected Savings)
- Color-coded Findings Cards with full resource IDs, issues, and actionable recommendations
- Clean Responsive Table view (with zero word-chopping or harsh truncation)
- Categorized Savings Breakdown by AWS Service
"""

from collections import defaultdict
from typing import List

from aws_cost_optimizer.models import Finding, Severity

# Severity Display Metadata: (Color, Icon, Priority Order)
SEVERITY_META = {
    Severity.CRITICAL: ("red", "🚨", 0),
    Severity.HIGH: ("red", "🚨", 1),
    Severity.MEDIUM: ("yellow", "⚠️ ", 2),
    Severity.LOW: ("cyan", "ℹ️ ", 3),
    Severity.INFO: ("blue", "ℹ️ ", 4),
}


def print_console_report(findings: List[Finding], mode: str = "cards") -> None:
    """
    Renders formatted console output for cost findings.
    Supports 'cards' (default visual card panels) and 'table' (responsive grid).
    """
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()

        if not findings:
            console.print(
                "\n[bold green]✅ No cost optimization issues detected across scanned services and regions![/bold green]\n"
            )
            return

        # Sort findings by severity priority then highest monthly savings
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                SEVERITY_META.get(f.severity, ("white", "", 99))[2],
                -f.estimated_monthly_saving,
            ),
        )

        total_savings = sum(f.estimated_monthly_saving for f in findings)
        crit_high_count = sum(
            1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(
            1 for f in findings if f.severity in (Severity.LOW, Severity.INFO)
        )

        # ---------------------------------------------------------------------
        # 1. Executive Summary KPI Banner
        # ---------------------------------------------------------------------
        kpi_table = Table.grid(expand=True)
        kpi_table.add_column(ratio=1)
        kpi_table.add_column(ratio=1)
        kpi_table.add_column(ratio=1)
        kpi_table.add_column(ratio=1)

        kpi_table.add_row(
            f"[bold green]💰 Total Monthly Savings[/bold green]\n[bold white]${total_savings:,.2f} / month[/bold white]",
            f"[bold green]📅 Projected Annual Savings[/bold green]\n[bold white]${total_savings * 12:,.2f} / year[/bold white]",
            f"[bold red]🚨 Critical / High Priority[/bold red]\n[bold white]{crit_high_count} finding(s)[/bold white]",
            f"[bold yellow]⚠️  Medium / Low Priority[/bold yellow]\n[bold white]{med_count + low_count} finding(s)[/bold white]",
        )

        console.print("\n")
        console.print(
            Panel(
                kpi_table,
                title="[bold cyan]📊 AWS COST OPTIMIZATION EXECUTIVE SUMMARY[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        # ---------------------------------------------------------------------
        # 2. Detailed Findings (Cards Mode by Default or Responsive Table)
        # ---------------------------------------------------------------------
        if mode == "table":
            # Responsive Table View (Auto-wrapped, no harsh string slicing)
            table = Table(box=box.ROUNDED, expand=True, show_lines=True)
            table.add_column("#", style="dim", justify="center", width=4)
            table.add_column("Severity", justify="center", width=10)
            table.add_column("Service", style="cyan", width=14)
            table.add_column("Region", width=11)
            table.add_column("Resource ID", style="bold magenta", width=22)
            table.add_column("Issue & Actionable Recommendation", ratio=1)
            table.add_column("Effort", justify="center", width=8)
            table.add_column(
                "Est. Saving", justify="right", style="bold green", width=12
            )

            for idx, f in enumerate(sorted_findings, 1):
                sev_color, sev_icon, _ = SEVERITY_META.get(
                    f.severity, ("white", "", 99)
                )
                sev_label = f"[{sev_color}]{f.severity.value}[/{sev_color}]"

                issue_and_rec = (
                    f"[bold white]{f.issue}[/bold white]\n"
                    f"[dim]↳ {f.recommendation}[/dim]"
                )

                table.add_row(
                    str(idx),
                    sev_label,
                    f.service,
                    f.region,
                    f.resource_id,
                    issue_and_rec,
                    f.effort,
                    f"${f.estimated_monthly_saving:,.2f}",
                )

            console.print(table)
        else:
            # High-Impact Visual Card View (No truncation whatsoever)
            for idx, f in enumerate(sorted_findings, 1):
                color, icon, _ = SEVERITY_META.get(f.severity, ("white", "", 99))
                sev_name = (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                )

                content = (
                    f"[bold white]{f.issue}[/bold white]\n"
                    f"[dim]💡 Action:[/] {f.recommendation}\n\n"
                    f"[dim]Resource:[/] [bold magenta]{f.resource_id}[/bold magenta]   "
                    f"[dim]Region:[/] [cyan]{f.region}[/cyan]   "
                    f"[dim]Effort:[/] {f.effort}   "
                    f"[dim]Confidence:[/] {f.confidence}   "
                    f"[dim]Est. Saving:[/] [bold green]${f.estimated_monthly_saving:,.2f}/mo[/bold green]"
                )
                title = f"[{color}] [{idx}] {icon} {sev_name}  •  {f.service} [/{color}]"
                console.print(
                    Panel(
                        content,
                        title=title,
                        title_align="left",
                        border_style=color,
                        box=box.ROUNDED,
                    )
                )

        # ---------------------------------------------------------------------
        # 3. Categorized Breakdown by AWS Service
        # ---------------------------------------------------------------------
        service_counts = defaultdict(int)
        service_savings = defaultdict(float)
        for f in findings:
            service_counts[f.service] += 1
            service_savings[f.service] += f.estimated_monthly_saving

        svc_table = Table(box=box.SIMPLE_HEAD, expand=False, show_header=True)
        svc_table.add_column("AWS Service", style="bold cyan")
        svc_table.add_column("Findings", justify="center")
        svc_table.add_column("Monthly Savings", justify="right", style="bold green")
        svc_table.add_column("Projected Annualized", justify="right", style="green")

        for svc, count in sorted(service_counts.items(), key=lambda x: -x[1]):
            sav = service_savings[svc]
            svc_table.add_row(
                svc, str(count), f"${sav:,.2f}/mo", f"${sav * 12:,.2f}/yr"
            )

        console.print(
            Panel(
                svc_table,
                title="[bold white]🏢 Breakdown by Service[/bold white]",
                border_style="dim",
                box=box.ROUNDED,
            )
        )
        console.print("\n")

    except ImportError:
        # Fallback formatting if rich is unavailable
        print("\n" + "=" * 90)
        print("📊 AWS COST OPTIMIZATION REPORT")
        print("=" * 90)
        for idx, f in enumerate(findings, 1):
            print(f"[{idx}] [{f.severity.value}] {f.service} ({f.region}) - {f.resource_id}")
            print(f"    Issue: {f.issue}")
            print(f"    Recommendation: {f.recommendation}")
            print(f"    Effort: {f.effort} | Confidence: {f.confidence} | Est. Saving: ${f.estimated_monthly_saving:,.2f}/mo")
            print("-" * 90)
