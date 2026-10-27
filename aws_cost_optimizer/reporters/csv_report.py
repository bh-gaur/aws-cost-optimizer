import csv
import json
from typing import List
from aws_cost_optimizer.models import Finding


def export_to_csv(findings: List[Finding], file_path: str) -> None:
    """Exports findings list to a standard CSV file."""
    headers = [
        "Severity",
        "Service",
        "Resource ID",
        "Resource Name",
        "Region",
        "Effort",
        "Confidence",
        "Issue",
        "Recommendation",
        "Est. Monthly Saving ($)",
    ]
    with open(file_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for item in findings:
            writer.writerow([
                item.severity.value if hasattr(item.severity, "value") else str(item.severity),
                item.service,
                item.resource_id,
                item.resource_name,
                item.region,
                item.effort,
                item.confidence,
                item.issue,
                item.recommendation,
                f"{item.estimated_monthly_saving:.2f}",
            ])


def export_to_json(findings: List[Finding], file_path: str) -> None:
    """Exports findings list to formatted JSON."""
    data = [f.to_dict() for f in findings]
    with open(file_path, mode="w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
