from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    service: str
    resource_id: str
    region: str
    severity: Severity
    issue: str
    recommendation: str
    resource_name: str = ""
    estimated_monthly_saving: float = 0.0
    effort: str = "Low"          # "Low", "Medium", "High"
    confidence: str = "Medium"  # "Low", "Medium", "High"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "region": self.region,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "effort": self.effort,
            "confidence": self.confidence,
            "issue": self.issue,
            "recommendation": self.recommendation,
            "estimated_monthly_saving": round(self.estimated_monthly_saving, 2),
            "metadata": self.metadata,
        }
