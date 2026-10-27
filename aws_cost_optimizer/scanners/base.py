import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, List
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from aws_cost_optimizer.config import CONFIG
from aws_cost_optimizer.models import Finding

logger = logging.getLogger("aws_cost_optimizer")


class BaseScanner(ABC):
    """
    Abstract base class for all service-specific cost scanners.
    Provides standard retry configuration, logging, and error handling.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Service short identifier (e.g., 'ec2', 'ebs', 'rds')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """User-friendly display name (e.g., 'Amazon EC2')."""
        pass

    @property
    def is_global(self) -> bool:
        """True if the service is global and shouldn't scan per region (e.g. S3)."""
        return False

    def get_client(self, session: boto3.Session, service_name: str, region: str = None) -> Any:
        """
        Creates a boto3 client configured with adaptive retry logic and exponential backoff.
        """
        retry_config = Config(
            retries={
                "max_attempts": CONFIG.AWS_MAX_ATTEMPTS,
                "mode": "adaptive",
            },
            connect_timeout=10,
            read_timeout=30,
        )
        kwargs = {"config": retry_config}
        if region and region != "global":
            kwargs["region_name"] = region
        return session.client(service_name, **kwargs)

    @abstractmethod
    def scan(self, session: boto3.Session, region: str) -> List[Finding]:
        """
        Execute cost audit checks for this service in the specified region.
        Returns a list of Finding objects.
        """
        pass

    @staticmethod
    def chunks(seq: list, n: int) -> Generator[list, None, None]:
        """Yield successive n-sized chunks from seq."""
        for i in range(0, len(seq), n):
            yield seq[i : i + n]

    @staticmethod
    def tags_to_dict(tags: Any) -> Dict[str, str]:
        """Converts AWS Tag lists to a standard key-value dictionary."""
        if not tags:
            return {}
        if isinstance(tags, dict):
            return tags
        if isinstance(tags, list):
            res = {}
            for t in tags:
                if isinstance(t, dict):
                    if "Key" in t:
                        res[t["Key"]] = t.get("Value", "")
                    elif "TagKey" in t:
                        res[t["TagKey"]] = t.get("TagValue", "")
            return res
        return {}

    def handle_client_error(self, err: ClientError, resource_context: str) -> None:
        """Standardized error handler for AWS client permission or API errors."""
        code = err.response.get("Error", {}).get("Code", "Unknown")
        msg = err.response.get("Error", {}).get("Message", str(err))
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            logger.warning(f"[{self.name.upper()}] Permission denied inspecting {resource_context}: {msg}")
        elif code in ("Throttling", "RequestLimitExceeded", "ThrottlingException"):
            logger.error(f"[{self.name.upper()}] API rate limit reached on {resource_context}: {msg}")
        else:
            logger.debug(f"[{self.name.upper()}] {code} on {resource_context}: {msg}")
