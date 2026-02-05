"""
Result Logger

Tracks injection results, external IDs, and errors for audit and reporting.
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class InjectionResult:
    """Represents a single injection result."""

    def __init__(
        self,
        alert_id: str,
        status: str,
        external_id: Optional[str] = None,
        error: Optional[str] = None,
        http_code: Optional[int] = None,
    ):
        """
        Initialize injection result.

        Args:
            alert_id: Alert ID from the alert
            status: Status ('success', 'failed', 'skipped')
            external_id: External ID from XSIAM response
            error: Error message if failed
            http_code: HTTP response code
        """
        self.alert_id = alert_id
        self.status = status
        self.external_id = external_id
        self.error = error
        self.http_code = http_code
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        """Convert result to dictionary."""
        return {
            "alert_id": self.alert_id,
            "status": self.status,
            "external_id": self.external_id,
            "error": self.error,
            "http_code": self.http_code,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return (
            f"InjectionResult(alert_id={self.alert_id}, status={self.status}, "
            f"external_id={self.external_id})"
        )


class ResultLogger:
    """Logs and tracks injection results."""

    def __init__(self, log_file: str = "logs/injection_results.json"):
        """
        Initialize result logger.

        Args:
            log_file: Path to JSON file for storing results
        """
        self.log_file = Path(log_file)
        self.results = []
        self._load_existing_results()

    def _load_existing_results(self):
        """Load existing results if log file exists."""
        if self.log_file.exists():
            try:
                with open(self.log_file, "r") as f:
                    data = json.load(f)
                    self.results = data if isinstance(data, list) else [data]
                logger.debug(f"Loaded {len(self.results)} existing results from {self.log_file}")
            except json.JSONDecodeError:
                logger.warning(f"Could not parse existing {self.log_file}, starting fresh")
                self.results = []

    def add_result(self, result: InjectionResult):
        """Add a result to the log."""
        self.results.append(result.to_dict())
        logger.debug(f"Logged result: {result}")

    def add_success(self, alert_id: str, external_id: str, http_code: int = 200):
        """Log a successful injection."""
        result = InjectionResult(
            alert_id=alert_id, status="success", external_id=external_id, http_code=http_code
        )
        self.add_result(result)

    def add_failure(self, alert_id: str, error: str, http_code: Optional[int] = None):
        """Log a failed injection."""
        result = InjectionResult(
            alert_id=alert_id, status="failed", error=error, http_code=http_code
        )
        self.add_result(result)

    def add_skip(self, alert_id: str, reason: str):
        """Log a skipped alert."""
        result = InjectionResult(
            alert_id=alert_id, status="skipped", error=reason, http_code=None
        )
        self.add_result(result)

    def save_to_file(self):
        """Save all results to the log file."""
        try:
            with open(self.log_file, "w") as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Results saved to {self.log_file}")
        except IOError as e:
            logger.error(f"Failed to write results to {self.log_file}: {e}")

    def get_summary(self) -> dict:
        """Get injection summary statistics."""
        total = len(self.results)
        successful = sum(1 for r in self.results if r["status"] == "success")
        failed = sum(1 for r in self.results if r["status"] == "failed")
        skipped = sum(1 for r in self.results if r["status"] == "skipped")

        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "skipped": skipped,
            "success_rate": (successful / total * 100) if total > 0 else 0,
        }

    def print_summary(self):
        """Print a human-readable summary."""
        summary = self.get_summary()
        logger.info("=" * 60)
        logger.info("INJECTION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total Alerts: {summary['total']}")
        logger.info(f"Successful: {summary['successful']}")
        logger.info(f"Failed: {summary['failed']}")
        logger.info(f"Skipped: {summary['skipped']}")
        logger.info(f"Success Rate: {summary['success_rate']:.2f}%")
        logger.info("=" * 60)

    def get_external_ids(self) -> dict:
        """Get mapping of alert IDs to external IDs for successful injections."""
        return {
            r["alert_id"]: r["external_id"]
            for r in self.results
            if r["status"] == "success" and r["external_id"]
        }

    def get_failed_alerts(self) -> list[dict]:
        """Get list of failed alerts with error details."""
        return [r for r in self.results if r["status"] == "failed"]
