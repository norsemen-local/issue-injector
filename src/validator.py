"""
Alert Validator

Validates alerts against the schema.json to ensure data integrity before injection.
"""

import json
import logging
from pathlib import Path
from jsonschema import validate, ValidationError, Draft202012Validator

logger = logging.getLogger(__name__)


class AlertValidator:
    """Validates alerts against the Cortex XSIAM schema."""

    def __init__(self, schema_path: str):
        """
        Initialize validator with schema file.

        Args:
            schema_path: Path to the schema.json file
        """
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
        self.validator = Draft202012Validator(self.schema)

    def _load_schema(self) -> dict:
        """Load and parse the schema file."""
        try:
            with open(self.schema_path, "r") as f:
                schema = json.load(f)
            logger.debug(f"Schema loaded successfully from {self.schema_path}")
            return schema
        except FileNotFoundError:
            logger.error(f"Schema file not found: {self.schema_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in schema file: {e}")
            raise

    def validate_alert(self, alert: dict) -> tuple[bool, list[str]]:
        """
        Validate a single alert against the schema.

        Args:
            alert: Alert dictionary to validate

        Returns:
            Tuple of (is_valid, errors_list)
        """
        errors = []
        try:
            validate(instance=alert, schema=self.schema)
            logger.debug(f"Alert validated successfully: {alert.get('alert_id', 'unknown')}")
            return True, []
        except ValidationError as e:
            error_msg = f"Validation Error at path {list(e.path)}: {e.message}"
            errors.append(error_msg)
            logger.warning(error_msg)
            return False, errors

    def validate_alerts_from_file(self, file_path: str) -> tuple[bool, list[dict], list[str]]:
        """
        Validate alerts from a JSON file.

        Args:
            file_path: Path to JSON file containing alert(s)

        Returns:
            Tuple of (all_valid, valid_alerts, error_messages)
        """
        all_valid = True
        valid_alerts = []
        error_messages = []

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            # Handle both single alert (dict) and multiple alerts (list)
            alerts = [data] if isinstance(data, dict) else data

            for idx, alert in enumerate(alerts):
                is_valid, errors = self.validate_alert(alert)
                if is_valid:
                    valid_alerts.append(alert)
                else:
                    all_valid = False
                    alert_id = alert.get("alert_id", f"Index {idx}")
                    for error in errors:
                        msg = f"Alert {alert_id}: {error}"
                        error_messages.append(msg)
                        logger.error(msg)

            if all_valid:
                logger.info(f"All {len(alerts)} alert(s) from {file_path} are valid")
            else:
                logger.warning(
                    f"{len(valid_alerts)}/{len(alerts)} alerts from {file_path} are valid"
                )

            return all_valid, valid_alerts, error_messages

        except FileNotFoundError:
            error_msg = f"File not found: {file_path}"
            logger.error(error_msg)
            return False, [], [error_msg]
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in {file_path}: {e}"
            logger.error(error_msg)
            return False, [], [error_msg]

    def get_validation_summary(self, alert: dict) -> dict:
        """
        Get detailed validation info about an alert without raising errors.

        Args:
            alert: Alert dictionary to check

        Returns:
            Summary dictionary with validation details
        """
        summary = {
            "is_valid": False,
            "required_fields": [],
            "missing_fields": [],
            "field_errors": [],
        }

        required_fields = self.schema.get("required", [])
        summary["required_fields"] = required_fields

        # Check required fields
        for field in required_fields:
            if field not in alert:
                summary["missing_fields"].append(field)

        # Validate
        is_valid, errors = self.validate_alert(alert)
        summary["is_valid"] = is_valid
        summary["field_errors"] = errors

        return summary
