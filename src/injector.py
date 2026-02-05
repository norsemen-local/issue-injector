#!/usr/bin/env python3
"""
Issues Injector

Reads alert JSON files, validates them against schema, and injects them into
Cortex XSIAM platform via API.

Usage:
    python injector.py --file <alert_file> [--api-url <url>] [--dry-run]
    python injector.py --dir <directory> [--api-url <url>] [--batch-size 100]
    python injector.py --validate <alert_file>
"""

import json
import logging
import argparse
import os
import time
import random
import socket
import struct
from pathlib import Path
from typing import Optional, List, Union
from datetime import datetime

import requests
from requests.exceptions import RequestException

from validator import AlertValidator
from result_logger import ResultLogger

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    # Try to load .env from current directory and parent
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        # Try parent directory
        parent_env = Path.cwd().parent / ".env"
        if parent_env.exists():
            load_dotenv(parent_env)
except ImportError:
    # python-dotenv not installed, that's okay - use env vars directly
    pass

# Configure logging
log_dir = Path(__file__).parent / "logs"
log_dir.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_dir / "injector.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


class XSIAMInjector:
    """Injects alerts into Cortex XSIAM platform."""

    # Default XSIAM API endpoint (can be overridden)
    DEFAULT_API_URL = "https://api.xsiam.example.com"
    DEFAULT_ENDPOINT = "/public_api/v1/alerts/create_alert"

    # Rate limiting: 600 alerts/minute
    RATE_LIMIT = 600  # alerts per minute
    RATE_LIMIT_INTERVAL = 60  # seconds
    MIN_DELAY = RATE_LIMIT_INTERVAL / RATE_LIMIT  # ~0.1 second per alert

    # All 318 validated custom fields from schema.json are whitelisted
    # Fields requiring transformation: IPs (to integers), timestamps (to milliseconds), Multi-Select (to arrays)
    XSIAM_ALLOWED_FIELDS = {
        # Required fields (7)
        "vendor", "product", "severity", "category", "alert_id", "timestamp", "description",
        
        # Core Alert Fields (14)
        "alert_name", "alert_domain", "alert_type", "alert_type_id", "alert_action",
        "title", "issue_name", "rule_name", "original_alert_name", "threat_name",
        "malware_name", "signature", "excluded", "starred",
        
        # Host/Device Fields (16)
        "host_name", "host_fqdn", "host_mac_address", "host_ip", "host_os", "host_risk_level",
        "asset_id", "asset_name", "device_id", "device_name", "device_model",
        "device_status", "device_hash", "endpoint_isolation_status", "cid", "remote_agent_hostname",
        
        # User/Identity Fields (26)
        "user_name", "user_id", "user_risk_level", "initiated_by", "display_name",
        "department", "given_name", "surname", "first_name", "last_name", "full_name",
        "email", "manager_name", "manager_email_address", "employee_display_name",
        "employee_email", "account_id", "account_status", "birthday", "cost_center",
        "cost_center_code", "job_code", "job_family", "job_function", "leadership",
        "org_level_1", "org_level_2", "org_level_3", "org_unit", "team_name",
        "phone_number", "work_phone", "mobile_phone", "password_changed_date", "user_creation_time",
        
        # Process Fields (26)
        "cgo_cmd", "cgo_md5", "cgo_name", "cgo_path", "cgo_sha256", "cgo_signer",
        "initiator_cmd", "initiator_md5", "initiator_path", "initiator_pid", "initiator_sha256",
        "initiator_signer", "initiator_tid", "os_parent_cmd", "os_parent_name", "os_parent_pid",
        "os_parent_sha256", "os_parent_signer", "os_parent_user_name", "os_actor_process_image_md5",
        "target_process_cmd", "target_process_name", "target_process_sha256", "parent_process_id",
        "process_execution_signer", "application_path", "command_line_verdict", "misc",
        
        # Network Fields (22)
        "remote_ip", "local_ip", "remote_ipv6", "local_ipv6", "remote_port", "local_port",
        "domain", "dns_query_name", "domain_registrar_abuse_email", "domain_updated_date",
        "url", "malicious_urls", "destination_zone_name", "source_zone_name",
        "asn", "asn_name", "xff", "src_os", "dest_os", "sensor_ip", "unique_ports", "remote_host",
        
        # Firewall Fields (5)
        "fw_name", "fw_rule_name", "fw_rule_id", "fw_serial_number", "ngfw_vsys_name",
        
        # Email/Phishing Fields (37)
        "email_subject", "email_sender", "email_recipient", "email_body", "email_cc",
        "email_bcc", "email_from", "email_to", "email_from_display_name", "email_reply_to",
        "email_return_path", "email_message_id", "email_received_date", "email_sent_date",
        "email_header_from", "email_header_to", "email_header_subject", "email_header_reply_to",
        "email_header_return_path", "email_header_message_id", "email_attachment_name",
        "email_attachment_hash", "email_attachment_type", "email_attachment_count",
        "email_attachment_extension", "spf", "dkim", "dmarc", "email_authentication",
        "phishing_confidence_score", "sender_ip_reputation", "url_reputation",
        "attachment_reputation", "sender_domain_age", "sender_domain_reputation",
        "email_headers", "message_id", "spf_result",
        
        # File/Hash Fields (14)
        "file_name", "file_path", "file_sha256", "file_sha1", "file_md5",
        "file_size", "file_type", "file_extension", "file_signature_status",
        "file_signature_vendor", "file_hash", "file_wildfire_verdict", "vault_id",
        "malicious_file_signature_id",
        
        # Cloud/Container Fields (19)
        "cloud_provider", "cloud_region", "cloud_account_id", "cloud_resource_id",
        "cloud_service", "cloud_instance_id", "cloud_instance_type", "cloud_vpc_id",
        "cloud_subnet_id", "cloud_security_group", "container_id", "container_name",
        "container_image", "container_runtime", "pod_name", "namespace",
        "cluster_name", "kubernetes_version", "orchestration_platform",
        
        # Detection/Source Fields (14)
        "detection_method", "detection_source", "detection_timestamp", "detection_engine",
        "detection_signature_id", "detection_confidence", "event_source", "source",
        "log_source", "log_type", "collector_name", "sensor_name", "sensor_version",
        "agent_version",
        
        # Threat Intelligence Fields (23)
        "threat_category", "threat_type", "threat_actor", "threat_campaign",
        "threat_family", "ioc_type", "ioc_value", "ioc_confidence", "ioc_source",
        "threat_indicator", "threat_score", "threat_level", "malware_family",
        "malware_type", "malware_category", "attack_vector", "attack_technique",
        "attack_tactic", "ttp", "cve_id", "vulnerability_id", "exploit_name",
        "threat_intelligence_source",
        
        # Policy/Compliance Fields (13)
        "policy_name", "policy_id", "policy_violation", "compliance_standard",
        "compliance_requirement", "compliance_control", "data_classification",
        "sensitivity_label", "dlp_policy_name", "dlp_rule_name", "dlp_action",
        "dlp_severity", "data_category",
        
        # Timestamps/Events Fields (10)
        "event_timestamp", "event_time", "first_seen", "last_seen", "created_time",
        "modified_time", "resolved_time", "closed_time", "event_id", "event_type",
        
        # Risk Assessment Fields (3)
        "risk_score", "risk_level", "risk_factors",
        
        # Resolution/Status Fields (8)
        "resolution_status", "resolution_comment", "assigned_to", "assigned_user",
        "handled_by", "action_taken", "remediation_action", "remediation_status",
        
        # External Integration Fields (3)
        "ticket_id", "case_id", "external_id",
        
        # MITRE ATT&CK Fields (2)
        "mitre_att&ck_tactic", "mitre_att&ck_technique",
        
        # Registry Fields (2)
        "registry_full_key", "registry_value",
        
        # Incident Management Fields (10)
        "incident_id", "incident_name", "incident_status", "incident_owner",
        "incident_severity", "incident_type", "incident_category", "notes",
        "tags", "labels",
        
        # Detection/Hunting Fields (4)
        "hunting_query", "detection_rule", "correlation_id", "alert_count",
        
        # Location/Region Fields (6)
        "city", "region", "location", "latitude", "longitude", "time_zone",
        
        # Device/Hardware Fields (4)
        "device_vendor", "device_type", "device_serial_number", "device_version",
        
        # Classification/Action Fields (5)
        "classification", "action", "action_status", "action_result", "verdict",
        
        # Miscellaneous Fields (7)
        "protocol", "port", "service", "application", "application_name",
        "src_type", "dest_type",
    }

    # Field mappings from our schema to XSIAM expected names
    FIELD_MAPPINGS = {
        "details": "description",
    }

    def __init__(
        self,
        schema_path: str = "schema.json",
    ):
        """
        Initialize the injector.

        Args:
            schema_path: Path to schema.json
        """
        self.schema_path = Path(schema_path)
        self.validator = AlertValidator(str(self.schema_path))

        # API configuration from .env only
        self.api_url = (os.getenv("XSIAM_API_URL") or self.DEFAULT_API_URL).rstrip("/")
        self.api_key = os.getenv("XSIAM_API_KEY")
        self.api_key_id = os.getenv("XSIAM_API_KEY_ID")

        # Results logger
        log_dir = Path(__file__).parent / "logs"
        self.result_logger = ResultLogger(str(log_dir / "injection_results.json"))

        # Statistics
        self.alerts_processed = 0
        self.last_injection_time = 0

        logger.info(f"Injector initialized with API URL: {self.api_url}")
        logger.debug(f"API Key configured: {bool(self.api_key)}")
        logger.debug(f"API Key ID configured: {bool(self.api_key_id)}")
        logger.debug(f"Full endpoint will be: {self.api_url}{self.DEFAULT_ENDPOINT}")

    def _enforce_rate_limit(self):
        """Enforce rate limiting between injections."""
        elapsed = time.time() - self.last_injection_time
        if elapsed < self.MIN_DELAY:
            sleep_time = self.MIN_DELAY - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.3f} seconds")
            time.sleep(sleep_time)

    @staticmethod
    def _ip_to_integer(ip: str) -> int:
        """
        Convert IP address string to integer.
        
        Args:
            ip: IP address string (e.g., "192.168.1.1")
            
        Returns:
            Integer representation of IP address
        """
        try:
            return struct.unpack('!I', socket.inet_aton(ip))[0]
        except (socket.error, OSError) as e:
            logger.warning(f"Failed to convert IP '{ip}' to integer: {e}")
            return None
    
    def _transform_field_value(self, field_name: str, value: Union[str, int, list, dict]) -> Union[str, int, list, dict]:
        """
        Transform field values according to XSIAM requirements.
        
        Transformations:
        - IP fields: String IPs -> Integers
        - IP array fields: List of string IPs -> List of integers
        - Timestamp fields: Ensure milliseconds since epoch
        - Multi-Select fields: Ensure arrays
        
        Args:
            field_name: Name of the field
            value: Field value to transform
            
        Returns:
            Transformed value
        """
        # IP fields that need integer conversion (arrays)
        ip_array_fields = {"host_ip", "remote_ip", "local_ip"}
        
        # Single IP fields (if any exist as strings)
        ip_string_fields = {"sensor_ip"}
        
        # Fields that should be arrays (Multi-Select fields from schema.json)
        array_fields = {
            "user_name", "device_id", "initiated_by", "phone_number", "cid", "remote_agent_hostname",
            "cgo_cmd", "cgo_md5", "cgo_name", "cgo_path", "cgo_sha256", "cgo_signer",
            "initiator_cmd", "initiator_md5", "initiator_path", "initiator_pid", "initiator_sha256",
            "initiator_signer", "initiator_tid", "os_parent_cmd", "os_parent_name", "os_parent_pid",
            "os_parent_sha256", "os_parent_signer", "os_parent_user_name", "os_actor_process_image_md5",
            "target_process_cmd", "target_process_name", "target_process_sha256",
            "process_execution_signer", "misc",
            "remote_ipv6", "local_ipv6", "remote_port", "local_port", "dns_query_name",
            "url", "malicious_urls", "destination_zone_name", "source_zone_name", "xff", "remote_host",
            "fw_name", "fw_rule_name", "fw_rule_id", "fw_serial_number", "ngfw_vsys_name",
            "email_subject", "email_sender", "email_recipient", "file_name",
        }
        
        # Transform IP arrays
        if field_name in ip_array_fields:
            if isinstance(value, list):
                # Convert each IP string to integer
                return [self._ip_to_integer(ip) for ip in value if isinstance(ip, str) and self._ip_to_integer(ip) is not None]
            elif isinstance(value, str):
                # Single IP string, convert to array of one integer
                ip_int = self._ip_to_integer(value)
                return [ip_int] if ip_int is not None else []
        
        # Transform single IP strings to integers (rare case)
        if field_name in ip_string_fields and isinstance(value, str):
            ip_int = self._ip_to_integer(value)
            return ip_int if ip_int is not None else value
        
        # Ensure Multi-Select fields are arrays
        if field_name in array_fields and not isinstance(value, list):
            return [value] if value else []
        
        # Timestamp field - ensure milliseconds
        if field_name == "timestamp" and isinstance(value, (int, float)):
            # If timestamp looks like seconds (less than year 3000 in seconds)
            if value < 32503680000:  # Jan 1, 3000 in seconds
                return int(value * 1000)
            return int(value)
        
        return value

    def _build_request_payload(self, alert: dict) -> dict:
        """
        Build the XSIAM API request payload.

        - Maps our internal field names to XSIAM expected names
        - Transforms field values (IPs to integers, timestamps, arrays)
        - Filters out unsupported fields to avoid 4xx/5xx from API

        Args:
            alert: Validated alert dictionary

        Returns:
            Request payload with request_data > alert structure
        """
        # Apply field mappings (e.g., 'details' -> 'description')
        transformed = {}
        for k, v in alert.items():
            mapped_key = self.FIELD_MAPPINGS.get(k, k)
            # Transform the value according to field requirements
            transformed_value = self._transform_field_value(mapped_key, v)
            transformed[mapped_key] = transformed_value

        # Filter to allowed fields only
        filtered_alert = {k: v for k, v in transformed.items() if k in self.XSIAM_ALLOWED_FIELDS}

        # Debug which fields were removed
        removed = set(transformed.keys()) - set(filtered_alert.keys())
        if removed:
            logger.debug(f"Removed unsupported fields from payload: {sorted(removed)}")

        return {"request_data": {"alert": filtered_alert}}

    def _build_headers(self) -> dict:
        """Build request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
        }

        if self.api_key:
            # Standard XSIAM authentication (not Bearer token)
            headers["Authorization"] = self.api_key
        if self.api_key_id:
            headers["x-xdr-auth-id"] = str(self.api_key_id)

        return headers

    def inject_alert(self, alert: dict, dry_run: bool = False) -> tuple[bool, Optional[str]]:
        """
        Inject a single alert into XSIAM.

        Args:
            alert: Validated alert dictionary
            dry_run: If True, don't actually send the request

        Returns:
            Tuple of (success, external_id_or_error)
        """
        alert_id = alert.get("alert_id", "unknown")

        # Handle timestamp generation
        if "timestamp" not in alert:
            now = time.time()
            
            # Check for relative_timestamp_hours (campaign mode)
            if "relative_timestamp_hours" in alert:
                hours_ago = alert.pop("relative_timestamp_hours")  # Remove metadata field
                timestamp_seconds = now - (hours_ago * 3600)
                alert["timestamp"] = int(timestamp_seconds * 1000)
                logger.debug(f"Timestamp for alert {alert_id} set to {hours_ago:.2f} hours ago: {alert['timestamp']} (campaign mode)")
            else:
                # Default: random time within last 7 days
                seven_days_ago = now - (7 * 24 * 60 * 60)
                random_timestamp = random.uniform(seven_days_ago, now)
                alert["timestamp"] = int(random_timestamp * 1000)
                logger.debug(f"Timestamp not provided for alert {alert_id}, auto-generated: {alert['timestamp']} (random within last 7 days)")

        # Validate first
        is_valid, errors = self.validator.validate_alert(alert)
        if not is_valid:
            error_msg = f"Validation failed: {errors[0]}"
            logger.error(f"Alert {alert_id}: {error_msg}")
            self.result_logger.add_failure(alert_id, error_msg)
            return False, error_msg

        # Prepare payload
        payload = self._build_request_payload(alert)
        headers = self._build_headers()
        endpoint = f"{self.api_url}{self.DEFAULT_ENDPOINT}"

        logger.info(f"Injecting alert: {alert_id}")
        logger.debug(f"Endpoint: {endpoint}")
        logger.debug(f"Headers: {list(headers.keys())}")
        logger.debug(f"Authorization header present: {'Authorization' in headers}")
        logger.debug(f"x-xdr-auth-id header present: {'x-xdr-auth-id' in headers}")

        if dry_run:
            logger.info(f"[DRY-RUN] Would POST to {endpoint}")
            logger.debug(f"[DRY-RUN] Payload: {json.dumps(payload, indent=2)}")
            self.result_logger.add_success(alert_id, "DRY-RUN", 200)
            return True, "DRY-RUN"

        try:
            # Enforce rate limiting
            self._enforce_rate_limit()

            # Make request
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=30,
            )

            self.last_injection_time = time.time()

            # Check response
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    external_id = response_data.get("data", "unknown")
                    logger.info(
                        f"Alert {alert_id} injected successfully. "
                        f"External ID: {external_id}"
                    )
                    self.result_logger.add_success(alert_id, external_id, 200)
                    return True, external_id
                except json.JSONDecodeError:
                    error_msg = f"Invalid JSON in response: {response.text[:100]}"
                    logger.error(error_msg)
                    self.result_logger.add_failure(alert_id, error_msg, 200)
                    return False, error_msg
            else:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.error(f"Alert {alert_id}: {error_msg}")
                self.result_logger.add_failure(alert_id, error_msg, response.status_code)
                return False, error_msg

        except RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(f"Alert {alert_id}: {error_msg}")
            self.result_logger.add_failure(alert_id, error_msg)
            return False, error_msg

    def inject_file(
        self, file_path: str, dry_run: bool = False
    ) -> tuple[int, int]:
        """
        Inject alerts from a file.

        Args:
            file_path: Path to JSON alert file
            dry_run: If True, validate but don't inject

        Returns:
            Tuple of (successful_count, failed_count)
        """
        logger.info(f"Processing file: {file_path}")

        # Validate file
        is_valid, valid_alerts, errors = self.validator.validate_alerts_from_file(
            file_path
        )

        if not is_valid:
            logger.warning(f"Validation errors in {file_path}:")
            for error in errors:
                logger.warning(f"  - {error}")

        # Inject valid alerts
        successful = 0
        failed = 0

        for alert in valid_alerts:
            success, _ = self.inject_alert(alert, dry_run=dry_run)
            if success:
                successful += 1
            else:
                failed += 1
            self.alerts_processed += 1

        logger.info(
            f"File processing complete: {successful} successful, "
            f"{failed} failed"
        )
        return successful, failed

    def inject_directory(
        self,
        directory: str,
        pattern: str = "*.json",
        dry_run: bool = False,
        batch_size: int = 100,
    ) -> tuple[int, int]:
        """
        Inject alerts from all JSON files in a directory.

        Args:
            directory: Directory path
            pattern: File pattern to match (default: *.json)
            dry_run: If True, validate but don't inject
            batch_size: Maximum alerts to process before reporting

        Returns:
            Tuple of (total_successful, total_failed)
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error(f"Directory not found: {directory}")
            return 0, 0

        # Find all JSON files
        json_files = sorted(dir_path.glob(pattern))
        if not json_files:
            logger.warning(f"No files matching '{pattern}' in {directory}")
            return 0, 0

        logger.info(f"Found {len(json_files)} file(s) in {directory}")

        total_successful = 0
        total_failed = 0

        for file_path in json_files:
            successful, failed = self.inject_file(str(file_path), dry_run=dry_run)
            total_successful += successful
            total_failed += failed

            # Report progress
            if self.alerts_processed % batch_size == 0:
                logger.info(
                    f"Progress: {self.alerts_processed} alerts processed. "
                    f"Success: {total_successful}, Failed: {total_failed}"
                )

        return total_successful, total_failed

    def validate_file(self, file_path: str) -> bool:
        """
        Validate alerts in a file without injecting.

        Args:
            file_path: Path to JSON alert file

        Returns:
            True if all alerts are valid
        """
        logger.info(f"Validating file: {file_path}")
        is_valid, valid_alerts, errors = self.validator.validate_alerts_from_file(
            file_path
        )

        if is_valid:
            logger.info(f"✓ All {len(valid_alerts)} alert(s) are valid")
        else:
            logger.error(f"✗ Validation failed with {len(errors)} error(s)")
            for error in errors:
                logger.error(f"  - {error}")

        return is_valid

    def print_summary(self):
        """Print final summary report."""
        self.result_logger.print_summary()
        external_ids = self.result_logger.get_external_ids()
        logger.info(f"External ID Mappings: {len(external_ids)} alerts tracked")

        failed = self.result_logger.get_failed_alerts()
        if failed:
            logger.warning("Failed Alerts:")
            for result in failed:
                logger.warning(
                    f"  - {result['alert_id']}: {result['error']}"
                )

    def save_results(self):
        """Save results to file."""
        self.result_logger.save_to_file()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Inject security alerts into Cortex XSIAM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a single alert file
  %(prog)s --validate issues_jsons/phishing_alert_clean.json

  # Inject alerts from a file (dry-run)
  %(prog)s --file issues_jsons/phishing_alert_clean.json --dry-run

  # Inject alerts from a file
  %(prog)s --file issues_jsons/phishing_alert_clean.json

  # Inject all alerts from a directory
  %(prog)s --dir issues_jsons/

Note: All API credentials are loaded from .env file
        """
    )

    parser.add_argument(
        "--file",
        type=str,
        help="Path to JSON alert file to inject",
    )
    parser.add_argument(
        "--dir",
        type=str,
        help="Directory containing JSON alert files to inject",
    )
    parser.add_argument(
        "--validate",
        type=str,
        help="Validate alerts in a file without injecting",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate but don't actually inject alerts",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Report progress every N alerts (default: 100)",
    )
    parser.add_argument(
        "--schema",
        type=str,
        default="schema.json",
        help="Path to schema.json (default: schema.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("=" * 70)
    logger.info("CORTEX XSIAM ALERT INJECTOR")
    logger.info("=" * 70)

    # Create injector
    injector = XSIAMInjector(schema_path=args.schema)

    # Perform requested action
    if args.validate:
        # Validation mode
        is_valid = injector.validate_file(args.validate)
        return 0 if is_valid else 1

    elif args.file:
        # Single file injection
        logger.info(f"Injecting from file: {args.file}")
        successful, failed = injector.inject_file(args.file, dry_run=args.dry_run)

    elif args.dir:
        # Directory injection
        logger.info(f"Injecting from directory: {args.dir}")
        successful, failed = injector.inject_directory(
            args.dir, dry_run=args.dry_run, batch_size=args.batch_size
        )

    else:
        parser.print_help()
        logger.error("Please specify --file, --dir, or --validate")
        return 1

    # Print and save results
    injector.print_summary()
    injector.save_results()

    logger.info("=" * 70)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
