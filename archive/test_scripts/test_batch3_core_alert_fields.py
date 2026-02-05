#!/usr/bin/env python3
"""
Test Batch 3 - Untested Core Alert Fields + High-Value Fields
============================================================

Testing 36 Core Alert Fields we haven't tested yet, plus other high-value fields
"""

import json
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
import time

load_dotenv()

XSIAM_API_URL = os.getenv("XSIAM_API_URL")
XSIAM_API_KEY = os.getenv("XSIAM_API_KEY")
XSIAM_API_KEY_ID = os.getenv("XSIAM_API_KEY_ID")


def create_base_alert(test_name):
    """Create minimal valid alert."""
    return {
        "vendor": "TestVendor",
        "product": "TestProduct",
        "severity": "high",
        "category": "Malware",
        "alert_id": f"TEST-B3-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Batch 3 test: {test_name}"
    }


# Core Alert Fields - Untested (36 fields)
CORE_ALERT_FIELDS_BATCH3 = [
    # Process Instance IDs
    {"name": "action_process_instance_id", "value": ["inst-12345"]},
    {"name": "actor_process_instance_id", "value": ["inst-67890"]},
    
    # App Fields
    {"name": "app_category", "value": ["collaboration"]},
    {"name": "app_id", "value": ["web-browsing"]},
    {"name": "app_subcategory", "value": ["file-sharing"]},
    {"name": "app_technology", "value": ["browser-based"]},
    
    # Cloud Identity/Resource
    {"name": "cloud_identity_sub_type", "value": ["service-account"]},
    {"name": "cloud_identity_type", "value": ["user"]},
    {"name": "cloud_operation_type", "value": ["create"]},
    {"name": "cloud_referenced_resource", "value": ["arn:aws:s3:::my-bucket"]},
    {"name": "cloud_resource_sub_type", "value": ["instance"]},
    {"name": "cloud_resource_type", "value": ["compute"]},
    
    # Container
    {"name": "container_id", "value": ["abc123def456"]},
    
    # Network/Geo
    {"name": "contains_featured_ip_address", "value": ["NO"]},
    {"name": "country", "value": ["US"]},
    {"name": "xff", "value": ["203.0.113.1"]},
    
    # Agent/Host
    {"name": "cid", "value": ["CID-12345"]},
    {"name": "remote_agent_hostname", "value": ["remote-host-01"]},
    {"name": "remote_host", "value": ["remote.example.com"]},
    
    # Detection
    {"name": "detection_rule_id", "value": "RULE-12345"},
    
    # Misc
    {"name": "misc", "value": ["additional-context"]},
    
    # Process Execution (try without signature suffix)
    {"name": "process_execution_signature", "value": ["Signed"]},
    {"name": "process_execution_signer", "value": ["Microsoft Corporation"]},
]

# Additional High-Value Fields from other categories
HIGH_VALUE_FIELDS = [
    # Severity/Priority (from Common Types)
    {"name": "severity", "value": "critical"},
    
    # Source/Detection
    {"name": "source_instance", "value": "xdr-agent-01"},
    {"name": "source_id", "value": "SOURCE-123"},
    
    # Vendor/Product
    {"name": "vendor_product", "value": "XDR Agent"},
    
    # Time fields
    {"name": "end_time", "value": "2025-11-26T18:00:00Z"},
    
    # External fields
    {"name": "external_link", "value": "https://portal.example.com/alert/123"},
    
    # Detection/Alert source
    {"name": "alert_action", "value": "Blocked"},
    
    # Account/Identity
    {"name": "account_id", "value": "ACCT-12345"},
    
    # Additional Email
    {"name": "email_body", "value": "This is a phishing email"},
    {"name": "email_from", "value": "attacker@evil.com"},
    
    # Network
    {"name": "source_geolocation", "value": ["US-CA"]},
    {"name": "destination_geolocation", "value": ["US-NY"]},
    
    # File
    {"name": "file_size", "value": "1024000"},
    {"name": "file_hash", "value": "abc123def456"},
    
    # Campaign
    {"name": "campaign_name", "value": "APT-2025-01"},
    
    # Threat
    {"name": "threat_family_name", "value": "Emotet"},
    
    # Ticket/Case
    {"name": "ticket_number", "value": "TICKET-12345"},
    
    # Policy
    {"name": "policy_id", "value": "POL-12345"},
    
    # Resource
    {"name": "resource_name", "value": "web-server-01"},
    {"name": "resource_type", "value": "EC2 Instance"},
]

ALL_TEST_CASES = CORE_ALERT_FIELDS_BATCH3 + HIGH_VALUE_FIELDS


def test_field(field_name, test_value):
    """Test a single field."""
    
    alert = create_base_alert(field_name)
    alert[field_name] = test_value
    
    payload = {"request_data": {"alert": alert}}
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": XSIAM_API_KEY,
        "x-xdr-auth-id": str(XSIAM_API_KEY_ID)
    }
    
    endpoint = f"{XSIAM_API_URL}/public_api/v1/alerts/create_alert"
    
    print(f"\n  Testing: {field_name}")
    print(f"  Value: {test_value}")
    
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"  ✅ SUCCESS")
            return True, "Success"
        else:
            try:
                response_json = response.json()
                error_msg = response_json.get("reply", {}).get("err_extra", response.text)
                print(f"  ❌ FAILED: {error_msg[:100]}")
                return False, error_msg
            except:
                print(f"  ❌ FAILED: HTTP {response.status_code}")
                return False, f"HTTP {response.status_code}"
            
    except Exception as e:
        print(f"  ❌ EXCEPTION: {str(e)}")
        return False, str(e)


def main():
    """Run batch 3 field tests."""
    
    print("\n" + "=" * 80)
    print("BATCH 3: UNTESTED CORE ALERT FIELDS + HIGH-VALUE FIELDS")
    print("=" * 80)
    print(f"\nTesting {len(CORE_ALERT_FIELDS_BATCH3)} Core Alert Fields")
    print(f"Testing {len(HIGH_VALUE_FIELDS)} High-Value Fields")
    print(f"Total tests: {len(ALL_TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    
    results = {}
    successful = []
    failed = []
    
    for i, test_case in enumerate(ALL_TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(ALL_TEST_CASES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message = test_field(test_case["name"], test_case["value"])
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "test_value": test_case["value"]
        }
        
        if success:
            successful.append(test_case["name"])
        else:
            failed.append(test_case["name"])
        
        time.sleep(0.5)
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("BATCH 3 SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ NEW Working Fields: {len(successful)}")
    print(f"❌ Failed: {len(failed)}")
    
    if successful:
        print(f"\n✅ ALL NEW WORKING FIELDS:")
        for field in successful:
            value_str = str(results[field]['test_value'])
            if len(value_str) > 50:
                value_str = value_str[:50] + "..."
            print(f"  ✅ {field} = {value_str}")
    
    print(f"\n🎉 TOTAL WORKING FIELDS NOW: {98 + len(successful)}")
    print()


if __name__ == "__main__":
    main()
