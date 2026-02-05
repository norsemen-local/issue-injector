#!/usr/bin/env python3
"""
Test Batch 4 - Retry Failed Fields with Different Data Types + More New Fields
==============================================================================

Testing fields that failed with alternative data types, plus new high-value fields
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
        "alert_id": f"TEST-B4-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Batch 4 test: {test_name}"
    }


# RETRY: Fields that failed - try different data types/values
RETRY_FIELDS = [
    # device_id failed with string, try array
    {"name": "device_id", "value": ["DEVICE-12345"]},
    
    # Signature fields failed with array, try string
    {"name": "cgo_signature", "value": "Signed"},
    {"name": "initiator_signature", "value": "Signed"},
    {"name": "os_parent_signature", "value": "Signed"},
    {"name": "process_execution_signature", "value": "Signed"},
    
    # MITRE fields - try as string instead of array
    {"name": "mitre_att&ck_tactic", "value": "TA0001 - Initial Access"},
    {"name": "mitre_att&ck_technique", "value": "T1078.002 - Valid Accounts: Domain Accounts"},
    
    # host_os failed with enum, try valid enum value
    {"name": "host_os", "value": "AGENT_OS_WINDOWS"},
    
    # country - try as string instead of array
    {"name": "country", "value": "US"},
    
    # detection_rule_id - try as array
    {"name": "detection_rule_id", "value": ["RULE-12345"]},
]

# NEW FIELDS: More high-value untested fields
NEW_FIELDS_BATCH4 = [
    # XDM fields (many in the list, let's test some)
    {"name": "xdm_source_ipv4", "value": ["203.0.113.1"]},
    {"name": "xdm_target_ipv4", "value": ["192.168.1.100"]},
    {"name": "xdm_source_port", "value": [50234]},
    {"name": "xdm_target_port", "value": [443]},
    {"name": "xdm_file_filename", "value": "malware.exe"},
    {"name": "xdm_file_path", "value": ["C:\\\\Windows\\\\Temp\\\\malware.exe"]},
    {"name": "xdm_file_sha256", "value": "abc123def456"},
    
    # More process fields
    {"name": "process_id", "value": ["1234"]},
    {"name": "parent_process_id", "value": "5678"},
    {"name": "process_creation_time", "value": ["2025-11-26T17:00:00Z"]},
    
    # User fields
    {"name": "user_groups", "value": ["Administrators", "Domain Users"]},
    {"name": "user_sid", "value": ["S-1-5-21-123456789-1234567890-1234567890-1001"]},
    
    # Email fields
    {"name": "email_cc", "value": "cc@example.com"},
    {"name": "email_bcc", "value": "bcc@example.com"},
    {"name": "email_message_id", "value": "msg-12345@example.com"},
    {"name": "email_reply_to", "value": "reply@example.com"},
    
    # Network/Protocol
    {"name": "protocol_names", "value": ["TCP"]},
    
    # Detection/Source fields
    {"name": "source_status", "value": "Active"},
    {"name": "source_category", "value": "Endpoint"},
    {"name": "source_priority", "value": "High"},
    
    # Asset/Device
    {"name": "device_model", "value": "Laptop"},
    {"name": "device_status", "value": "Active"},
    {"name": "device_os_name", "value": ["Windows"]},
    {"name": "device_os_version", "value": ["10"]},
    
    # Location/Region
    {"name": "location", "value": "US-East"},
    {"name": "region", "value": "us-east-1"},
    
    # Threat/Malware
    {"name": "malware_family", "value": "Ransomware"},
    {"name": "threat_actor", "value": "APT-29"},
    
    # Verdict/Classification
    {"name": "verdict", "value": "Malicious"},
    
    # URL/Domain
    {"name": "domain_registrar_abuse_email", "value": "abuse@registrar.com"},
    
    # SHA hashes
    {"name": "sha1", "value": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
    {"name": "sha512", "value": "abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456abc123def456"},
    
    # Risk/Score
    {"name": "risk_name", "value": "High Risk User Activity"},
    
    # Signature/Hash
    {"name": "signature", "value": "Signed"},
    
    # Timestamps
    {"name": "last_seen", "value": "2025-11-26T17:00:00Z"},
    {"name": "first_seen", "value": "2025-11-25T17:00:00Z"},
    
    # Cloud fields
    {"name": "cloud_region_list", "value": ["us-east-1", "us-west-2"]},
    {"name": "cloud_resource_list", "value": ["resource-1", "resource-2"]},
    
    # Account fields
    {"name": "account_status", "value": "Active"},
]

ALL_TEST_CASES = RETRY_FIELDS + NEW_FIELDS_BATCH4


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
    print(f"  Type: {type(test_value).__name__}")
    
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
    """Run batch 4 field tests."""
    
    print("\n" + "=" * 80)
    print("BATCH 4: RETRY FAILED FIELDS + MORE NEW FIELDS")
    print("=" * 80)
    print(f"\nRetrying {len(RETRY_FIELDS)} failed fields with different data types")
    print(f"Testing {len(NEW_FIELDS_BATCH4)} new fields")
    print(f"Total tests: {len(ALL_TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    
    results = {}
    successful = []
    failed = []
    retry_successes = []
    
    # Test retry fields first
    print(f"\n{'=' * 80}")
    print("PHASE 1: RETRYING FAILED FIELDS WITH DIFFERENT DATA TYPES")
    print(f"{'=' * 80}")
    
    for i, test_case in enumerate(RETRY_FIELDS, 1):
        print(f"\n{'=' * 80}")
        print(f"RETRY {i}/{len(RETRY_FIELDS)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message = test_field(test_case["name"], test_case["value"])
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "test_value": test_case["value"]
        }
        
        if success:
            successful.append(test_case["name"])
            retry_successes.append(test_case["name"])
        else:
            failed.append(test_case["name"])
        
        time.sleep(0.5)
    
    # Test new fields
    print(f"\n{'=' * 80}")
    print("PHASE 2: TESTING NEW FIELDS")
    print(f"{'=' * 80}")
    
    for i, test_case in enumerate(NEW_FIELDS_BATCH4, 1):
        print(f"\n{'=' * 80}")
        print(f"NEW FIELD {i}/{len(NEW_FIELDS_BATCH4)}: {test_case['name']}")
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
    print("BATCH 4 SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ Total NEW Working Fields: {len(successful)}")
    if retry_successes:
        print(f"   - Retry successes: {len(retry_successes)} (fixed with different data types!)")
    print(f"❌ Failed: {len(failed)}")
    
    if retry_successes:
        print(f"\n🎯 RETRY SUCCESSES (fixed with different data types):")
        for field in retry_successes:
            value_str = str(results[field]['test_value'])
            if len(value_str) > 50:
                value_str = value_str[:50] + "..."
            print(f"  ✅ {field} = {value_str}")
    
    if successful:
        print(f"\n✅ ALL NEW WORKING FIELDS:")
        for field in successful:
            value_str = str(results[field]['test_value'])
            if len(value_str) > 50:
                value_str = value_str[:50] + "..."
            print(f"  ✅ {field} = {value_str}")
    
    print(f"\n🎉 TOTAL WORKING FIELDS NOW: {133 + len(successful)}")
    print()


if __name__ == "__main__":
    main()
