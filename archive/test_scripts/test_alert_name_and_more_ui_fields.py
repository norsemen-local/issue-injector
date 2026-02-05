#!/usr/bin/env python3
"""
Test Alert Name Field + More UI Fields
=====================================

CRITICAL: Finding the alert NAME field
Plus testing more high-priority UI fields we haven't tested yet
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
        "alert_id": f"TEST-NAME-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Alert name test: {test_name}"
    }


# PRIORITY 1: Alert Name Candidates
ALERT_NAME_CANDIDATES = [
    {"name": "alert_name", "value": "Critical Malware Detected"},
    {"name": "issue_name", "value": "Critical Malware Detected"},
    {"name": "detection_name", "value": "Critical Malware Detected"},
    {"name": "incident_name", "value": "Critical Malware Detected"},
    {"name": "rule_name", "value": "Critical Malware Detected"},
    {"name": "original_alert_name", "value": "Critical Malware Detected"},
    {"name": "threat_name", "value": "Critical Malware Detected"},
    {"name": "malware_name", "value": "Critical Malware Detected"},
    {"name": "title", "value": "Critical Malware Detected"},
    {"name": "subject", "value": "Critical Malware Detected"},
]

# PRIORITY 2: More Important UI Fields Not Yet Tested
MORE_UI_FIELDS = [
    # Process Fields
    {"name": "process_cmd", "value": ["cmd.exe /c dir"]},
    {"name": "process_md5", "value": ["abc123"]},
    {"name": "process_sha256", "value": ["def456"]},
    {"name": "process_names", "value": ["cmd.exe", "powershell.exe"]},
    {"name": "process_paths", "value": ["C:\\\\Windows\\\\System32\\\\cmd.exe"]},
    {"name": "parent_process_name", "value": ["explorer.exe"]},
    {"name": "parent_process_cmd", "value": ["explorer.exe"]},
    {"name": "parent_process_md5", "value": ["abc123"]},
    {"name": "parent_process_sha256", "value": ["def456"]},
    
    # Identity/User Fields
    {"name": "user_id", "value": "U12345"},
    {"name": "user_groups", "value": ["Administrators", "Domain Users"]},
    {"name": "identity_type", "value": ["User"]},
    
    # Email Fields
    {"name": "email_subject", "value": ["Urgent: Review Required"]},
    {"name": "email_sender", "value": ["attacker@evil.com"]},
    {"name": "email_recipient", "value": ["victim@corp.com"]},
    
    # Detection/Source Fields
    {"name": "source_brand", "value": "XDR Agent"},
    {"name": "log_source", "value": "Windows Event Log"},
    {"name": "log_source_name", "value": ["Security"]},
    
    # Severity/Priority
    {"name": "external_severity", "value": ["Critical"]},
    {"name": "external_status", "value": ["Open"]},
    
    # Asset Fields
    {"name": "asset_id", "value": "ASSET-12345"},
    {"name": "device_id", "value": "DEVICE-12345"},
    {"name": "device_name", "value": "DESKTOP-WORKSTATION"},
    
    # Network Fields
    {"name": "destination_zone_name", "value": ["untrust"]},
    {"name": "source_zone_name", "value": ["trust"]},
    {"name": "protocol_names", "value": ["TCP", "HTTP"]},
    
    # MITRE Fields
    {"name": "mitre_tactic_id", "value": ["TA0001"]},
    {"name": "mitre_tactic_name", "value": ["Initial Access"]},
    {"name": "mitre_technique_id", "value": ["T1078"]},
    {"name": "mitre_technique_name", "value": ["Valid Accounts"]},
    {"name": "mitre_att&ck_tactic", "value": ["Initial Access"]},
    {"name": "mitre_att&ck_technique", "value": ["Valid Accounts"]},
    
    # URL/Domain Fields
    {"name": "urls", "value": ["http://evil.com", "http://malicious.net"]},
    {"name": "domain_name", "value": ["evil.com"]},
    
    # Category/Type Fields
    {"name": "category", "value": "Malware"},
    {"name": "sub_category", "value": "Trojan"},
    {"name": "alert_type_id", "value": "TYPE-123"},
    
    # Cloud/SaaS Fields
    {"name": "cloud_service_name", "value": "S3"},
    {"name": "cloud_provider_account_id", "value": "123456789012"},
    
    # Risk/Score Fields
    {"name": "risk_score", "value": "95"},
    {"name": "risk_rating", "value": "Critical"},
    
    # Timestamp Fields
    {"name": "occurred", "value": "2025-11-26T17:00:00Z"},
    {"name": "start_time", "value": "2025-11-26T17:00:00Z"},
]

ALL_TEST_CASES = ALERT_NAME_CANDIDATES + MORE_UI_FIELDS


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
                print(f"  ❌ FAILED: {error_msg}")
                return False, error_msg
            except:
                print(f"  ❌ FAILED: HTTP {response.status_code}")
                return False, f"HTTP {response.status_code}"
            
    except Exception as e:
        print(f"  ❌ EXCEPTION: {str(e)}")
        return False, str(e)


def main():
    """Run alert name + UI field tests."""
    
    print("\n" + "=" * 80)
    print("ALERT NAME + MORE UI FIELDS TEST")
    print("=" * 80)
    print(f"\n🎯 PRIORITY: Finding the alert NAME field!")
    print(f"Testing {len(ALERT_NAME_CANDIDATES)} name candidates + {len(MORE_UI_FIELDS)} more UI fields")
    print(f"Total tests: {len(ALL_TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    
    results = {}
    successful = []
    failed = []
    name_field_found = None
    
    # Test alert name candidates first
    print(f"\n{'=' * 80}")
    print("TESTING ALERT NAME CANDIDATES")
    print(f"{'=' * 80}")
    
    for i, test_case in enumerate(ALERT_NAME_CANDIDATES, 1):
        print(f"\n{'=' * 80}")
        print(f"NAME CANDIDATE {i}/{len(ALERT_NAME_CANDIDATES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message = test_field(test_case["name"], test_case["value"])
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "test_value": test_case["value"]
        }
        
        if success:
            successful.append(test_case["name"])
            if name_field_found is None:
                name_field_found = test_case["name"]
                print(f"\n🎉 🎉 🎉 ALERT NAME FIELD FOUND: {name_field_found} 🎉 🎉 🎉")
        else:
            failed.append(test_case["name"])
        
        time.sleep(0.5)
    
    # Test more UI fields
    print(f"\n{'=' * 80}")
    print("TESTING MORE UI FIELDS")
    print(f"{'=' * 80}")
    
    for i, test_case in enumerate(MORE_UI_FIELDS, 1):
        print(f"\n{'=' * 80}")
        print(f"UI FIELD {i}/{len(MORE_UI_FIELDS)}: {test_case['name']}")
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
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ NEW Working Fields: {len(successful)}")
    print(f"❌ Failed: {len(failed)}")
    
    if name_field_found:
        print(f"\n🎯 🎯 🎯 ALERT NAME FIELD DISCOVERED: {name_field_found} 🎯 🎯 🎯")
    else:
        print(f"\n❌ Alert name field NOT found in tested candidates")
    
    if successful:
        print(f"\n✅ ALL NEW WORKING FIELDS:")
        for field in successful:
            value_str = str(results[field]['test_value'])
            if len(value_str) > 50:
                value_str = value_str[:50] + "..."
            print(f"  ✅ {field} = {value_str}")
    
    print()


if __name__ == "__main__":
    main()
