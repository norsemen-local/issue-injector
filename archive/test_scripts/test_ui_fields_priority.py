#!/usr/bin/env python3
"""
Test UI Field Names with Underscore Transformation - Priority Fields
====================================================================

Testing field names from fields_from_xsiam.txt (UI fields) with spaces/hyphens replaced by underscores.
Example: "CGO name" → "cgo_name", "File Macro SHA256" → "file_macro_sha256"

Prioritizing fields that:
1. Appear in real alerts (from entry_artifact files)
2. Haven't been tested yet
3. Are commonly used Core Alert Fields
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
        "alert_id": f"TEST-UI-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"UI field test: {test_name}"
    }


# Priority UI fields to test (transformed with underscores, lowercase)
# Focus on Core Alert Fields and common fields
UI_FIELD_TEST_CASES = [
    # CGO Fields (Causality Group Owner)
    {"name": "cgo_cmd", "value": ["cmd.exe /c whoami"]},
    {"name": "cgo_md5", "value": ["d41d8cd98f00b204e9800998ecf8427e"]},
    {"name": "cgo_name", "value": ["malware.exe"]},
    {"name": "cgo_path", "value": ["C:\\\\Temp\\\\malware.exe"]},
    {"name": "cgo_sha256", "value": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
    {"name": "cgo_signature", "value": ["Signed"]},
    {"name": "cgo_signer", "value": ["Microsoft Corporation"]},
    
    # File Fields (UI names)
    {"name": "file_macro_sha256", "value": ["abc123def456"]},
    {"name": "file_md5", "value": ["5d41402abc4b2a76b9719d911017c592"]},
    {"name": "file_sha1", "value": ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"]},
    
    # Initiator Fields
    {"name": "initiator_cmd", "value": ["powershell.exe"]},
    {"name": "initiator_md5", "value": ["abc123"]},
    {"name": "initiator_path", "value": ["C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"]},
    {"name": "initiator_pid", "value": [1234]},
    {"name": "initiator_sha256", "value": ["def456"]},
    {"name": "initiator_signature", "value": ["Signed"]},
    {"name": "initiator_signer", "value": ["Microsoft Corporation"]},
    {"name": "initiator_tid", "value": [5678]},
    
    # OS Parent Fields
    {"name": "os_parent_cmd", "value": ["explorer.exe"]},
    {"name": "os_parent_id", "value": [100]},
    {"name": "os_parent_name", "value": ["explorer.exe"]},
    {"name": "os_parent_pid", "value": [100]},
    {"name": "os_parent_sha256", "value": ["abc123"]},
    {"name": "os_parent_signature", "value": ["Signed"]},
    {"name": "os_parent_signer", "value": ["Microsoft Corporation"]},
    {"name": "os_parent_user_name", "value": ["SYSTEM"]},
    
    # Target Process Fields
    {"name": "target_process_cmd", "value": ["notepad.exe"]},
    {"name": "target_process_name", "value": ["notepad.exe"]},
    {"name": "target_process_sha256", "value": ["def789"]},
    
    # Network/Firewall Fields
    {"name": "fw_name", "value": ["pa-220"]},
    {"name": "fw_rule_name", "value": ["Allow-Internet"]},
    {"name": "ngfw_vsys_name", "value": ["vsys1"]},
    
    # Cloud Fields
    {"name": "cloud_project", "value": ["my-project"]},
    {"name": "cloud_provider", "value": ["AWS"]},
    {"name": "container_name", "value": ["nginx-container"]},
    {"name": "cluster_name", "value": ["prod-cluster"]},
    {"name": "namespace", "value": ["default"]},
    {"name": "image_name", "value": ["nginx:latest"]},
    
    # Host Fields
    {"name": "host_fqdn", "value": "desktop.corp.local"},
    {"name": "host_mac_address", "value": "00:50:56:8c:f5:66"},
    {"name": "host_os", "value": "Windows 10"},
    {"name": "host_risk_level", "value": "High"},
    {"name": "host_risk_reasons", "value": ["Malware detected", "Suspicious process"]},
    
    # User Fields
    {"name": "user_risk_level", "value": "Medium"},
    {"name": "user_risk_reasons", "value": ["Failed logins", "Unusual activity"]},
    
    # Detection Fields
    {"name": "detection_method", "value": "XDR Agent"},
    {"name": "detection_rule_id", "value": "rule-12345"},
    
    # Case/Story Fields
    {"name": "case_id", "value": 12345},
    {"name": "case_ids", "value": [12345, 12346]},
    
    # IPv6 Fields
    {"name": "local_ipv6", "value": ["fe80::1"]},
    {"name": "remote_ipv6", "value": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"]},
    
    # Additional Important Fields
    {"name": "agent_id", "value": "agent-12345"},
    {"name": "initiated_by", "value": ["john.doe"]},
    {"name": "is_phishing", "value": ["YES"]},
    {"name": "module", "value": ["Behavioral Threat Protection"]},
    {"name": "operation_name", "value": ["CreateProcess"]},
    {"name": "registry_data", "value": ["test_value"]},
    {"name": "registry_full_key", "value": ["HKLM\\\\Software\\\\Test"]},
    {"name": "user_agent", "value": ["Mozilla/5.0"]},
    
    # XDM Fields (these are Core Alert Fields with xdm prefix)
    {"name": "xdm_domain", "value": "evil.com"},
    {"name": "xdm_event_type", "value": ["Network Connection"]},
    {"name": "xdm_file_sha256", "value": "abc123def456"},
]


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
                print(f"  ❌ FAILED: {error_msg}")
                return False, error_msg
            except:
                print(f"  ❌ FAILED: HTTP {response.status_code}")
                return False, f"HTTP {response.status_code}"
            
    except Exception as e:
        print(f"  ❌ EXCEPTION: {str(e)}")
        return False, str(e)


def main():
    """Run UI field tests."""
    
    print("\n" + "=" * 80)
    print("UI FIELD TEST - Transformed Field Names from XSIAM UI")
    print("=" * 80)
    print(f"\nTesting {len(UI_FIELD_TEST_CASES)} priority UI fields")
    print("Field names transformed: spaces/hyphens → underscores, lowercase")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    
    results = {}
    successful = []
    failed = []
    
    for i, test_case in enumerate(UI_FIELD_TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(UI_FIELD_TEST_CASES)}: {test_case['name']}")
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
    print("UI FIELD TEST SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ NEW Working Fields: {len(successful)}")
    print(f"❌ Failed: {len(failed)}")
    
    if successful:
        print(f"\n✅ NEW WORKING UI FIELDS:")
        for field in successful:
            print(f"  ✅ {field} = {results[field]['test_value']}")
    
    if failed:
        print(f"\n❌ FAILED UI FIELDS:")
        for field in failed:
            print(f"  ❌ {field}: {results[field]['message'][:100]}")
    
    print()


if __name__ == "__main__":
    main()
