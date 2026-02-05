#!/usr/bin/env python3
"""
Complete Comprehensive Field Test - All Untested Fields from Real XSIAM Alerts
===============================================================================

Based on 305 unique fields extracted from real production XSIAM alerts.
Testing only NEW fields we haven't tested yet to discover more working fields.
"""

import json
import requests
import os
import struct
import socket
from dotenv import load_dotenv
from datetime import datetime
import time

load_dotenv()

XSIAM_API_URL = os.getenv("XSIAM_API_URL")
XSIAM_API_KEY = os.getenv("XSIAM_API_KEY")
XSIAM_API_KEY_ID = os.getenv("XSIAM_API_KEY_ID")


def ip_to_int(ip_string):
    """Convert IP address string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip_string))[0]


def create_base_alert(test_name):
    """Create minimal valid alert."""
    return {
        "vendor": "TestVendor",
        "product": "TestProduct",
        "severity": "high",
        "category": "Malware",
        "alert_id": f"TEST-COMPLETE-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Complete field test: {test_name}"
    }


# Comprehensive test of ALL untested fields from real XSIAM alerts (305 total)
# Organized by category, testing only underscored versions (those work)
COMPLETE_TEST_CASES = [
    # === ACTION FIELDS (from real alerts) ===
    {
        "name": "action_country",
        "test_value": "US",
        "expected_type": "string"
    },
    {
        "name": "action_external_hostname",
        "test_value": "evil-server.malicious.com",
        "expected_type": "string"
    },
    {
        "name": "action_local_ip",
        "test_value": "172.29.2.46",
        "expected_type": "string"
    },
    {
        "name": "action_local_port",
        "test_value": 60346,
        "expected_type": "int"
    },
    {
        "name": "action_remote_ip",
        "test_value": "185.234.219.76",
        "expected_type": "string"
    },
    {
        "name": "action_remote_port",
        "test_value": 443,
        "expected_type": "int"
    },
    
    # === ACTOR/PROCESS FIELDS ===
    {
        "name": "actor_process_command_line",
        "test_value": "msedge.exe --no-sandbox",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_name",
        "test_value": "msedge.exe",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_path",
        "test_value": "C:\\\\Program Files\\\\Microsoft\\\\Edge\\\\msedge.exe",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_sha256",
        "test_value": "e0f315a910252f094696b53060508656126829289b6a633683a48e0416007a09",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_md5",
        "test_value": "362c64dd47030e598714ae974524bfec",
        "expected_type": "string"
    },
    {
        "name": "actor_process_signature_status",
        "test_value": "Signed",
        "expected_type": "string"
    },
    {
        "name": "actor_process_signature_vendor",
        "test_value": "Microsoft Corporation",
        "expected_type": "string"
    },
    {
        "name": "actor_process_os_pid",
        "test_value": 4284,
        "expected_type": "int"
    },
    
    # === CAUSALITY ACTOR PROCESS ===
    {
        "name": "causality_actor_process_command_line",
        "test_value": "msedge.exe --profile-directory=Default",
        "expected_type": "string"
    },
    {
        "name": "causality_actor_process_image_name",
        "test_value": "msedge.exe",
        "expected_type": "string"
    },
    {
        "name": "causality_actor_process_image_path",
        "test_value": "C:\\\\Program Files\\\\Microsoft\\\\Edge\\\\msedge.exe",
        "expected_type": "string"
    },
    {
        "name": "causality_actor_process_image_sha256",
        "test_value": "e0f315a910252f094696b53060508656126829289b6a633683a48e0416007a09",
        "expected_type": "string"
    },
    {
        "name": "causality_actor_process_signature_status",
        "test_value": "Signed",
        "expected_type": "string"
    },
    {
        "name": "causality_actor_process_execution_time",
        "test_value": 1762959094941,
        "expected_type": "int"
    },
    
    # === AGENT FIELDS ===
    {
        "name": "agent_version",
        "test_value": "8.9.0.14028",
        "expected_type": "string"
    },
    {
        "name": "agent_os_type",
        "test_value": "Windows",
        "expected_type": "string"
    },
    {
        "name": "agent_os_sub_type",
        "test_value": "Windows 10 [10.0 (Build 19045)]",
        "expected_type": "string"
    },
    {
        "name": "agent_install_type",
        "test_value": "STANDARD",
        "expected_type": "string"
    },
    {
        "name": "agent_is_vdi",
        "test_value": False,
        "expected_type": "boolean"
    },
    {
        "name": "agent_host_boot_time",
        "test_value": 1761756829345,
        "expected_type": "int"
    },
    
    # === ALERT FIELDS ===
    {
        "name": "alert_domain",
        "test_value": "DOMAIN_SECURITY",
        "expected_type": "string"
    },
    {
        "name": "alert_type",
        "test_value": "Unclassified",
        "expected_type": "string"
    },
    {
        "name": "alert_id",
        "test_value": "1201973260",
        "expected_type": "string"
    },
    
    # === EVENT FIELDS ===
    {
        "name": "event_id",
        "test_value": "MzYyNjI2Nzk1NTE5MzcyNzY2Ng==",
        "expected_type": "string"
    },
    {
        "name": "event_type",
        "test_value": "Network Connections",
        "expected_type": "string"
    },
    {
        "name": "event_sub_type",
        "test_value": 11,
        "expected_type": "int"
    },
    {
        "name": "event_timestamp",
        "test_value": 1762960415102,
        "expected_type": "int"
    },
    
    # === DETECTION FIELDS ===
    {
        "name": "detection_timestamp",
        "test_value": 1762960415000,
        "expected_type": "int"
    },
    {
        "name": "name",
        "test_value": "Malware Detection Alert",
        "expected_type": "string"
    },
    {
        "name": "description",
        "test_value": "Test malware detection on endpoint",
        "expected_type": "string"
    },
    {
        "name": "source",
        "test_value": "XDR Agent - Behavioral Analysis",
        "expected_type": "string"
    },
    
    # === HOST FIELDS ===
    {
        "name": "host_ip_list",
        "test_value": ["172.29.2.46"],
        "expected_type": "array"
    },
    {
        "name": "endpoint_id",
        "test_value": "48451bd4bfc441ec902304b01fe51e96",
        "expected_type": "string"
    },
    
    # === DNS FIELDS ===
    {
        "name": "dns_query_name",
        "test_value": "malicious-domain.com",
        "expected_type": "string"
    },
    
    # === FIREWALL FIELDS ===
    {
        "name": "fw_app_id",
        "test_value": "web-browsing",
        "expected_type": "string"
    },
    {
        "name": "fw_app_category",
        "test_value": "collaboration",
        "expected_type": "string"
    },
    {
        "name": "fw_app_subcategory",
        "test_value": "web-browsing",
        "expected_type": "string"
    },
    {
        "name": "fw_app_technology",
        "test_value": "browser-based",
        "expected_type": "string"
    },
    {
        "name": "fw_device_name",
        "test_value": "pa-firewall-01",
        "expected_type": "string"
    },
    {
        "name": "fw_rule",
        "test_value": "Allow Internet Access",
        "expected_type": "string"
    },
    {
        "name": "fw_rule_id",
        "test_value": "rule-12345",
        "expected_type": "string"
    },
    {
        "name": "fw_serial_number",
        "test_value": "007900000716735",
        "expected_type": "string"
    },
    {
        "name": "fw_interface_from",
        "test_value": "trust",
        "expected_type": "string"
    },
    {
        "name": "fw_interface_to",
        "test_value": "untrust",
        "expected_type": "string"
    },
    {
        "name": "fw_is_phishing",
        "test_value": "No",
        "expected_type": "string"
    },
    {
        "name": "fw_vsys",
        "test_value": "vsys1",
        "expected_type": "string"
    },
    
    # === MITRE ATT&CK ===
    {
        "name": "mitre_tactic_id_and_name",
        "test_value": "TA0001 - Initial Access",
        "expected_type": "string"
    },
    {
        "name": "mitre_technique_id_and_name",
        "test_value": "T1078.002 - Valid Accounts: Domain Accounts",
        "expected_type": "string"
    },
    
    # === RESOLUTION/STATUS ===
    {
        "name": "resolution_status",
        "test_value": "STATUS_010_NEW",
        "expected_type": "string"
    },
    {
        "name": "resolution_comment",
        "test_value": "Alert under investigation",
        "expected_type": "string"
    },
    
    # === ASSOCIATION/MATCHING ===
    {
        "name": "association_strength",
        "test_value": 50,
        "expected_type": "int"
    },
    {
        "name": "matching_status",
        "test_value": "MATCHED",
        "expected_type": "string"
    },
    {
        "name": "is_whitelisted",
        "test_value": False,
        "expected_type": "boolean"
    },
    {
        "name": "is_pcap",
        "test_value": False,
        "expected_type": "boolean"
    },
    
    # === MAC ADDRESS ===
    {
        "name": "mac",
        "test_value": "00:50:56:8c:f5:66",
        "expected_type": "string"
    },
    
    # === CONTAINS FEATURED ===
    {
        "name": "contains_featured_host",
        "test_value": "NO",
        "expected_type": "string"
    },
    {
        "name": "contains_featured_ip",
        "test_value": "NO",
        "expected_type": "string"
    },
    {
        "name": "contains_featured_user",
        "test_value": "NO",
        "expected_type": "string"
    },
    
    # === EXTERNAL ID ===
    {
        "name": "external_id",
        "test_value": "7564104940663388564",
        "expected_type": "string"
    },
    
    # === ORIGINAL TAGS ===
    {
        "name": "original_tags",
        "test_value": "DS:XDR Agent,DOM:Security,SEVERITY:Critical",
        "expected_type": "string"
    },
]


def test_field(field_name, test_value, description):
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
            return True, "Success", test_value
        else:
            try:
                response_json = response.json()
                error_msg = response_json.get("reply", {}).get("err_extra", response.text)
                print(f"  ❌ FAILED: {error_msg}")
                return False, error_msg, test_value
            except:
                print(f"  ❌ FAILED: HTTP {response.status_code}")
                return False, f"HTTP {response.status_code}", test_value
            
    except Exception as e:
        print(f"  ❌ EXCEPTION: {str(e)}")
        return False, str(e), test_value


def main():
    """Run complete comprehensive field tests."""
    
    print("\n" + "=" * 80)
    print("COMPLETE COMPREHENSIVE FIELD TEST - All Untested Fields")
    print("=" * 80)
    print("\nTesting ALL new fields from real XSIAM alerts (305 total unique fields)")
    print(f"Fields in this test: {len(COMPLETE_TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    print(f"   URL: {XSIAM_API_URL}")
    
    results = {}
    successful = []
    failed = []
    
    # Test each field
    for i, test_case in enumerate(COMPLETE_TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(COMPLETE_TEST_CASES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message, value = test_field(
            test_case["name"],
            test_case["test_value"],
            test_case["expected_type"]
        )
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "test_value": value,
            "expected_type": test_case["expected_type"]
        }
        
        if success:
            successful.append(test_case["name"])
        else:
            failed.append(test_case["name"])
        
        # Rate limiting
        time.sleep(0.5)
    
    # Generate Complete Field Guide
    print(f"\n{'=' * 80}")
    print("GENERATING COMPLETE FIELD GUIDE")
    print(f"{'=' * 80}\n")
    
    guide_content = f"""# XSIAM Custom Alert Field Guide - COMPLETE
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total fields tested in this run: {len(COMPLETE_TEST_CASES)}
- NEW working fields discovered: {len(successful)}
- Failed fields: {len(failed)}

## ✅ NEW Working Fields Discovered ({len(successful)})

"""
    
    for field_name in successful:
        result = results[field_name]
        value = result["test_value"]
        value_display = json.dumps(value)
        
        guide_content += f"""### {field_name}
- **Type**: {result['expected_type']}
- **Example**: `{value_display}`

"""
    
    if failed:
        guide_content += f"\n## ❌ Failed Fields ({len(failed)})\n\n"
        for field_name in failed:
            result = results[field_name]
            guide_content += f"""### {field_name}
- **Error**: {result['message']}
- **Attempted value**: `{json.dumps(result['test_value'])}`

"""
    
    # Save guide
    guide_path = "/Users/mabutbul/Desktop/agentix_issues/FIELD_GUIDE_COMPLETE.md"
    with open(guide_path, "w") as f:
        f.write(guide_content)
    
    print(f"✅ Complete field guide saved to: {guide_path}")
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ NEW Working Fields: {len(successful)}")
    print(f"❌ Failed: {len(failed)}")
    
    if successful:
        print(f"\n✅ NEW WORKING FIELDS DISCOVERED:")
        for field in successful:
            print(f"  ✅ {field}")
    
    print()


if __name__ == "__main__":
    main()
