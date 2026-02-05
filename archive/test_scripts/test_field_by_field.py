#!/usr/bin/env python3
"""
Field-by-Field Test: Understanding XSIAM Custom Field Requirements
===================================================================

Test each custom field individually to understand:
1. Exact field name (with underscores)
2. Required data type (string, array, int, etc.)
3. Field mapping (what XSIAM internally calls it)
"""

import json
import requests
import os
import struct
import socket
from dotenv import load_dotenv
from datetime import datetime

# Load environment
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
        "alert_id": f"TEST-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Field test: {test_name}"
    }


# Define test cases for each field
TEST_CASES = [
    {
        "name": "host_name",
        "description": "Host Name (Short Text per fields_from_xsiam.txt)",
        "variants": [
            {"label": "String value", "value": "TEST-WORKSTATION-01"},
            {"label": "Array with one string", "value": ["TEST-WORKSTATION-01"]},
        ]
    },
    {
        "name": "user_name",
        "description": "User Name (Multi Select per fields_from_xsiam.txt)",
        "variants": [
            {"label": "Array with one string", "value": ["john.doe@company.com"]},
            {"label": "Array with multiple strings", "value": ["john.doe@company.com", "jane.smith@company.com"]},
            {"label": "Single string (wrong?)", "value": "john.doe@company.com"},
        ]
    },
    {
        "name": "host_ip",
        "description": "Host IP (Multi Select per fields_from_xsiam.txt)",
        "variants": [
            {"label": "Array of IP strings", "value": ["192.168.1.100"]},
            {"label": "Array of IP integers", "value": [ip_to_int("192.168.1.100")]},
            {"label": "Single IP integer", "value": ip_to_int("192.168.1.100")},
            {"label": "Array of multiple IP integers", "value": [ip_to_int("192.168.1.100"), ip_to_int("192.168.1.101")]},
        ]
    },
    {
        "name": "file_sha256",
        "description": "File SHA256 (Multi Select per fields_from_xsiam.txt)",
        "variants": [
            {"label": "Array with SHA256 string", "value": ["abc123def456789012345678901234567890123456789012345678901234"]},
            {"label": "Single SHA256 string", "value": "abc123def456789012345678901234567890123456789012345678901234"},
        ]
    },
    {
        "name": "file_name",
        "description": "File Name (Multi Select per fields_from_xsiam.txt)",
        "variants": [
            {"label": "Array with filename", "value": ["malware.exe"]},
            {"label": "Single filename string", "value": "malware.exe"},
        ]
    },
    {
        "name": "remote_ip",
        "description": "Remote IP (Multi Select per fields_from_xsiam.txt)",
        "variants": [
            {"label": "Array of IP strings", "value": ["10.0.0.50"]},
            {"label": "Array of IP integers", "value": [ip_to_int("10.0.0.50")]},
        ]
    },
]


def test_field_variant(field_name, variant_label, field_value):
    """Test a single field with a specific value variant."""
    
    # Create base alert
    alert = create_base_alert(field_name)
    
    # Add the field being tested
    alert[field_name] = field_value
    
    payload = {"request_data": {"alert": alert}}
    
    # Build headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": XSIAM_API_KEY,
        "x-xdr-auth-id": str(XSIAM_API_KEY_ID)
    }
    
    endpoint = f"{XSIAM_API_URL}/public_api/v1/alerts/create_alert"
    
    print(f"\n  Testing: {variant_label}")
    print(f"  Value: {field_value}")
    print(f"  Type: {type(field_value).__name__}")
    
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"  ✅ SUCCESS")
            try:
                response_json = response.json()
                if "reply" in response_json:
                    print(f"     Response: {json.dumps(response_json['reply'], indent=6)}")
            except:
                pass
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
    """Run field-by-field tests."""
    
    print("\n" + "=" * 80)
    print("FIELD-BY-FIELD TEST - XSIAM Custom Fields")
    print("=" * 80)
    print("\nGoal: Understand exact data type and format for each custom field")
    print("\nStrategy: Test each field individually with different data type variants")
    
    # Verify config
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    print(f"   URL: {XSIAM_API_URL}")
    
    # Results summary
    results = {}
    
    # Test each field
    for test_case in TEST_CASES:
        field_name = test_case["name"]
        description = test_case["description"]
        
        print(f"\n{'=' * 80}")
        print(f"TESTING FIELD: {field_name}")
        print(f"Description: {description}")
        print(f"{'=' * 80}")
        
        field_results = []
        
        for variant in test_case["variants"]:
            success, message = test_field_variant(
                field_name,
                variant["label"],
                variant["value"]
            )
            field_results.append({
                "variant": variant["label"],
                "success": success,
                "message": message
            })
        
        results[field_name] = field_results
        
        # Brief pause between fields
        import time
        time.sleep(1)
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("SUMMARY - What Works for Each Field")
    print(f"{'=' * 80}\n")
    
    for field_name, field_results in results.items():
        print(f"\n{field_name}:")
        for result in field_results:
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {result['variant']}")
            if not result["success"]:
                print(f"     Error: {result['message']}")
    
    print()


if __name__ == "__main__":
    main()
