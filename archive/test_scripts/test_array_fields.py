#!/usr/bin/env python3
"""
Test Array-Type Fields - Retry with Array Format
=================================================

These 7 fields failed with "should be type of List" error:
- agent_version
- event_type
- dns_query_name
- fw_rule_id
- fw_serial_number
- contains_featured_host
- contains_featured_user
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
        "alert_id": f"TEST-ARRAY-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:20]}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Array field test: {test_name}"
    }


ARRAY_TEST_CASES = [
    {
        "name": "agent_version",
        "test_value": ["8.9.0.14028"]
    },
    {
        "name": "event_type",
        "test_value": ["Network Connections"]
    },
    {
        "name": "dns_query_name",
        "test_value": ["malicious-domain.com"]
    },
    {
        "name": "fw_rule_id",
        "test_value": ["rule-12345"]
    },
    {
        "name": "fw_serial_number",
        "test_value": ["007900000716735"]
    },
    {
        "name": "contains_featured_host",
        "test_value": ["NO"]
    },
    {
        "name": "contains_featured_user",
        "test_value": ["NO"]
    }
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
    """Run array field tests."""
    
    print("\n" + "=" * 80)
    print("ARRAY FIELD TEST - Retry with Array Format")
    print("=" * 80)
    print(f"\nTesting {len(ARRAY_TEST_CASES)} fields that require array format")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    
    results = {}
    successful = []
    failed = []
    
    for i, test_case in enumerate(ARRAY_TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(ARRAY_TEST_CASES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message = test_field(test_case["name"], test_case["test_value"])
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "test_value": test_case["test_value"]
        }
        
        if success:
            successful.append(test_case["name"])
        else:
            failed.append(test_case["name"])
        
        time.sleep(0.5)
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("ARRAY FIELD TEST SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ NEW Working Fields: {len(successful)}")
    print(f"❌ Still Failed: {len(failed)}")
    
    if successful:
        print(f"\n✅ NEW WORKING ARRAY FIELDS:")
        for field in successful:
            print(f"  ✅ {field} = {results[field]['test_value']}")
    
    if failed:
        print(f"\n❌ STILL FAILING:")
        for field in failed:
            print(f"  ❌ {field}: {results[field]['message']}")
    
    print()


if __name__ == "__main__":
    main()
