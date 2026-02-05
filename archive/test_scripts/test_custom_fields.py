#!/usr/bin/env python3
"""
Simple Test: Create Custom Alert with Custom Fields
====================================================

Goal: Test if XSIAM accepts custom fields and understand exact field naming/types.

Based on data/fields_from_xsiam.txt:
- hostname: Short Text (string)
- username: Multi Select (array)
- hostip: Multi Select (array)
- filesha256: Multi Select (array)
- remoteip: Multi Select (array)
"""

import json
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment
load_dotenv()

XSIAM_API_URL = os.getenv("XSIAM_API_URL")
XSIAM_API_KEY = os.getenv("XSIAM_API_KEY")
XSIAM_API_KEY_ID = os.getenv("XSIAM_API_KEY_ID")

# Test 1: Minimal alert with NO underscores (as shown in fields_from_xsiam.txt)
test_alert_no_underscores = {
    "request_data": {
        "alert": {
            # Required fields
            "vendor": "TestVendor",
            "product": "TestProduct",
            "severity": "high",
            "category": "Malware",
            "alert_id": f"TEST-NO-UNDERSCORE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": int(datetime.now().timestamp() * 1000),
            "description": "Test alert to verify custom field acceptance - NO underscores",
            
            # Custom fields - NO underscores (matching fields_from_xsiam.txt machine names)
            "hostname": "TEST-WORKSTATION-01",           # Short Text
            "username": ["john.doe@company.com"],        # Multi Select (array)
            "hostip": ["192.168.1.100"],                 # Multi Select (array)
            "filesha256": ["abc123def456..."],           # Multi Select (array)
            "remoteip": ["10.0.0.50"]                    # Multi Select (array)
        }
    }
}

# Test 2: Same alert WITH underscores (as recommended in XSIAM documentation)
test_alert_with_underscores = {
    "request_data": {
        "alert": {
            # Required fields
            "vendor": "TestVendor",
            "product": "TestProduct",
            "severity": "high",
            "category": "Malware",
            "alert_id": f"TEST-WITH-UNDERSCORE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": int(datetime.now().timestamp() * 1000),
            "description": "Test alert to verify custom field acceptance - WITH underscores",
            
            # Custom fields - WITH underscores (XSIAM docs say to use underscores)
            "host_name": "TEST-WORKSTATION-02",
            "user_name": ["jane.smith@company.com"],
            "host_ip": ["192.168.1.101"],
            "file_sha256": ["def789abc123..."],
            "remote_ip": ["10.0.0.51"]
        }
    }
}


def test_inject_alert(test_name: str, alert_payload: dict):
    """Test injecting an alert and print detailed response."""
    
    print(f"\n{'=' * 70}")
    print(f"TEST: {test_name}")
    print(f"{'=' * 70}")
    
    # Build headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": XSIAM_API_KEY,
        "x-xdr-auth-id": str(XSIAM_API_KEY_ID)
    }
    
    endpoint = f"{XSIAM_API_URL}/public_api/v1/alerts/create_alert"
    
    print(f"\nEndpoint: {endpoint}")
    print(f"\nPayload:")
    print(json.dumps(alert_payload, indent=2))
    
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=alert_payload,
            timeout=30
        )
        
        print(f"\n--- RESPONSE ---")
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        try:
            response_json = response.json()
            print(f"Body:")
            print(json.dumps(response_json, indent=2))
        except:
            print(f"Body (raw text):")
            print(response.text)
        
        if response.status_code == 200:
            print(f"\n✅ SUCCESS: Alert created successfully!")
            return True
        else:
            print(f"\n❌ FAILED: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"\n❌ EXCEPTION: {str(e)}")
        return False


def main():
    """Run tests."""
    
    print("\n" + "=" * 70)
    print("CUSTOM FIELDS TEST - XSIAM Alert Injection")
    print("=" * 70)
    print(f"\nGoal: Understand which field naming convention works:")
    print(f"  1. NO underscores: hostname, username, hostip, filesha256, remoteip")
    print(f"  2. WITH underscores: host_name, user_name, host_ip, file_sha256, remote_ip")
    print(f"\nNote: Multi Select fields MUST be arrays, not strings!")
    
    # Verify config
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        print(f"   XSIAM_API_URL: {bool(XSIAM_API_URL)}")
        print(f"   XSIAM_API_KEY: {bool(XSIAM_API_KEY)}")
        print(f"   XSIAM_API_KEY_ID: {bool(XSIAM_API_KEY_ID)}")
        return
    
    print(f"\n✅ Environment configured")
    print(f"   URL: {XSIAM_API_URL}")
    print(f"   Key ID: {XSIAM_API_KEY_ID}")
    
    # Run tests
    result1 = test_inject_alert("NO UNDERSCORES (fields_from_xsiam.txt format)", test_alert_no_underscores)
    
    input("\nPress Enter to run second test...")
    
    result2 = test_inject_alert("WITH UNDERSCORES (XSIAM docs format)", test_alert_with_underscores)
    
    # Summary
    print(f"\n{'=' * 70}")
    print(f"TEST SUMMARY")
    print(f"{'=' * 70}")
    print(f"Test 1 (NO underscores):   {'✅ PASSED' if result1 else '❌ FAILED'}")
    print(f"Test 2 (WITH underscores): {'✅ PASSED' if result2 else '❌ FAILED'}")
    print()


if __name__ == "__main__":
    main()
