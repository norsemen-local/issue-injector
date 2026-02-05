#!/usr/bin/env python3
"""
Extended Field Test - Core Alert Fields from fields_from_xsiam.txt
===================================================================

Testing Core Alert Fields that we haven't tested yet, 
focusing on fields WITHOUT underscores as shown in the XSIAM system.
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
        "alert_id": f"TEST-EXT-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Extended field test: {test_name}"
    }


# Core Alert Fields to test (based on fields_from_xsiam.txt)
EXTENDED_TEST_CASES = [
    # Try fields WITHOUT underscores (as shown in system)
    {
        "name": "localip",
        "description": "Local IP (Core Alert Fields - Multi Select)",
        "test_value": [ip_to_int("10.100.50.87")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "remoteip",
        "description": "Remote IP (Core Alert Fields - Multi Select)",
        "test_value": [ip_to_int("185.234.219.76")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "localport",
        "description": "Local Port (Core Alert Fields - Multi Select)",
        "test_value": [49872],
        "expected_type": "array"
    },
    {
        "name": "remoteport",
        "description": "Remote Port (Core Alert Fields - Multi Select)",
        "test_value": [443],
        "expected_type": "array"
    },
    {
        "name": "username",
        "description": "User name (Core Alert Fields - Multi Select)",
        "test_value": ["ailestrade@agentix.ad.bakerstreetlabs.io"],
        "expected_type": "array"
    },
    {
        "name": "filename",
        "description": "File name (Core Alert Fields - Multi Select)",
        "test_value": ["malware.exe"],
        "expected_type": "array"
    },
    {
        "name": "filepath",
        "description": "File path (Core Alert Fields - Multi Select)",
        "test_value": ["C:\\\\Users\\\\test\\\\malware.exe"],
        "expected_type": "array"
    },
    {
        "name": "filesha256",
        "description": "File SHA256 (Core Alert Fields - Multi Select)",
        "test_value": ["657c0cce98d6e73e53b4001eeea51ed91fdcf3d47a18712b6ba9c66d59677980"],
        "expected_type": "array"
    },
    {
        "name": "filemd5",
        "description": "File MD5 (Core Alert Fields - Multi Select)",
        "test_value": ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"],
        "expected_type": "array"
    },
    {
        "name": "mitreattcktactic",
        "description": "MITRE ATT&CK Tactic (Core Alert Fields - Multi Select)",
        "test_value": ["TA0002 - Execution"],
        "expected_type": "array"
    },
    {
        "name": "mitreattcktechnique",
        "description": "MITRE ATT&CK Technique (Core Alert Fields - Multi Select)",
        "test_value": ["T1204.002 - User Execution: Malicious File"],
        "expected_type": "array"
    },
    {
        "name": "eventtype",
        "description": "Event Type (Core Alert Fields - Multi Select)",
        "test_value": ["Process Execution"],
        "expected_type": "array"
    },
    {
        "name": "hostname",
        "description": "Host Name (Core Alert Fields - Short Text)",
        "test_value": "DESKTOP-AGENTIX-042",
        "expected_type": "string"
    },
    {
        "name": "hostip",
        "description": "Host IP (Core Alert Fields - Multi Select)",
        "test_value": [ip_to_int("10.100.50.87")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "hostos",
        "description": "Host OS (Core Alert Fields - Single Select)",
        "test_value": "Windows",
        "expected_type": "string"
    },
    {
        "name": "hostrisklevel",
        "description": "Host Risk Level (Core Alert Fields - Short Text)",
        "test_value": "HIGH",
        "expected_type": "string"
    },
    {
        "name": "userrisklevel",
        "description": "User Risk Level (Core Alert Fields - Short Text)",
        "test_value": "MEDIUM",
        "expected_type": "string"
    },
    {
        "name": "domain",
        "description": "Domain (Core Alert Fields - Short Text)",
        "test_value": "agentix.ad.bakerstreetlabs.io",
        "expected_type": "string"
    },
    {
        "name": "dnsqueryname",
        "description": "DNS Query Name (Core Alert Fields - Multi Select)",
        "test_value": ["malicious-domain.com"],
        "expected_type": "array"
    },
    {
        "name": "url",
        "description": "URL (Core Alert Fields - Multi Select)",
        "test_value": ["https://malicious-site[.]com/payload"],
        "expected_type": "array"
    },
    {
        "name": "remotehost",
        "description": "Remote Host (Core Alert Fields - Multi Select)",
        "test_value": ["c2-server.evil[.]com"],
        "expected_type": "array"
    },
    {
        "name": "agentid",
        "description": "Agent Id (Core Alert Fields - Short Text)",
        "test_value": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "expected_type": "string"
    },
    {
        "name": "agentossubtype",
        "description": "Agent OS Sub Type (Core Alert Fields - Short Text)",
        "test_value": "Windows 10 Pro",
        "expected_type": "string"
    },
    {
        "name": "ruleid",
        "description": "Detection Rule ID (Core Alert Fields - Short Text)",
        "test_value": "RULE-12345",
        "expected_type": "string"
    },
    {
        "name": "excluded",
        "description": "Excluded (Core Alert Fields - Boolean)",
        "test_value": False,
        "expected_type": "boolean"
    },
    {
        "name": "starred",
        "description": "Starred (Core Alert Fields - Boolean)",
        "test_value": True,
        "expected_type": "boolean"
    },
    {
        "name": "isphishing",
        "description": "Is Phishing (Core Alert Fields - Multi Select)",
        "test_value": ["YES"],
        "expected_type": "array"
    },
    {
        "name": "emailsubject",
        "description": "Email Subject (Core Alert Fields - Multi Select)",
        "test_value": ["Urgent: Payment Required"],
        "expected_type": "array"
    },
    {
        "name": "emailsender",
        "description": "Email Sender (Core Alert Fields - Multi Select)",
        "test_value": ["attacker@evil.com"],
        "expected_type": "array"
    },
    {
        "name": "emailrecipient",
        "description": "Email Recipient (Core Alert Fields - Multi Select)",
        "test_value": ["victim@company.com"],
        "expected_type": "array"
    },
    {
        "name": "categoryname",
        "description": "Category (Core Alert Fields - Short Text)",
        "test_value": "Malware",
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
    print(f"  Description: {description}")
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
    """Run extended field tests."""
    
    print("\n" + "=" * 80)
    print("EXTENDED FIELD TEST - Core Alert Fields (No Underscores)")
    print("=" * 80)
    print("\nTesting Core Alert Fields from fields_from_xsiam.txt")
    print(f"Total fields to test: {len(EXTENDED_TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    print(f"   URL: {XSIAM_API_URL}")
    
    results = {}
    successful = []
    failed = []
    
    # Test each field
    for i, test_case in enumerate(EXTENDED_TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(EXTENDED_TEST_CASES)}: {test_case['name']}")
        print(f"{'=' * 80}")
        
        success, message, value = test_field(
            test_case["name"],
            test_case["test_value"],
            test_case["description"]
        )
        
        results[test_case["name"]] = {
            "success": success,
            "message": message,
            "description": test_case["description"],
            "test_value": value,
            "expected_type": test_case["expected_type"]
        }
        
        if success:
            successful.append(test_case["name"])
        else:
            failed.append(test_case["name"])
        
        # Rate limiting
        time.sleep(0.5)
    
    # Update Field Guide
    print(f"\n{'=' * 80}")
    print("UPDATING FIELD GUIDE")
    print(f"{'=' * 80}\n")
    
    guide_content = f"""# XSIAM Custom Alert Field Guide - EXTENDED
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total fields tested in this run: {len(EXTENDED_TEST_CASES)}
- Successful: {len(successful)}
- Failed: {len(failed)}

## ✅ Working Fields ({len(successful)})

"""
    
    for field_name in successful:
        result = results[field_name]
        value = result["test_value"]
        
        # Format value for display
        if isinstance(value, list):
            if len(value) > 0 and isinstance(value[0], int) and value[0] > 1000000:
                # It's an IP as integer - show both
                ip_str = socket.inet_ntoa(struct.pack("!I", value[0]))
                value_display = f'[{value[0]}]  # IP: {ip_str}'
            else:
                value_display = json.dumps(value)
        else:
            value_display = json.dumps(value)
        
        guide_content += f"""### {field_name}
- **Description**: {result['description']}
- **Type**: {result['expected_type']}
- **Example**: `{value_display}`

"""
    
    if failed:
        guide_content += f"\n## ❌ Failed Fields ({len(failed)})\n\n"
        for field_name in failed:
            result = results[field_name]
            guide_content += f"""### {field_name}
- **Description**: {result['description']}
- **Error**: {result['message']}
- **Attempted value**: `{json.dumps(result['test_value'])}`

"""
    
    # Save guide
    guide_path = "/Users/mabutbul/Desktop/agentix_issues/FIELD_GUIDE_EXTENDED.md"
    with open(guide_path, "w") as f:
        f.write(guide_content)
    
    print(f"✅ Extended field guide saved to: {guide_path}")
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ Successful: {len(successful)} fields")
    print(f"❌ Failed: {len(failed)} fields")
    
    if successful:
        print(f"\n✅ NEW WORKING FIELDS:")
        for field in successful:
            print(f"  ✅ {field}")
    
    if failed:
        print(f"\n❌ Failed fields:")
        for field in failed:
            print(f"  ❌ {field}")
    
    print()


if __name__ == "__main__":
    main()
