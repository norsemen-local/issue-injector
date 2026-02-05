#!/usr/bin/env python3
"""
Comprehensive Field Test - All Important Fields from issues_jsons/
==================================================================

Test all commonly used fields to create a complete field guide.
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
        "alert_id": f"TEST-{test_name}-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}",
        "timestamp": int(datetime.now().timestamp() * 1000),
        "description": f"Field test: {test_name}"
    }


# Comprehensive test cases based on actual issues_jsons/ files
TEST_CASES = [
    {
        "name": "name",
        "description": "Alert Name/Title",
        "test_value": "Emotet Banking Trojan Execution Detected",
        "expected_type": "string"
    },
    {
        "name": "host_name", 
        "description": "Host Name (Short Text)",
        "test_value": "DESKTOP-AGENTIX-042",
        "expected_type": "string"
    },
    {
        "name": "user_name",
        "description": "User Name (Multi Select - Array)",
        "test_value": ["ailestrade@agentix.ad.bakerstreetlabs.io"],
        "expected_type": "array"
    },
    {
        "name": "host_ip",
        "description": "Host IP (Multi Select - Array of Integers)",
        "test_value": [ip_to_int("10.100.50.87")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "file_name",
        "description": "File Name (Multi Select - Array)",
        "test_value": ["Invoice_2024_Nov.exe"],
        "expected_type": "array"
    },
    {
        "name": "file_path",
        "description": "File Path (Multi Select - Array)",
        "test_value": ["C:\\\\Users\\\\ailestrade\\\\Downloads\\\\Invoice_2024_Nov.exe"],
        "expected_type": "array"
    },
    {
        "name": "file_sha256",
        "description": "File SHA256 (Multi Select - Array)",
        "test_value": ["657c0cce98d6e73e53b4001eeea51ed91fdcf3d47a18712b6ba9c66d59677980"],
        "expected_type": "array"
    },
    {
        "name": "remote_ip",
        "description": "Remote IP (Multi Select - Array of Integers)",
        "test_value": [ip_to_int("185.234.219.76")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "remote_port",
        "description": "Remote Port (Multi Select - Array of Integers)",
        "test_value": [443],
        "expected_type": "array"
    },
    {
        "name": "local_ip",
        "description": "Local IP (Multi Select - Array of Integers)",
        "test_value": [ip_to_int("10.100.50.87")],
        "expected_type": "array_of_ints"
    },
    {
        "name": "local_port",
        "description": "Local Port (Multi Select - Array)",
        "test_value": [49872],
        "expected_type": "array"
    },
    {
        "name": "country",
        "description": "Country (Multi Select - Array)",
        "test_value": ["US"],
        "expected_type": "array"
    },
    {
        "name": "action",
        "description": "Action (Single Select)",
        "test_value": "BLOCKED",
        "expected_type": "string"
    },
    {
        "name": "action_pretty",
        "description": "Action Pretty/Display Name",
        "test_value": "Prevented - Process Terminated & Host Isolated",
        "expected_type": "string"
    },
    {
        "name": "action_file_name",
        "description": "Action File Name",
        "test_value": "Invoice_2024_Nov.exe",
        "expected_type": "string"
    },
    {
        "name": "action_file_path",
        "description": "Action File Path",
        "test_value": "C:\\\\Users\\\\ailestrade\\\\Downloads\\\\Invoice_2024_Nov.exe",
        "expected_type": "string"
    },
    {
        "name": "action_external_hostname",
        "description": "External Hostname",
        "test_value": "emotet-c2-node47.onion.to",
        "expected_type": "string"
    },
    {
        "name": "event_type",
        "description": "Event Type (Multi Select - Array)",
        "test_value": ["Process Execution"],
        "expected_type": "array"
    },
    {
        "name": "mitre_tactic_id_and_name",
        "description": "MITRE Tactic (Multi Select - Array)",
        "test_value": ["TA0002 - Execution"],
        "expected_type": "array"
    },
    {
        "name": "mitre_technique_id_and_name",
        "description": "MITRE Technique (Multi Select - Array)",
        "test_value": ["T1204.002 - User Execution: Malicious File"],
        "expected_type": "array"
    },
    {
        "name": "agent_version",
        "description": "Agent Version (Multi Select - Array)",
        "test_value": ["8.9.0.14028"],
        "expected_type": "array"
    },
    {
        "name": "agent_os_type",
        "description": "Agent OS Type",
        "test_value": "Windows",
        "expected_type": "string"
    },
    {
        "name": "agent_os_sub_type",
        "description": "Agent OS Sub Type",
        "test_value": "Windows 10 Pro [10.0 (Build 19045)]",
        "expected_type": "string"
    },
    {
        "name": "source",
        "description": "Alert Source",
        "test_value": "XDR Agent - Behavioral Analysis",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_name",
        "description": "Process Name",
        "test_value": "Invoice_2024_Nov.exe",
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_path",
        "description": "Process Path",
        "test_value": "C:\\\\Users\\\\ailestrade\\\\Downloads\\\\Invoice_2024_Nov.exe",
        "expected_type": "string"
    },
    {
        "name": "actor_process_command_line",
        "description": "Process Command Line",
        "test_value": '"C:\\\\Users\\\\ailestrade\\\\Downloads\\\\Invoice_2024_Nov.exe" /silent',
        "expected_type": "string"
    },
    {
        "name": "actor_process_image_sha256",
        "description": "Process SHA256",
        "test_value": "657c0cce98d6e73e53b4001eeea51ed91fdcf3d47a18712b6ba9c66d59677980",
        "expected_type": "string"
    },
    {
        "name": "actor_process_signature_status",
        "description": "Process Signature Status",
        "test_value": "SIGNATURE_UNAVAILABLE",
        "expected_type": "string"
    },
    {
        "name": "malicious_urls",
        "description": "Malicious URLs (Multi Select - Array)",
        "test_value": ["secure-updates-cdn[.]com", "api-config[.]tk"],
        "expected_type": "array"
    },
    {
        "name": "tags",
        "description": "Tags",
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
    """Run comprehensive field tests."""
    
    print("\n" + "=" * 80)
    print("COMPREHENSIVE FIELD TEST - Creating Field Guide")
    print("=" * 80)
    print("\nTesting all important fields from issues_jsons/ files")
    print(f"Total fields to test: {len(TEST_CASES)}")
    
    if not all([XSIAM_API_URL, XSIAM_API_KEY, XSIAM_API_KEY_ID]):
        print("\n❌ ERROR: Missing environment variables!")
        return
    
    print(f"\n✅ Environment configured")
    print(f"   URL: {XSIAM_API_URL}")
    
    results = {}
    successful = []
    failed = []
    
    # Test each field
    for i, test_case in enumerate(TEST_CASES, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}/{len(TEST_CASES)}: {test_case['name']}")
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
    
    # Generate Field Guide
    print(f"\n{'=' * 80}")
    print("GENERATING FIELD GUIDE")
    print(f"{'=' * 80}\n")
    
    guide_content = f"""# XSIAM Custom Alert Field Guide
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- Total fields tested: {len(TEST_CASES)}
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
    
    # Add conversion helpers
    guide_content += """
## Important Notes

### IP Address Conversion
IP addresses MUST be converted to integers:
```python
import struct
import socket

def ip_to_int(ip_string):
    return struct.unpack("!I", socket.inet_aton(ip_string))[0]

# Example
"192.168.1.100" -> 3232235876
"10.0.0.50" -> 167772210
```

### Field Naming
- ALWAYS use underscores: `host_name`, `user_name`, `file_sha256`
- NEVER without underscores: `hostname`, `username`, `filesha256`

### Data Types
- **Short Text**: Plain string
- **Multi Select**: Array of strings or integers
- **IP fields**: Array of integers (converted from IP strings)
- **Port fields**: Array of integers

### Internal Field Mappings (Discovered)
XSIAM internally maps fields:
- `host_name` → `agent_hostname`
- `user_name` → `actor_effective_username`
- `host_ip` → `agent_ip_addresses`
- `file_sha256` → `action_file_sha256`
- `file_name` → `action_file_name`
- `remote_ip` → `action_remote_ip`
"""
    
    # Save guide
    guide_path = "/Users/mabutbul/Desktop/agentix_issues/FIELD_GUIDE.md"
    with open(guide_path, "w") as f:
        f.write(guide_content)
    
    print(f"✅ Field guide saved to: {guide_path}")
    
    # Print summary
    print(f"\n{'=' * 80}")
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ Successful: {len(successful)} fields")
    print(f"❌ Failed: {len(failed)} fields")
    
    if successful:
        print(f"\nWorking fields:")
        for field in successful:
            print(f"  ✅ {field}")
    
    if failed:
        print(f"\nFailed fields:")
        for field in failed:
            print(f"  ❌ {field} - {results[field]['message']}")
    
    print()


if __name__ == "__main__":
    main()
