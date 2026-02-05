#!/usr/bin/env python3
"""
Test Batch 5: Curated Valuable Fields - FIXED VERSION
Testing high-value fields from data/real_valuable_fields.txt with proper underscore transformation.

The curated list has field names like 'parentprocessids' but we need to transform them
by adding underscores at word boundaries: 'parent_process_ids'
"""

import os
import sys
import requests
import json
import time
import re
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
API_URL = os.getenv('XSIAM_API_URL')
API_KEY = os.getenv('XSIAM_API_KEY')
API_KEY_ID = os.getenv('XSIAM_API_KEY_ID')

if not all([API_URL, API_KEY, API_KEY_ID]):
    print("❌ Missing required environment variables")
    sys.exit(1)

# Test timestamp
TIMESTAMP = int(datetime.now().timestamp() * 1000)

def camel_to_snake(name):
    """
    Convert camelCase or concatenated words to snake_case.
    Examples:
    - parentprocessids -> parent_process_ids
    - userid -> user_id
    - emailsenderip -> email_sender_ip
    """
    # Insert underscore before uppercase letters
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    # Insert underscore before uppercase followed by lowercase
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def create_alert_with_field(field_name, field_value):
    """Create alert with specific custom field."""
    
    base_alert = {
        "vendor": "TestVendor_Batch5",
        "product": "FieldDiscovery",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"batch5-{field_name}-{int(time.time() * 1000)}",
        "timestamp": TIMESTAMP,
        "description": f"Testing field: {field_name}"
    }
    
    # Add the custom field
    base_alert[field_name] = field_value
    
    payload = {
        "request_data": {
            "alert": base_alert
        }
    }
    
    headers = {
        "x-xdr-auth-id": API_KEY_ID,
        "Authorization": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/public_api/v1/alerts/create_alert",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        result = {
            "field": field_name,
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "response": response.json() if response.status_code == 200 else response.text
        }
        
        return result
        
    except Exception as e:
        return {
            "field": field_name,
            "success": False,
            "error": str(e)
        }

def test_fields():
    """Test all batch 5 fields with proper naming."""
    
    # Define test fields with proper underscore naming
    # Format: machine name -> transformed name with underscores
    test_fields = {
        # Process fields (10 fields)
        "Process Fields": {
            "parent_process_ids": ["12345", "67890"],  # parentprocessids
            "parent_process_cmd": ["C:\\Windows\\explorer.exe"],  # parentprocesscmd
            "parent_process_file_path": ["C:\\Windows\\explorer.exe"],  # parentprocessfilepath
            "parent_process_md5": ["d41d8cd98f00b204e9800998ecf8427e"],  # parentprocessmd5
            "parent_process_name": ["explorer.exe"],  # parentprocessname
            "parent_process_path": ["C:\\Windows"],  # parentprocesspath
            "parent_process_sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],  # parentprocesssha256
            "process_id": ["1001", "1002"],  # processid
            "process_cmd": ["notepad.exe"],  # processcmd
            "process_md5": ["abc123def456"],  # processmd5
        },
        
        # User/Identity fields (8 fields)
        "User/Identity Fields": {
            "user_id": "user-12345",  # userid
            "user_groups": ["Domain Users", "Administrators"],  # usergroups
            "user_sid": ["S-1-5-21-123456789-123456789-123456789-1001"],  # usersid
            "display_name": "John Doe",  # displayname
            "department": "IT Security",  # department (no change)
            "given_name": "John",  # givenname
            "surname": "Doe",  # surname (no change)
            "manager_name": "Jane Smith",  # managername
        },
        
        # Network fields (6 fields)
        "Network Fields": {
            "source_geolocation": ["US", "United States"],  # sourcegeolocation
            "destination_geolocation": ["CN", "China"],  # destinationgeolocation
            "destination_networks": ["10.0.0.0/8"],  # destinationnetworks
            "source_networks": ["192.168.0.0/16"],  # sourcenetworks
            "traffic_direction": ["OUTBOUND"],  # trafficdirection
            "protocol_names": ["TCP", "HTTPS"],  # protocolnames
        },
        
        # Device/Asset fields (6 fields)
        "Device/Asset Fields": {
            "device_os_name": ["Windows 10 Pro"],  # deviceosname
            "device_os_version": ["10.0.19045"],  # deviceosversion
            "device_ou": ["CN=Computers,DC=corp,DC=local"],  # deviceou
            "asset_name": "LAPTOP-ABC123",  # assetname
            "agent_id": "agent-uuid-12345",  # agentid
            "agents_id": ["agent-001", "agent-002"],  # agentsid
        },
        
        # Email/Phishing fields (8 fields)
        "Email/Phishing Fields": {
            "attachment_count": 2,  # attachmentcount
            "attachment_name": "invoice.pdf",  # attachmentname
            "attachment_size": "1024000",  # attachmentsize
            "email_sender_ip": "203.0.113.5",  # emailsenderip
            "email_size": 50000,  # emailsize
            "email_internal_message_id": "msg-id-12345",  # emailinternalmessageid
            "email_recipients_count": 5,  # emailrecipientscount
            "email_to_count": "3",  # emailtocount
        },
        
        # Threat/Detection fields (7 fields)
        "Threat/Detection Fields": {
            "detection_id": 99887766,  # detectionid
            "log_source_name": ["Firewall-PA-220"],  # logsourcename
            "log_source_type": ["NGFW"],  # logsourcetype
            "bugtraq": "BID-12345",  # bugtraq (no change)
            "cve": "CVE-2024-1234",  # cve (no change)
            "cve_id": "CVE-2024-1234",  # cveid
            "threat_actor": "APT29",  # threatactor
        },
        
        # Policy/Compliance fields (5 fields)
        "Policy/Compliance Fields": {
            "policy_actions": ["ALERT", "BLOCK"],  # policyactions
            "policy_details": "Policy requires MFA for admin access",  # policydetails
            "policy_description": "Multi-factor authentication policy",  # policydescription
            "policy_severity": "High",  # policyseverity
            "policy_type": "Security",  # policytype
        }
    }
    
    results = {
        "working": [],
        "failed": [],
        "errors": []
    }
    
    total_fields = sum(len(fields) for fields in test_fields.values())
    current = 0
    
    print(f"\n{'='*80}")
    print(f"BATCH 5: Testing {total_fields} Curated Valuable Fields (WITH UNDERSCORES)")
    print(f"{'='*80}\n")
    
    for category, fields in test_fields.items():
        print(f"\n--- Testing {category} ({len(fields)} fields) ---\n")
        
        for field_name, field_value in fields.items():
            current += 1
            print(f"[{current}/{total_fields}] Testing: {field_name}...", end=" ", flush=True)
            
            result = create_alert_with_field(field_name, field_value)
            
            if result["success"]:
                print("✅ SUCCESS")
                results["working"].append({
                    "field": field_name,
                    "value": field_value,
                    "type": type(field_value).__name__,
                    "category": category
                })
            else:
                error_msg = result.get("response", result.get("error", "Unknown error"))
                print(f"❌ FAILED: {error_msg}")
                results["failed"].append({
                    "field": field_name,
                    "value": field_value,
                    "error": error_msg,
                    "category": category
                })
            
            # Small delay between requests
            time.sleep(0.3)
    
    return results

def generate_report(results):
    """Generate detailed test report."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n\n{'='*80}")
    print(f"BATCH 5 TEST RESULTS - {timestamp}")
    print(f"{'='*80}\n")
    
    working_count = len(results["working"])
    failed_count = len(results["failed"])
    total_count = working_count + failed_count
    
    print(f"Total Fields Tested: {total_count}")
    print(f"✅ Working: {working_count} ({working_count/total_count*100:.1f}%)")
    print(f"❌ Failed: {failed_count} ({failed_count/total_count*100:.1f}%)")
    
    if results["working"]:
        print(f"\n{'='*80}")
        print(f"✅ WORKING FIELDS ({working_count})")
        print(f"{'='*80}\n")
        
        # Group by category
        by_category = {}
        for field in results["working"]:
            cat = field["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(field)
        
        for category, fields in by_category.items():
            print(f"\n{category}: {len(fields)} fields")
            print("-" * 40)
            for field in fields:
                value_repr = field["value"]
                if isinstance(value_repr, list) and len(str(value_repr)) > 50:
                    value_repr = f"[{len(value_repr)} items]"
                print(f"  • {field['field']}: {value_repr}")
    
    if results["failed"]:
        print(f"\n{'='*80}")
        print(f"❌ FAILED FIELDS ({failed_count})")
        print(f"{'='*80}\n")
        
        # Group by category
        by_category = {}
        for field in results["failed"]:
            cat = field["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(field)
        
        for category, fields in by_category.items():
            print(f"\n{category}: {len(fields)} fields")
            print("-" * 40)
            for field in fields:
                error = field["error"]
                if len(str(error)) > 100:
                    error = str(error)[:100] + "..."
                print(f"  • {field['field']}: {error}")
    
    # Save detailed results to file
    output_file = f"batch5_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")
    
    # Update cumulative count
    previous_working = 159  # From previous batches
    total_working = previous_working + working_count
    
    print(f"\n📊 CUMULATIVE STATISTICS")
    print(f"{'='*80}")
    print(f"Previous working fields: {previous_working}")
    print(f"New discoveries (Batch 5): {working_count}")
    print(f"Total working fields: {total_working}")
    print(f"{'='*80}\n")

def main():
    """Main execution."""
    print("\n🚀 Starting Batch 5: Valuable Curated Fields Test (FIXED)")
    print(f"Target: Test 50 high-value untested fields from curated list")
    print(f"Excluding: 159 already-tested working fields")
    print(f"Using: Proper underscore transformation (e.g., parentprocessids -> parent_process_ids)\n")
    
    results = test_fields()
    generate_report(results)
    
    print("\n✅ Batch 5 testing complete!")
    
    if results["working"]:
        print(f"\n🎉 Discovered {len(results['working'])} new working fields!")
        print("📝 Next steps:")
        print("   1. Review results in batch5_results_*.json")
        print("   2. Update FIELD_GUIDE_FINAL.md with new discoveries")
        print("   3. Continue testing remaining valuable fields from curated list")

if __name__ == "__main__":
    main()
