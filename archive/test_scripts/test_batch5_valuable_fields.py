#!/usr/bin/env python3
"""
Test Batch 5: Curated Valuable Fields
Testing high-value fields from data/real_valuable_fields.txt that haven't been tested yet.
Excluding the 159 already-tested working fields.

Focus areas:
1. Process fields (parentprocess*, process*)
2. User/Identity fields (userid, usergroups, displayname, etc.)
3. Network enrichment (geolocation, traffic direction, protocols)
4. Device/Asset fields (deviceos*, assetname, agentid)
5. Email/Phishing fields (attachment*, email*)
6. Threat/Detection fields (detectionid, logsource*, cve, bugtraq)
7. Policy/Compliance fields (policy*)

Total fields to test: 50
"""

import os
import sys
import requests
import json
import time
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
    """Test all batch 5 fields."""
    
    # Define test fields organized by category
    test_fields = {
        # Process fields (10 fields)
        "Process Fields": {
            "parentprocessids": ["12345", "67890"],  # Multi Select
            "parentprocesscmd": ["C:\\Windows\\explorer.exe"],  # Multi Select
            "parentprocessfilepath": ["C:\\Windows\\explorer.exe"],  # Multi Select
            "parentprocessmd5": ["d41d8cd98f00b204e9800998ecf8427e"],  # Multi Select
            "parentprocessname": ["explorer.exe"],  # Multi Select
            "parentprocesspath": ["C:\\Windows"],  # Multi Select
            "parentprocesssha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],  # Multi Select
            "processid": ["1001", "1002"],  # Multi Select
            "processcmd": ["notepad.exe"],  # Multi Select
            "processmd5": ["abc123def456"],  # Multi Select
        },
        
        # User/Identity fields (8 fields)
        "User/Identity Fields": {
            "userid": "user-12345",  # Short Text
            "usergroups": ["Domain Users", "Administrators"],  # Multi Select
            "usersid": ["S-1-5-21-123456789-123456789-123456789-1001"],  # Multi Select
            "displayname": "John Doe",  # Short Text
            "department": "IT Security",  # Short Text
            "givenname": "John",  # Short Text
            "surname": "Doe",  # Short Text
            "managername": "Jane Smith",  # Short Text
        },
        
        # Network fields (6 fields)
        "Network Fields": {
            "sourcegeolocation": ["US", "United States"],  # Multi Select
            "destinationgeolocation": ["CN", "China"],  # Multi Select
            "destinationnetworks": ["10.0.0.0/8"],  # Multi Select
            "sourcenetworks": ["192.168.0.0/16"],  # Multi Select
            "trafficdirection": ["OUTBOUND"],  # Multi Select
            "protocolnames": ["TCP", "HTTPS"],  # Multi Select
        },
        
        # Device/Asset fields (6 fields)
        "Device/Asset Fields": {
            "deviceosname": ["Windows 10 Pro"],  # Multi Select
            "deviceosversion": ["10.0.19045"],  # Multi Select
            "deviceou": ["CN=Computers,DC=corp,DC=local"],  # Multi Select
            "assetname": "LAPTOP-ABC123",  # Short Text
            "agentid": "agent-uuid-12345",  # Short Text
            "agentsid": ["agent-001", "agent-002"],  # Multi Select
        },
        
        # Email/Phishing fields (8 fields)
        "Email/Phishing Fields": {
            "attachmentcount": 2,  # Number
            "attachmentname": "invoice.pdf",  # Short Text
            "attachmentsize": "1024000",  # Short Text (bytes as string)
            "emailsenderip": "203.0.113.5",  # Short Text
            "emailsize": 50000,  # Number
            "emailinternalmessageid": "msg-id-12345",  # Short Text
            "emailrecipientscount": 5,  # Number
            "emailtocount": "3",  # Short Text
        },
        
        # Threat/Detection fields (7 fields)
        "Threat/Detection Fields": {
            "detectionid": 99887766,  # Number
            "logsourcename": ["Firewall-PA-220"],  # Multi Select
            "logsourcetype": ["NGFW"],  # Multi Select
            "bugtraq": "BID-12345",  # Short Text
            "cve": "CVE-2024-1234",  # Short Text
            "cveid": "CVE-2024-1234",  # Short Text
            "threatactor": "APT29",  # Short Text (but this shows as not in list - might be threatfamilyname)
        },
        
        # Policy/Compliance fields (5 fields)
        "Policy/Compliance Fields": {
            "policyactions": ["ALERT", "BLOCK"],  # Multi Select
            "policydetails": "Policy requires MFA for admin access",  # Short Text
            "policydescription": "Multi-factor authentication policy",  # Long Text (try as string)
            "policyseverity": "High",  # Short Text
            "policytype": "Security",  # Short Text
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
    print(f"BATCH 5: Testing {total_fields} Curated Valuable Fields")
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
    print("\n🚀 Starting Batch 5: Valuable Curated Fields Test")
    print(f"Target: Test 50 high-value untested fields from curated list")
    print(f"Excluding: 159 already-tested working fields\n")
    
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
