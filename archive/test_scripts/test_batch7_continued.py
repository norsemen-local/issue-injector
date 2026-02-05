#!/usr/bin/env python3
"""
Test Batch 7: Continued Curated Fields Testing
Testing more high-value fields from the curated list.

Focus areas for Batch 7:
1. Location/Region fields
2. More detection/source fields
3. Status/state fields
4. Additional user/account fields
5. Network protocol/direction fields
6. Cloud region/resource fields
7. More timestamp fields
8. Compliance/audit fields

Total fields to test: 45
"""

import os
import sys
import requests
import json
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv('XSIAM_API_URL')
API_KEY = os.getenv('XSIAM_API_KEY')
API_KEY_ID = os.getenv('XSIAM_API_KEY_ID')

if not all([API_URL, API_KEY, API_KEY_ID]):
    print("❌ Missing required environment variables")
    sys.exit(1)

TIMESTAMP = int(datetime.now().timestamp() * 1000)

def create_alert_with_field(field_name, field_value):
    """Create alert with specific custom field."""
    
    base_alert = {
        "vendor": "TestVendor_Batch7",
        "product": "FieldDiscovery",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"batch7-{field_name}-{int(time.time() * 1000)}",
        "timestamp": TIMESTAMP,
        "description": f"Testing field: {field_name}"
    }
    
    base_alert[field_name] = field_value
    
    payload = {"request_data": {"alert": base_alert}}
    
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
        
        return {
            "field": field_name,
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "response": response.json() if response.status_code == 200 else response.text
        }
        
    except Exception as e:
        return {
            "field": field_name,
            "success": False,
            "error": str(e)
        }

def test_fields():
    """Test all batch 7 fields."""
    
    test_fields = {
        # Location/Region fields (5 fields)
        "Location/Region Fields": {
            "region": "us-east-1",  # region - Short Text
            "region_id": "reg-12345",  # regionid - Short Text
            "location_region": "North America",  # locationregion - Short Text
            "city": "New York",  # city - Short Text
            "country": "US",  # country - string (tried array before, now string)
        },
        
        # More detection/source fields (6 fields)
        "Detection/Source Fields": {
            "source_create_time": "2025-11-26T10:00:00Z",  # sourcecreatetime - Short Text
            "source_created_by": "admin",  # sourcecreatedby - Short Text
            "source_updated_by": "analyst",  # sourceupdatedby - Short Text
            "source_urgency": "High",  # sourceurgency - Short Text
            "detection_url": "https://xdr.example.com/alert/123",  # detectionurl - URL
            "detection_end_time": "2025-11-26T12:00:00Z",  # detectionendtime - Date Picker
        },
        
        # Status/State fields (5 fields)
        "Status/State Fields": {
            "state": "Active",  # state - Short Text
            "status_reason": "Under investigation",  # statusreason - Short Text
            "closing_reason": "False positive",  # closingreason - Short Text
            "closing_user": "analyst@company.com",  # closinguser - Short Text
            "isolated": "true",  # isolated - Short Text
        },
        
        # Additional user/account fields (6 fields)
        "User/Account Fields": {
            "first_name": "John",  # firstname - Short Text
            "last_name": "Doe",  # lastname - Short Text
            "full_name": "John Doe",  # fullname - Short Text
            "email": "john.doe@company.com",  # email - Short Text
            "phone_number": ["+1-555-0123"],  # phonenumber - Multi Select
            "work_phone": "+1-555-0124",  # workphone - Short Text
        },
        
        # Network protocol/direction fields (5 fields)
        "Network Protocol Fields": {
            "src_os": "Windows",  # srcos - Short Text
            "dest_os": "Linux",  # destos - Short Text
            "sensor_ip": "10.0.0.100",  # sensorip - Short Text
            "unique_ports": "443,8443,22",  # uniqueports - Short Text
        },
        
        # Cloud region/resource fields (5 fields)
        "Cloud/Resource Fields": {
            "project_id": ["proj-12345"],  # projectid - Multi Select
            "resource_url": "https://cloud.example.com/resource/123",  # resourceurl - Short Text
            "referenced_resource_id": ["res-abc123"],  # referencedresourceid - Multi Select
            "referenced_resource_name": ["MyResource"],  # referencedresourcename - Multi Select
            "sku_name": "Premium",  # skuname - Short Text
        },
        
        # More timestamp/audit fields (5 fields)
        "Timestamp/Audit Fields": {
            "last_update_time": "2025-11-26T15:00:00Z",  # lastupdatetime - Short Text
            "last_modified_by": "analyst",  # lastmodifiedby - Short Text
            "last_modified_on": "2025-11-26T14:00:00Z",  # lastmodifiedon - Short Text
            "password_changed_date": "2025-01-15",  # passwordchangeddate - Short Text
            "user_creation_time": "2024-06-01T00:00:00Z",  # usercreationtime - Short Text
        },
        
        # Compliance/Audit fields (5 fields)
        "Compliance/Audit Fields": {
            "audit_logs": "Access granted to sensitive data",  # auditlogs - Short Text
            "approval_status": "Approved",  # approvalstatus - Short Text
            "approver": "manager@company.com",  # approver - Short Text
            "assigned_user": "analyst@company.com",  # assigneduser - Short Text
            "assignment_group": "Security Team",  # assignmentgroup - Short Text
        },
        
        # Additional misc fields (3 fields)
        "Miscellaneous Fields": {
            "caller": "user@company.com",  # caller - Short Text
            "scenario": ["Data Exfiltration"],  # scenario - Multi Select
            "rating": "5",  # rating - Short Text
        },
    }
    
    results = {
        "working": [],
        "failed": [],
        "errors": []
    }
    
    total_fields = sum(len(fields) for fields in test_fields.values())
    current = 0
    
    print(f"\n{'='*80}")
    print(f"BATCH 7: Testing {total_fields} More Curated Fields")
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
                if len(str(error_msg)) > 100:
                    error_display = str(error_msg)[:100] + "..."
                else:
                    error_display = str(error_msg)
                print(f"❌ FAILED: {error_display}")
                results["failed"].append({
                    "field": field_name,
                    "value": field_value,
                    "error": error_msg,
                    "category": category
                })
            
            time.sleep(0.3)
    
    return results

def generate_report(results):
    """Generate detailed test report."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n\n{'='*80}")
    print(f"BATCH 7 TEST RESULTS - {timestamp}")
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
                elif isinstance(value_repr, str) and len(value_repr) > 50:
                    value_repr = value_repr[:50] + "..."
                print(f"  • {field['field']}: {value_repr}")
    
    if results["failed"]:
        print(f"\n{'='*80}")
        print(f"❌ FAILED FIELDS ({failed_count})")
        print(f"{'='*80}\n")
        
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
    
    output_file = f"batch7_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")
    
    previous_working = 211
    total_working = previous_working + working_count
    
    print(f"\n📊 CUMULATIVE STATISTICS")
    print(f"{'='*80}")
    print(f"Previous working fields: {previous_working}")
    print(f"New discoveries (Batch 7): {working_count}")
    print(f"Total working fields: {total_working}")
    print(f"{'='*80}\n")

def main():
    """Main execution."""
    print("\n🚀 Starting Batch 7: Continued Curated Fields Test")
    print(f"Target: Test 45 more high-value untested fields")
    print(f"Categories: Location, Detection, Status, User, Network, Cloud, Timestamps, Compliance\n")
    
    results = test_fields()
    generate_report(results)
    
    print("\n✅ Batch 7 testing complete!")
    
    if results["working"]:
        print(f"\n🎉 Discovered {len(results['working'])} new working fields!")

if __name__ == "__main__":
    main()
