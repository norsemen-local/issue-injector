#!/usr/bin/env python3
"""
Test Batch 5B: Retry Failed Fields with Different Data Types
Retry the 26 fields that failed in Batch 5 with alternative data types.
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
        "vendor": "TestVendor_Batch5B",
        "product": "FieldDiscovery",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"batch5b-{field_name}-{int(time.time() * 1000)}",
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

def test_retry_fields():
    """Retry failed fields with different data types."""
    
    # Fields that failed in Batch 5 - trying alternative data types
    retry_tests = {
        # Process fields - try as strings instead of arrays
        "Process Fields (String)": {
            "parent_process_ids": "12345",  # Was array
            "parent_process_cmd": "C:\\Windows\\explorer.exe",  # Was array
            "parent_process_file_path": "C:\\Windows\\explorer.exe",  # Was array
            "parent_process_md5": "d41d8cd98f00b204e9800998ecf8427e",  # Was array
            "parent_process_name": "explorer.exe",  # Was array
            "parent_process_path": "C:\\Windows",  # Was array
            "parent_process_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Was array
            "process_id": "1001",  # Was array
            "process_cmd": "notepad.exe",  # Was array
            "process_md5": "abc123def456",  # Was array
        },
        
        # User fields - try as strings instead of arrays
        "User Fields (String)": {
            "user_groups": "Domain Users",  # Was array
            "user_sid": "S-1-5-21-123456789-123456789-123456789-1001",  # Was array
        },
        
        # Network fields - try as strings
        "Network Fields (String)": {
            "source_geolocation": "US",  # Was array
            "destination_geolocation": "CN",  # Was array
            "destination_networks": "10.0.0.0/8",  # Was array
            "source_networks": "192.168.0.0/16",  # Was array
            "traffic_direction": "OUTBOUND",  # Was array
            "protocol_names": "TCP",  # Was array
        },
        
        # Device fields - try as strings or arrays
        "Device Fields (Alternative)": {
            "device_os_name": "Windows 10 Pro",  # Was array, try string
            "device_os_version": "10.0.19045",  # Was array, try string
            "device_ou": "CN=Computers,DC=corp,DC=local",  # Was array, try string
            "agent_id": ["agent-uuid-12345"],  # Was string, try array
            "agents_id": "agent-001",  # Was array, try string
        },
        
        # Detection fields - try as strings
        "Detection Fields (String)": {
            "log_source_name": "Firewall-PA-220",  # Was array
            "log_source_type": "NGFW",  # Was array
        },
        
        # Policy fields - try as string
        "Policy Fields (String)": {
            "policy_actions": "ALERT",  # Was array
        },
    }
    
    results = {
        "working": [],
        "failed": [],
        "errors": []
    }
    
    total_fields = sum(len(fields) for fields in retry_tests.values())
    current = 0
    
    print(f"\n{'='*80}")
    print(f"BATCH 5B: Retrying {total_fields} Failed Fields with Different Data Types")
    print(f"{'='*80}\n")
    
    for category, fields in retry_tests.items():
        print(f"\n--- Testing {category} ({len(fields)} fields) ---\n")
        
        for field_name, field_value in fields.items():
            current += 1
            print(f"[{current}/{total_fields}] Testing: {field_name} (type: {type(field_value).__name__})...", end=" ", flush=True)
            
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
                # Truncate long error messages
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
            
            # Small delay between requests
            time.sleep(0.3)
    
    return results

def generate_report(results):
    """Generate detailed test report."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n\n{'='*80}")
    print(f"BATCH 5B TEST RESULTS - {timestamp}")
    print(f"{'='*80}\n")
    
    working_count = len(results["working"])
    failed_count = len(results["failed"])
    total_count = working_count + failed_count
    
    print(f"Total Fields Retested: {total_count}")
    print(f"✅ Working: {working_count} ({working_count/total_count*100:.1f}%)")
    print(f"❌ Failed: {failed_count} ({failed_count/total_count*100:.1f}%)")
    
    if results["working"]:
        print(f"\n{'='*80}")
        print(f"✅ NEW WORKING FIELDS ({working_count})")
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
                if isinstance(value_repr, str) and len(value_repr) > 50:
                    value_repr = value_repr[:50] + "..."
                print(f"  • {field['field']} ({field['type']}): {value_repr}")
    
    if results["failed"]:
        print(f"\n{'='*80}")
        print(f"❌ STILL FAILED ({failed_count})")
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
    output_file = f"batch5b_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")
    
    # Update cumulative count
    previous_working = 183  # From batches 1-5
    total_working = previous_working + working_count
    
    print(f"\n📊 CUMULATIVE STATISTICS")
    print(f"{'='*80}")
    print(f"Previous working fields: {previous_working}")
    print(f"New discoveries (Batch 5B): {working_count}")
    print(f"Total working fields: {total_working}")
    print(f"{'='*80}\n")

def main():
    """Main execution."""
    print("\n🚀 Starting Batch 5B: Retry Failed Fields with Different Data Types")
    print(f"Retrying 26 failed fields from Batch 5")
    print(f"Strategy: Test arrays as strings, strings as arrays, etc.\n")
    
    results = test_retry_fields()
    generate_report(results)
    
    print("\n✅ Batch 5B testing complete!")
    
    if results["working"]:
        print(f"\n🎉 Discovered {len(results['working'])} more working fields!")
        print("📝 These fields work with different data types than initially tried")

if __name__ == "__main__":
    main()
