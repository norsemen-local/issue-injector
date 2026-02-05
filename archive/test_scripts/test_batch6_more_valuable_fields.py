#!/usr/bin/env python3
"""
Test Batch 6: More Curated Valuable Fields
Testing another batch of high-value untested fields from the curated list.

Focus areas for Batch 6:
1. Registry fields
2. More email/phishing fields
3. File fields
4. Event/timestamp fields
5. Risk/score fields
6. Network/URL fields
7. MITRE fields (alternatives)
8. Compliance/policy fields
9. Cloud/container fields
10. User/account fields

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
        "vendor": "TestVendor_Batch6",
        "product": "FieldDiscovery",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"batch6-{field_name}-{int(time.time() * 1000)}",
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
    """Test all batch 6 fields."""
    
    # Define test fields with proper underscore naming
    test_fields = {
        # Registry fields (5 fields)
        "Registry Fields": {
            "registry_hive": ["HKEY_LOCAL_MACHINE"],  # registryhive - Multi Select
            "registry_key": ["Software\\Microsoft\\Windows"],  # registrykey - Multi Select
            "registry_value": ["test_value"],  # registryvalue - Multi Select
            "registry_value_type": ["REG_SZ"],  # registryvaluetype - Multi Select
        },
        
        # More Email/Phishing fields (7 fields)
        "More Email Fields": {
            "email_labels": "Important",  # emaillabels - Short Text
            "email_keywords": "urgent payment",  # emailkeywords - Short Text
            "email_return_path": "bounce@example.com",  # emailreturnpath - Short Text
            "email_source": "Gmail",  # emailsource - Short Text
            "email_body_format": "HTML",  # emailbodyformat - Short Text
            "email_client_name": "Outlook",  # emailclientname - Short Text
            "email_in_reply_to": "msg-original-12345",  # emailinreplyto - Short Text
        },
        
        # File fields (5 fields)
        "File Fields": {
            "file_sha1": ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],  # filesha1 - Multi Select
            "file_size": "1024000",  # filesize - Short Text
            "file_creation_date": "2025-11-26T10:00:00Z",  # filecreationdate - Short Text
            "file_access_date": "2025-11-26T12:00:00Z",  # fileaccessdate - Short Text
        },
        
        # Event/Timestamp fields (5 fields)
        "Event Fields": {
            "event_action": "allow",  # eventaction - Single Select
            "event_names": ["ProcessCreation", "FileCreated"],  # eventnames - Multi Select
            "event_descriptions": ["Process started", "File written"],  # eventdescriptions - Multi Select
            "start_time": "2025-11-26T10:00:00Z",  # starttime - Short Text
            "close_time": "2025-11-26T12:00:00Z",  # closetime - Short Text
        },
        
        # Risk/Score fields (5 fields)
        "Risk Fields": {
            "risk_score": "85",  # riskscore - Short Text
            "risk_rating": "High",  # riskrating - Short Text
            "exposure_level": "Critical",  # exposurelevel - Short Text
            "host_risk_reasons": ["Multiple failed logins", "Suspicious process"],  # hostriskreasons - Multi Select
            "user_risk_reasons": ["Unusual login location", "After hours access"],  # userriskreasons - Multi Select
        },
        
        # Network/URL fields (5 fields)
        "Network/URL Fields": {
            "domain_name": ["malicious-site.com"],  # domainname - Multi Select
            "domain_updated_date": "2025-01-15",  # domainupdateddate - Short Text
            "urls": ["http://evil.com", "https://phishing.net"],  # urls - Multi Select
            "asn": "AS12345",  # asn - Short Text
            "asn_name": "Evil Hosting Corp",  # asnname - Short Text
        },
        
        # MITRE Alternative fields (4 fields)
        "MITRE Fields": {
            "mitre_tactic_id": ["TA0001", "TA0002"],  # mitretacticid - Multi Select
            "mitre_tactic_name": ["Initial Access", "Execution"],  # mitretacticname - Multi Select
            "mitre_technique_id": ["T1078", "T1059"],  # mitretechniqueid - Multi Select
            "mitre_technique_name": ["Valid Accounts", "Command and Scripting Interpreter"],  # mitretechniquename - Multi Select
        },
        
        # Account/User fields (5 fields)
        "Account/User Fields": {
            "account_id": "ACC-12345",  # accountid - Short Text
            "account_member_of": ["Domain Users", "VPN Users"],  # accountmemberof - Multi Select
            "employee_display_name": "John Doe",  # employeedisplayname - Short Text
            "employee_email": "john.doe@company.com",  # employeeemail - Short Text
            "manager_email_address": "jane.manager@company.com",  # manageremailaddress - Short Text
        },
        
        # Device/Endpoint fields (5 fields)
        "Device/Endpoint Fields": {
            "device_hash": "device-hash-abc123",  # devicehash - Short Text
            "device_mac_address": ["00:0a:95:9d:68:16"],  # devicemacaddress - Multi Select
            "device_time": ["2025-11-26T10:00:00Z"],  # devicetime - Multi Select
            "endpoint_isolation_status": "Isolated",  # endpointisolationstatus - Short Text
        },
        
        # Classification/Action fields (4 fields)
        "Classification Fields": {
            "classification": "Malware",  # classification - Short Text
            "sub_category": "Trojan",  # subcategory - Short Text
            "subtype": "Backdoor",  # subtype - Short Text
            "signature": "Malware.Generic",  # signature - Short Text (might work as string not array)
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
    print(f"BATCH 6: Testing {total_fields} More Curated Valuable Fields")
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
                # Truncate long errors
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
    print(f"BATCH 6 TEST RESULTS - {timestamp}")
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
                elif isinstance(value_repr, str) and len(value_repr) > 50:
                    value_repr = value_repr[:50] + "..."
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
    output_file = f"batch6_results_{int(time.time())}.json"
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
    print(f"New discoveries (Batch 6): {working_count}")
    print(f"Total working fields: {total_working}")
    print(f"{'='*80}\n")

def main():
    """Main execution."""
    print("\n🚀 Starting Batch 6: More Curated Valuable Fields Test")
    print(f"Target: Test 50 more high-value untested fields")
    print(f"Categories: Registry, Email, File, Event, Risk, Network, MITRE, Account, Device, Classification\n")
    
    results = test_fields()
    generate_report(results)
    
    print("\n✅ Batch 6 testing complete!")
    
    if results["working"]:
        print(f"\n🎉 Discovered {len(results['working'])} new working fields!")
        print("📝 Next steps:")
        print("   1. Review results in batch6_results_*.json")
        print("   2. Continue testing more fields from curated list")

if __name__ == "__main__":
    main()
