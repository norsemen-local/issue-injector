#!/usr/bin/env python3
"""
Test Batch 8: Large Batch - 100 Curated Fields
Testing 100 more high-value fields from the curated list.

Total fields to test: 100
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
        "vendor": "TestVendor_Batch8",
        "product": "FieldDiscovery",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"batch8-{field_name}-{int(time.time() * 1000)}",
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
    """Test all batch 8 fields."""
    
    test_fields = {
        # More email/phishing fields (15 fields)
        "Email/Phishing Extended": {
            "attachment_extension": "pdf",
            "attachment_hash": "abc123hash",
            "attachment_id": "attach-12345",
            "attachment_type": "application/pdf",
            "email_received": "2025-11-26T10:00:00Z",
            "email_url_clicked": "http://phishing.com",
            "malicious_url_clicked": "Yes",
            "malicious_url_viewed": "Yes",
            "reported_email_cc": "cc@example.com",
            "reported_email_from": "phisher@evil.com",
            "reported_email_message_id": "msg-phish-123",
            "reported_email_subject": "Urgent: Update your password",
            "reported_email_to": "victim@company.com",
            "reporter_email_address": "reporter@company.com",
            "phishing_sub_type": ["Spear Phishing"],
        },
        
        # Device/Hardware fields (10 fields)
        "Device/Hardware": {
            "mobile_device_model": "iPhone 14",
            "mobile_phone": "+1-555-0199",
            "device_external_ips": ["203.0.113.50"],
            "device_internal_ips": ["192.168.1.100"],
            "detected_endpoints": "DESKTOP-ABC123",
            "detected_external_ips": "203.0.113.75",
            "detected_internal_hosts": "workstation-001",
            "remote_host": ["remote-server-01"],
            "street_address": "123 Main St",
            "zip_code": "10001",
        },
        
        # Threat/Malware fields (12 fields)
        "Threat/Malware": {
            "related_campaign": "APT-Campaign-2024",
            "part_of_campaign": "Yes",
            "threat_family_name": "Emotet",
            "related_report": "Threat-Report-2024-001",
            "related_endpoints": "DESKTOP-001, LAPTOP-002",
            "suspicious_executions_found": "3 suspicious processes detected",
            "command_line_verdict": "Malicious",
            "blocked_action": "File execution blocked",
            "attack_mode": "Automated",
            "triggered_security_profile": "Anti-Malware",
            "objective": ["Data Theft", "Lateral Movement"],
            "tactic": ["Initial Access", "Execution"],
        },
        
        # File/Hash extended (8 fields)
        "File/Hash Extended": {
            "file_relationships": "parent: explorer.exe",
            "number_of_similar_files": 5,
            "macro_source_code": "Sub AutoOpen()...",
            "ss_deep": "ssdeep-hash-value",
            "application_path": "C:\\Program Files\\App\\app.exe",
            "process_names": ["chrome.exe", "firefox.exe"],
            "process_paths": ["C:\\Program Files\\Chrome", "C:\\Program Files\\Firefox"],
            "process_sha256": ["abc123", "def456"],
        },
        
        # User/Identity extended (12 fields)
        "User/Identity Extended": {
            "birthday": "1990-01-15",
            "cost_center": "IT-001",
            "cost_center_code": "CC-IT-001",
            "job_code": "ENG-001",
            "job_family": "Engineering",
            "job_function": "Software Engineer",
            "leadership": "Senior Engineer",
            "org_level_1": "Technology",
            "org_level_2": "Engineering",
            "org_level_3": "Backend",
            "org_unit": "Platform Team",
            "team_name": "Infrastructure",
        },
        
        # Network extended (10 fields)
        "Network Extended": {
            "destination_ipv6": ["2001:0db8:85a3::8a2e:0370:7334"],
            "post_nat_destination_ip": ["192.168.1.200"],
            "post_nat_destination_port": ["8080"],
            "post_nat_source_ip": ["10.0.0.50"],
            "post_nat_source_port": ["55000"],
            "pre_nat_destination_port": ["443"],
            "pre_nat_source_ip": ["172.16.0.100"],
            "pre_nat_source_port": ["60000"],
            "source_external_ips": ["203.0.113.100"],
            "device_external_ips": ["203.0.113.101"],
        },
        
        # Detection/Hunting (8 fields)
        "Detection/Hunting": {
            "hunt_results_count": "15",
            "number_of_found_related_alerts": 7,
            "number_of_log_sources": 3,
            "number_of_related_incidents": 2,
            "list_of_rules_event": ["Rule-001", "Rule-002"],
            "low_level_categories_events": ["ProcessCreation", "NetworkConnection"],
            "operation_name": ["CreateFile", "DeleteFile"],
            "raw_event": ["Raw log data here"],
        },
        
        # Policy/Compliance extended (8 fields)
        "Policy/Compliance Extended": {
            "policy_deleted": "No",
            "policy_recommendation": "Enable MFA for all users",
            "policy_remediable": "Yes",
            "policy_uri": "https://policies.company.com/pol-001",
            "compliance_notes": ["Compliant with SOC2", "PCI-DSS requirements met"],
            "use_case_description": "Detect unauthorized data access",
            "verification_method": "Manual Review",
            "verification_status": "Verified",
        },
        
        # Incident Management (8 fields)
        "Incident Management": {
            "investigation_stage": "Analysis",
            "escalation": "Level 2",
            "follow_up": "true",
            "incident_link": "https://xdr.company.com/incident/123",
            "similar_incidents": ["INC-001", "INC-002"],
            "number_of_related_incidents": 3,
            "changed": "2025-11-26T15:00:00Z",
            "item_owner": "analyst@company.com",
        },
        
        # CVE/Vulnerability (9 fields)
        "CVE/Vulnerability": {
            "cve_published": "2024-01-15",
            "cvss": "9.8",
            "cvss_availability_requirement": ["High"],
            "cvss_collateral_damage_potential": ["Medium"],
            "cvss_confidentiality_requirement": ["High"],
            "cvss_integrity_requirement": ["High"],
            "vulnerability_category": "Remote Code Execution",
            "vulnerable_product": "Apache Log4j",
            "exposure_level": "Critical",
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
    print(f"BATCH 8: Testing {total_fields} Fields - Large Batch")
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
    print(f"BATCH 8 TEST RESULTS - {timestamp}")
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
                print(f"  • {field['field']}")
    
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
            for field in fields[:5]:  # Show first 5 per category
                print(f"  • {field['field']}")
            if len(fields) > 5:
                print(f"  ... and {len(fields) - 5} more")
    
    output_file = f"batch8_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")
    
    previous_working = 249
    total_working = previous_working + working_count
    
    print(f"\n📊 CUMULATIVE STATISTICS")
    print(f"{'='*80}")
    print(f"Previous working fields: {previous_working}")
    print(f"New discoveries (Batch 8): {working_count}")
    print(f"Total working fields: {total_working}")
    print(f"{'='*80}\n")

def main():
    """Main execution."""
    print("\n🚀 Starting Batch 8: Large Batch - 100 Fields Test")
    print(f"Target: Test 100 more high-value untested fields")
    print(f"This is our biggest batch yet!\n")
    
    results = test_fields()
    generate_report(results)
    
    print("\n✅ Batch 8 testing complete!")
    
    if results["working"]:
        print(f"\n🎉 Discovered {len(results['working'])} new working fields!")

if __name__ == "__main__":
    main()
