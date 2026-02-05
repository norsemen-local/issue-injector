#!/usr/bin/env python3
"""
Test script to create manual cases in XSIAM via the create_manual_case API endpoint.
This bypasses the standard alert ingestion API for more direct control over case fields.
"""

import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API credentials
API_KEY = os.getenv("XSIAM_API_KEY")
API_KEY_ID = os.getenv("XSIAM_API_KEY_ID")
BASE_URL = "https://agent-maui.xdr.us.paloaltonetworks.com"

if not API_KEY or not API_KEY_ID:
    print("ERROR: API_KEY and API_KEY_ID must be set in .env file")
    exit(1)


def create_manual_case(case_data):
    """
    Create a manual case in XSIAM.
    
    Args:
        case_data (dict): Case data including severity, type, name, description, etc.
    
    Returns:
        dict: Response from the API
    """
    url = f"{BASE_URL}/api/webapp/cases/create_case"
    
    headers = {
        "Authorization": f"{API_KEY_ID}:{API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Prepare the request payload
    payload = {
        "request_data": case_data
    }
    
    print(f"[{datetime.now().isoformat()}] Creating manual case...")
    print(f"URL: {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        print(f"\n[{datetime.now().isoformat()}] Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            print(f"✓ SUCCESS: Manual case created! (HTTP 200)")
            try:
                result = response.json()
                print(f"Response: {json.dumps(result, indent=2)}")
                return result
            except ValueError:
                # Empty or non-JSON response - still success
                print(f"Response: Empty/No JSON body (this is normal for this API)")
                print(f"Raw Response Text: '{response.text}'")
                return {"status": "success", "message": "Case created"}
        else:
            print(f"✗ FAILED: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"✗ ERROR: Request failed - {e}")
        return None


def test_basic_case():
    """Test creating a basic manual case."""
    case_data = {
        "severity": 2,  # High (1=Low, 2=Medium, 3=High, 4=Critical)
        "type": "Unclassified",
        "name": "TEST MANUAL CASE - Field Mapping Test",
        "description": "This is a test manual case to verify field mappings work correctly",
        "case_domain": "DOMAIN_SECURITY",
        "issue_custom_fields": {
            "is_triggering_playbook": False,
            "playbookId": None,
            "alert_category": "MALWARE",
            "domain": "agentix.ad.bakerstreetlabs.io",
            "username": ["testuser@agentix.ad.bakerstreetlabs.io", "admin@agentix.ad.bakerstreetlabs.io"],
            "hostname": "TEST-MANUAL-WORKSTATION-001",
            "hostip": ["10.100.88.88"],
            "filesha256": ["2222222222222222222222222222222222222222222222222222222222222222"],
            "filename": ["manual_test_malware.exe"],
            "filepath": ["C:\\Users\\testuser\\Downloads\\manual_test_malware.exe"],
            "localip": ["10.100.88.88"],
            "localport": [50000],
            "remoteip": ["185.234.219.88"],
            "remoteport": [443],
            "country": ["US"],
            "mitreattcktactic": ["TA0002 - Execution"],
            "mitreattcktechnique": ["T1204.002 - User Execution: Malicious File"],
            "agentversion": ["8.9.0.14028"],
            "agentossubtype": "Windows 10 Pro [10.0 (Build 19045)]",
            "eventtype": ["Process Execution"],
            "tags": "DS:Manual Case,DOM:Security,SEVERITY:High,TEST:Manual"
        }
    }
    
    return create_manual_case(case_data)


def test_malware_case():
    """Test creating a malware-focused manual case."""
    case_data = {
        "severity": 4,  # Critical
        "type": "Malware",
        "name": "Emotet Banking Trojan - Manual Case Test",
        "description": "Manual case creation test for Emotet banking trojan with comprehensive field mapping",
        "case_domain": "DOMAIN_SECURITY",
        "issue_custom_fields": {
            "is_triggering_playbook": False,
            "playbookId": None,
            "alert_category": "MALWARE",
            "domain": "agentix.ad.bakerstreetlabs.io",
            "username": ["ailestrade@agentix.ad.bakerstreetlabs.io"],
            "hostname": "DESKTOP-MANUAL-042",
            "hostip": ["10.100.77.77"],
            "endpointid": "manual1234567890abcdef",
            "filesha256": ["657c0cce98d6e73e53b4001eeea51ed91fdcf3d47a18712b6ba9c66d59677980"],
            "filename": ["Invoice_Manual.exe"],
            "filepath": ["C:\\Users\\ailestrade\\Downloads\\Invoice_Manual.exe"],
            "localip": ["10.100.77.77"],
            "localport": [49888],
            "remoteip": ["185.234.219.77"],
            "remoteport": [443],
            "country": ["NL"],
            "mitreattcktactic": ["TA0002 - Execution"],
            "mitreattcktechnique": ["T1204.002 - User Execution: Malicious File"],
            "agentversion": ["8.9.0.14028"],
            "agentossubtype": "Windows 10 Pro [10.0 (Build 19045)]",
            "eventtype": ["Process Execution"],
            "sourcebrand": "XDR Agent - Manual Case",
            "tags": "DS:Manual Case,DOM:Security,SEVERITY:Critical,MALWARE:Emotet"
        }
    }
    
    return create_manual_case(case_data)


if __name__ == "__main__":
    print("=" * 80)
    print("XSIAM MANUAL CASE CREATION TEST")
    print("=" * 80)
    print()
    
    # Test 1: Basic case
    print("\n" + "=" * 80)
    print("TEST 1: Basic Manual Case")
    print("=" * 80)
    result1 = test_basic_case()
    
    # Test 2: Malware case
    print("\n" + "=" * 80)
    print("TEST 2: Malware Manual Case")
    print("=" * 80)
    result2 = test_malware_case()
    
    print("\n" + "=" * 80)
    print("TESTS COMPLETED")
    print("=" * 80)
