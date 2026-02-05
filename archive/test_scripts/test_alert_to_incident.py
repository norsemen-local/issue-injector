#!/usr/bin/env python3
"""
Test script to create custom alert, wait for incident creation, then update it.
This is a workaround to add custom fields to incidents by:
1. Creating a custom alert
2. Waiting for XSIAM to create an incident
3. Fetching the incident
4. Updating it with additional fields
"""

import os
import json
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API credentials
API_KEY = os.getenv("XSIAM_API_KEY")
API_KEY_ID = os.getenv("XSIAM_API_KEY_ID")
API_BASE_URL = os.getenv("XSIAM_API_URL", "https://api-agent-maui.xdr.us.paloaltonetworks.com")

if not API_KEY or not API_KEY_ID:
    print("ERROR: XSIAM_API_KEY and XSIAM_API_KEY_ID must be set in .env file")
    exit(1)


def create_custom_alert(alert_data):
    """Create a custom alert using the existing injector."""
    import subprocess
    import tempfile
    
    alert_id = alert_data.get('alert_id', 'unknown')
    
    print(f"[{datetime.now().isoformat()}] Creating custom alert...")
    print(f"Alert ID: {alert_id}")
    
    # Write alert to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(alert_data, f, indent=2)
        temp_file = f.name
    
    try:
        # Call the existing injector
        result = subprocess.run(
            ['python3', 'src/injector.py', '--file', temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Check both stdout and stderr since injector logs to stderr
        output = result.stdout + result.stderr
        if result.returncode == 0 and ('successful' in output.lower() or 'injected successfully' in output.lower()):
            print(f"✓ Alert created successfully!")
            return True
        else:
            print(f"✗ Failed to create alert")
            print(f"Output: {result.stdout}")
            print(f"Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ Error creating alert: {e}")
        return False
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_file)
        except:
            pass


def get_incidents(limit=100):
    """Fetch recent incidents from XSIAM."""
    url = f"{API_BASE_URL}/public_api/v1/incidents/get_incidents"
    
    headers = {
        "Authorization": API_KEY,
        "x-xdr-auth-id": str(API_KEY_ID),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "request_data": {
            "sort": {
                "field": "creation_time",
                "keyword": "desc"
            }
        }
    }
    
    print(f"[{datetime.now().isoformat()}] Fetching incidents...")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            incidents = result.get("reply", {}).get("incidents", [])
            print(f"✓ Fetched {len(incidents)} incidents")
            return incidents
        else:
            print(f"✗ Failed to fetch incidents: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return []
            
    except Exception as e:
        print(f"✗ Error fetching incidents: {e}")
        return []


def find_incident_by_alert_id(alert_id, max_attempts=12, wait_seconds=10):
    """
    Poll for incident containing the specified alert ID.
    
    Args:
        alert_id: The alert ID to search for
        max_attempts: Maximum number of polling attempts (default: 12 = 2 minutes)
        wait_seconds: Seconds to wait between attempts (default: 10)
    
    Returns:
        dict: The incident if found, None otherwise
    """
    print(f"\n[{datetime.now().isoformat()}] Waiting for incident creation...")
    print(f"Looking for alert_id: {alert_id}")
    print(f"Will poll {max_attempts} times, every {wait_seconds} seconds")
    
    for attempt in range(1, max_attempts + 1):
        print(f"\nAttempt {attempt}/{max_attempts}...")
        
        incidents = get_incidents()
        
        for incident in incidents:
            incident_id = incident.get("incident_id")
            alerts = incident.get("alerts", [])
            
            # Check if any alert in this incident matches our alert_id
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    print(f"✓ FOUND! Incident ID: {incident_id}")
                    print(f"Incident Name: {incident.get('incident_name')}")
                    print(f"Creation Time: {incident.get('creation_time')}")
                    return incident
        
        if attempt < max_attempts:
            print(f"Not found yet, waiting {wait_seconds} seconds...")
            time.sleep(wait_seconds)
    
    print(f"✗ Incident not found after {max_attempts} attempts")
    return None


def update_incident(incident_id, update_fields):
    """Update an incident with additional fields."""
    url = f"{API_BASE_URL}/public_api/v1/incidents/update_incident"
    
    headers = {
        "Authorization": API_KEY,
        "x-xdr-auth-id": str(API_KEY_ID),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {
        "request_data": {
            "incident_id": str(incident_id),
            "update_data": update_fields
        }
    }
    
    print(f"\n[{datetime.now().isoformat()}] Updating incident {incident_id}...")
    print(f"Update fields: {json.dumps(update_fields, indent=2)}")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Incident updated successfully!")
            print(f"Response: {json.dumps(result, indent=2)}")
            return True
        else:
            print(f"✗ Failed to update incident: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error updating incident: {e}")
        return False


def test_workflow():
    """Test the complete workflow: create alert -> wait -> find incident -> update."""
    
    # Step 1: Create a unique test alert
    alert_id = f"TEST-WORKFLOW-{int(time.time())}"
    
    alert_data = {
        "vendor": "Test Workflow",
        "product": "Alert to Incident Test",
        "name": "Workflow Test Alert",
        "rawName": "Workflow Test Alert",
        "issuename": "Workflow Test Alert",
        "description": "This alert tests the workflow of creating an alert and updating the resulting incident",
        "severity": "High",
        "category": "Malware",
        "action": "DETECTED",
        "alert_id": alert_id,
        
        # Fields to test
        "username": ["workflowtest@agentix.ad.bakerstreetlabs.io"],
        "hostname": "WORKFLOW-TEST-001",
        "hostip": ["10.100.99.99"],
        "filesha256": ["9999999999999999999999999999999999999999999999999999999999999999"],
        "filename": ["workflow_test.exe"],
        "tags": "TEST:Workflow,METHOD:AlertToIncident"
    }
    
    print("=" * 80)
    print("STEP 1: CREATE CUSTOM ALERT")
    print("=" * 80)
    
    if not create_custom_alert(alert_data):
        print("\n✗ WORKFLOW FAILED: Could not create alert")
        return False
    
    print("\n" + "=" * 80)
    print("STEP 2: WAIT FOR INCIDENT CREATION")
    print("=" * 80)
    
    incident = find_incident_by_alert_id(alert_id, max_attempts=12, wait_seconds=10)
    
    if not incident:
        print("\n✗ WORKFLOW FAILED: Could not find incident")
        return False
    
    incident_id = incident.get("incident_id")
    
    print("\n" + "=" * 80)
    print("STEP 3: UPDATE INCIDENT WITH ADDITIONAL FIELDS")
    print("=" * 80)
    
    # Try updating with standard incident fields
    update_fields = {
        "notes": f"Updated via workflow test at {datetime.now().isoformat()}. " +
                 "Alert contained: username=workflowtest@agentix.ad.bakerstreetlabs.io, " +
                 "hostname=WORKFLOW-TEST-001, filesha256=9999...9999",
        "manual_severity": "high"
    }
    
    if update_incident(incident_id, update_fields):
        print("\n✓ WORKFLOW COMPLETED SUCCESSFULLY!")
        print(f"Incident ID: {incident_id}")
        print(f"Check XSIAM UI to verify the incident was updated")
        return True
    else:
        print("\n✗ WORKFLOW FAILED: Could not update incident")
        return False


if __name__ == "__main__":
    print("=" * 80)
    print("ALERT -> INCIDENT WORKFLOW TEST")
    print("=" * 80)
    print()
    
    success = test_workflow()
    
    print("\n" + "=" * 80)
    print("WORKFLOW", "COMPLETED" if success else "FAILED")
    print("=" * 80)
