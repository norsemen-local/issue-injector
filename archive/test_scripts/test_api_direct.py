#!/usr/bin/env python3
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("XSIAM_API_URL") + "/public_api/v1/alerts/create_alert"
headers = {
    "Content-Type": "application/json",
    "Authorization": os.getenv("XSIAM_API_KEY"),
    "x-xdr-auth-id": os.getenv("XSIAM_API_KEY_ID")
}

payload = {
    "request_data": {
        "alert": {
            "vendor": "TestVendor",
            "product": "TestProduct",
            "severity": "High",
            "category": "Malware",
            "title": "Field Naming Test",
            "description": "Testing underscore fields",
            "alert_id": "TEST-UNDERSCORE-003",
            "timestamp": "2025-11-26T16:00:00Z",
            "remote_ip": ["192.168.1.1"],
            "host_name": "TEST-HOST-001"
        }
    }
}

print("Sending request...")
print(json.dumps(payload, indent=2))

response = requests.post(url, headers=headers, json=payload)
print(f"\nStatus: {response.status_code}")
print(f"Response: {response.text}")
