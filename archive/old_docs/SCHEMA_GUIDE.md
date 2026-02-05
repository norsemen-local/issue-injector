# XSIAM Alert Schema Guide

## Overview

This guide explains the JSON schema used to validate alerts before injection into Cortex XSIAM. All alerts must conform to this schema to be successfully injected.

## Schema File Location

`data/schema.json` - Standard JSON Schema (Draft 2020-12)

## Required Fields

Every alert JSON file **must** include these four fields:

### 1. `vendor` (string)
- **Description**: The vendor or source of the alert
- **Examples**: `"Cortex"`, `"Splunk"`, `"Microsoft"`, `"DemoIncidentGenerator"`
- **Requirements**: Non-empty string
- **Purpose**: Maps to XSIAM alert API `vendor` field

### 2. `product` (string)
- **Description**: The product or instance name
- **Examples**: `"XDR"`, `"SOAR"`, `"Splunk Integration 1"`, `"Microsoft Defender"`
- **Requirements**: Non-empty string
- **Purpose**: Maps to XSIAM alert API `product` field

### 3. `severity` (string - enum)
- **Description**: Alert severity level
- **Allowed Values**: 
  - `"Informational"` - Low priority, informational only
  - `"Low"` - Low severity
  - `"Medium"` - Medium severity
  - `"High"` - High severity
  - `"Critical"` - Critical severity
- **Purpose**: Maps to XSIAM alert API `severity` field
- **Note**: Must be one of the exact values listed above

### 4. `category` (string)
- **Description**: Classification or categorization of the alert
- **Examples**: `"Phishing"`, `"Lateral Movement"`, `"Privilege Escalation"`, `"Reconnaissance"`
- **Common MITRE Categories**:
  - Reconnaissance
  - Resource Development
  - Initial Access
  - Execution
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Credential Access
  - Discovery
  - Lateral Movement
  - Collection
  - Exfiltration
  - Command and Control
  - Impact
- **Custom Categories**: You can use any custom category if not using MITRE taxonomy
- **Purpose**: Maps to XSIAM alert API `category` field

## Recommended Fields

These fields are **not required** but strongly recommended for better alert context:

### `title` (string)
- Brief summary of the alert
- Examples: `"Phishing Email Detected"`, `"Impossible Travel Detected"`

### `details` (string)
- Detailed description of what triggered the alert
- Include context about why this is suspicious or important
- Examples: `"User received phishing email from suspicious domain attempting credential theft"`

### `alert_id` (string)
- External alert identifier for tracking
- Useful for correlating with source system
- Examples: `"ALERT-12345"`, `"SPLUNK-987654"`

### `timestamp` (string - ISO 8601)
- When the alert was detected
- Format: `"2025-11-23T05:20:00.976Z"`
- Must be valid ISO 8601 date-time format

### `remote_ip` (string)
- Source IP address involved in the alert
- Examples: `"192.168.1.100"`, `"176.10.104.240"`

### `remote_host` (string)
- Source hostname or domain
- Examples: `"attacker.com"`, `"suspicious-domain.net"`

### `host_name` (string)
- Target hostname affected by the alert
- Examples: `"DMORENO-LT81571"`, `"SERVER-01"`

### `initiated_by` (string)
- Username of the user involved
- Examples: `"doris_moreno"`, `"karen_castro"`

## Optional Security Fields

### `group_id` (string)
- Organization or group identifier

### `initiator_sha256` (string)
- SHA256 hash of initiating process
- Must be valid 64-character hex string: `^[a-fA-F0-9]{64}$`

### `target_process_sha256` (string)
- SHA256 hash of target process
- Must be valid 64-character hex string

### `file_sha256` (string)
- SHA256 hash of relevant file
- Must be valid 64-character hex string

### `os_parent_cmd` (string)
- Parent process command line

### `os_parent_user_name` (string)
- Parent process owner username

### `mitre_defs` (object)
- MITRE ATT&CK tactics and techniques
- Format: `{ "TA0001": ["T1234", "T1235"], "TA0002": ["T2567"] }`
- Keys are tactic codes, values are arrays of technique codes

### `source` (string)
- Source system or integration name

### `status` (integer)
- Alert status code
- Examples: `0` (pending), `1` (active), `2` (resolved)

## Additional Properties

The schema allows **any additional properties** beyond those defined above. This means you can add custom fields specific to your alerts:

```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing",
  "title": "Phishing Email Detected",
  "details": "Email from suspicious domain",
  "custom_field_1": "custom_value",
  "custom_field_2": 12345
}
```

## Creating an Alert JSON File

### Minimal Alert (Required Fields Only)

```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing"
}
```

### Recommended Alert (With Common Fields)

```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing",
  "title": "Phishing Email Detected",
  "details": "User received phishing email attempting credential theft",
  "alert_id": "PHISHING-2025-001",
  "timestamp": "2025-11-23T10:30:00.000Z",
  "initiated_by": "doris_moreno",
  "host_name": "DMORENO-LT81571",
  "remote_ip": "192.168.1.100"
}
```

### Full Alert (With Security Context)

```json
{
  "vendor": "DemoIncidentGenerator",
  "product": "Splunk Integration 1",
  "severity": "High",
  "category": "Lateral Movement",
  "title": "Impossible Travel Detected",
  "details": "User logged in from impossible location in short time window",
  "alert_id": "IMPOSSIBLE-TRAVEL-001",
  "timestamp": "2022-05-04T19:35:49.587134Z",
  "initiated_by": "karen_castro",
  "host_name": "SERVER-01",
  "remote_ip": "176.10.104.240",
  "remote_host": "suspicious-host.com",
  "group_id": "IT-TEAM",
  "mitre_defs": {
    "TA0001": ["T1087", "T1087.001"]
  },
  "source": "Azure AD",
  "status": 1
}
```

## Field Naming Convention

- All field names must use **snake_case** (lowercase with underscores)
- Do NOT use camelCase or PascalCase
- Examples:
  - ✅ `remote_ip`
  - ❌ `remoteIp`
  - ✅ `initiated_by`
  - ❌ `initiatedBy`

## Severity Levels Explained

| Severity | Use When | Example |
|----------|----------|---------|
| **Informational** | Non-threatening, FYI only | System backup completed |
| **Low** | Minor issue, low risk | Failed login attempt |
| **Medium** | Noteworthy, moderate risk | Suspicious process execution |
| **High** | Serious, high risk | Phishing email with credentials requested |
| **Critical** | Immediate threat, urgent action needed | Ransomware detected, account compromised |

## Validation

Before injection, alerts are validated against this schema:

1. All required fields are present
2. Severity is one of the allowed values
3. SHA256 hashes (if provided) are valid format
4. Timestamps (if provided) are valid ISO 8601 format

Validation happens automatically when using the `injector.py` script.

## Common Mistakes

### ❌ Missing Required Field
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High"
  // Missing "category"
}
```

### ❌ Invalid Severity
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "CRITICAL",  // Should be "Critical"
  "category": "Phishing"
}
```

### ❌ Invalid Field Name (camelCase)
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing",
  "remoteIp": "192.168.1.100"  // Should be "remote_ip"
}
```

### ❌ Invalid SHA256 Hash
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing",
  "file_sha256": "invalid_hash"  // Must be 64 hex characters
}
```

### ✅ Correct Format
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing",
  "remote_ip": "192.168.1.100",
  "file_sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
}
```

## Examples by Alert Type

See `examples/` directory for complete alert examples:
- `phishing_alert_example.json` - Phishing detection alert
- `impossible_travel_example.json` - Impossible travel alert
- `alert_template.json` - Minimal template to copy and modify

## Further Reading

- [Cortex XSIAM API Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
- [JSON Schema Specification](https://json-schema.org/)
- [ISO 8601 Date Format](https://en.wikipedia.org/wiki/ISO_8601)
