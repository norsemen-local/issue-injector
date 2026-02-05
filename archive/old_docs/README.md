# XSIAM Alert Data & Schema

This directory contains the JSON schema, templates, and example alerts for the issues_injection project.

## Files Overview

### 📋 Core Schema & Documentation

**`schema.json`** (4.4 KB)
- JSON Schema (Draft 2020-12) for alert validation
- Defines 4 required fields and 20+ optional fields
- Validates field types, formats, and constraints
- **Use**: Referenced by injector.py for validation

**`SCHEMA_GUIDE.md`** (8.0 KB)
- Comprehensive guide explaining all schema fields
- Required vs. optional fields
- Field naming conventions (snake_case)
- Common mistakes and how to avoid them
- Multiple examples for different alert levels
- **Use**: Reference when creating new alerts

### 📝 Templates & Examples

**`alert_template.json`** (419 B)
- Minimal template with all required and key optional fields
- Perfect for copying and modifying to create new alerts
- All required fields marked with "ChangeMe"
- **Use**: Copy this and fill in your alert data

**`phishing_alert_example.json`** (807 B)
- Complete, production-ready phishing alert
- Demonstrates recommended fields usage
- Includes MITRE mapping
- Ready to inject to XSIAM
- **Use**: Reference for phishing-type alerts

**`impossible_travel_alert_example.json`** (1.2 KB)
- Complete, production-ready impossible travel alert
- Demonstrates location/security context fields
- Includes custom fields (distance_miles, travel_time_minutes)
- Ready to inject to XSIAM
- **Use**: Reference for travel anomaly alerts

## Quick Start

### Creating Your First Alert

1. **Copy the template**
   ```bash
   cp alert_template.json my_new_alert.json
   ```

2. **Edit with required fields**
   ```json
   {
     "vendor": "MyVendor",
     "product": "MyProduct",
     "severity": "High",
     "category": "Phishing"
   }
   ```

3. **Add optional fields** (recommended)
   - Look at examples: `phishing_alert_example.json`
   - Read the guide: `SCHEMA_GUIDE.md`

4. **Validate your alert**
   - Schema validation happens automatically in injector.py
   - Or test manually: `python validator.py my_new_alert.json`

## Schema Quick Reference

### Required Fields (Must Have)
| Field | Type | Values |
|-------|------|--------|
| `vendor` | string | Any non-empty string |
| `product` | string | Any non-empty string |
| `severity` | string | Informational, Low, Medium, High, Critical |
| `category` | string | Any non-empty string |

### Recommended Fields (Strongly Suggested)
- `title` - Brief alert summary
- `details` - Detailed description
- `alert_id` - External identifier
- `timestamp` - ISO 8601 format
- `initiated_by` - Username
- `host_name` - Target hostname
- `remote_ip` - Source IP

### Optional Security Fields
- `remote_host` - Source hostname
- `group_id` - Organization/group
- `initiator_sha256` - Process SHA256 (64 hex chars)
- `target_process_sha256` - Target process SHA256
- `file_sha256` - File SHA256
- `os_parent_cmd` - Parent command
- `os_parent_user_name` - Parent user
- `mitre_defs` - MITRE tactics/techniques
- `source` - Source system name
- `status` - Status code

### Additional Properties
You can add ANY custom fields beyond the schema definition:
```json
{
  "vendor": "MyVendor",
  "product": "MyProduct",
  "severity": "High",
  "category": "Phishing",
  "custom_field_1": "value",
  "custom_field_2": 12345
}
```

## Field Naming Convention

- Use **snake_case** (lowercase with underscores)
- ✅ `remote_ip`, `initiated_by`, `parent_cmd`
- ❌ `remoteIP`, `initiatedBy`, `parentCmd`

## Severity Levels

| Level | Usage |
|-------|-------|
| **Informational** | Non-threatening, FYI |
| **Low** | Minor issue, low risk |
| **Medium** | Noteworthy, moderate risk |
| **High** | Serious, high risk |
| **Critical** | Immediate threat |

## Validation Rules

The schema enforces:
1. ✓ All required fields present
2. ✓ Severity is one of allowed values
3. ✓ SHA256 hashes are 64 hex characters (if provided)
4. ✓ Timestamps are ISO 8601 format (if provided)
5. ✓ Strings are non-empty (if required)

## Examples

### Minimal Alert (Only Required)
```json
{
  "vendor": "Cortex",
  "product": "XDR",
  "severity": "High",
  "category": "Phishing"
}
```

### Recommended Alert
See: `phishing_alert_example.json`

### Full Alert with Security Context
See: `impossible_travel_alert_example.json`

## Further Reading

- `SCHEMA_GUIDE.md` - Complete field documentation
- `schema.json` - JSON Schema specification
- Cortex XSIAM API Documentation (external)

## Support

For questions about:
- **Field meanings**: Read `SCHEMA_GUIDE.md`
- **Examples**: Check the `.json` files in this directory
- **Validation**: Run injector.py which provides clear error messages
