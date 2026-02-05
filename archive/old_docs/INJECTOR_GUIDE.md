# Cortex XSIAM Alert Injector - Complete Guide

## Overview

The **Alert Injector** (Step 3) is a production-ready Python tool for injecting security alerts into the Cortex XSIAM platform. It reads validated alert JSON files, performs schema validation, and submits them to the XSIAM API with proper error handling, logging, and result tracking.

## Features

- ✅ **Schema Validation**: Validates all alerts against `data/schema.json` before injection
- ✅ **Batch Processing**: Inject single files or entire directories of alerts
- ✅ **Rate Limiting**: Respects 600 alerts/minute API limit automatically
- ✅ **Dry-Run Mode**: Test injection pipeline without sending to API
- ✅ **Result Tracking**: Logs all results with external IDs and timestamps
- ✅ **Error Handling**: Clear error messages for validation and API failures
- ✅ **Progress Reporting**: Track injection progress for large batches
- ✅ **Audit Trail**: JSON results file for compliance and debugging

## Architecture

```
src/
├── injector.py          # Main injector CLI and XSIAMInjector class
├── validator.py         # AlertValidator for schema validation
├── result_logger.py     # ResultLogger for tracking results
└── __init__.py         # Package initialization
```

### Key Components

#### 1. **XSIAMInjector** (`injector.py`)
Main class that orchestrates the injection process:
- Reads and validates alerts
- Manages API authentication
- Enforces rate limiting
- Logs all operations

#### 2. **AlertValidator** (`validator.py`)
Validates alerts against the JSON schema:
- Uses `jsonschema` library with JSON Schema Draft 2020-12
- Returns detailed validation errors
- Supports single alerts and alert arrays

#### 3. **ResultLogger** (`result_logger.py`)
Tracks injection results:
- Records success/failure status
- Extracts external IDs from XSIAM responses
- Generates summary statistics
- Persists results to JSON for audit trail

## Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

**Core requirements:**
- `requests >= 2.31.0` - HTTP client
- `jsonschema >= 4.19.0` - JSON schema validation

### 2. Set Environment Variables

Configure XSIAM API credentials:

```bash
export XSIAM_API_URL="https://your-xsiam-instance.api.com"
export XSIAM_API_KEY="your-api-key"
export XSIAM_API_KEY_ID="your-api-key-id"
```

Or create a `.env` file:

```bash
XSIAM_API_URL=https://your-xsiam-instance.api.com
XSIAM_API_KEY=your-api-key
XSIAM_API_KEY_ID=your-api-key-id
```

## Usage

### Basic Commands

#### 1. Validate Alerts (No Injection)

```bash
# Validate a single alert file
python3 src/injector.py --validate issues_jsons/phishing_alert_clean.json

# Output:
# ✓ All 1 alert(s) are valid
```

#### 2. Dry-Run Injection

Test the entire pipeline without sending to API:

```bash
# Dry-run on single file
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json --dry-run

# Dry-run on directory
python3 src/injector.py --dir issues_jsons/ --dry-run
```

#### 3. Actual Injection

Submit alerts to XSIAM API:

```bash
# Inject single file
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json

# Inject entire directory
python3 src/injector.py --dir issues_jsons/

# Inject with custom API URL (overrides env var)
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json \
    --api-url https://custom.xsiam.api.com
```

### Advanced Options

#### Batch Size Configuration

```bash
# Report progress every 50 alerts (instead of default 100)
python3 src/injector.py --dir issues_jsons/ --batch-size 50
```

#### Custom Schema Path

```bash
# Use alternative schema file
python3 src/injector.py --file alerts.json --schema /path/to/custom/schema.json
```

#### Verbose Logging

```bash
# Enable debug-level logging
python3 src/injector.py --validate alerts.json --verbose
```

## API Integration Details

### XSIAM API Endpoint

```
POST /public_api/v1/alerts/create_alert
```

### Request Structure

```json
{
  "request_data": {
    "alert": {
      "vendor": "Security Operations Center",
      "product": "Incident Detection System",
      "severity": "High",
      "category": "Phishing",
      ...
    }
  }
}
```

### Authentication Headers

- `Authorization: Bearer <API_KEY>`
- `x-xdr-auth-id: <API_KEY_ID>`
- `Content-Type: application/json`

### Success Response (HTTP 200)

```json
{
  "data": "alert_external_id_12345"
}
```

The external ID is extracted and logged for audit trail.

### Error Responses

```
HTTP 400 - Bad Request (validation error)
HTTP 401 - Unauthorized (auth failure)
HTTP 429 - Too Many Requests (rate limit)
HTTP 500 - Server Error
```

## Output and Results

### Logging

Logs are written to:
1. **Console** - Real-time feedback
2. **injector.log** - Persistent file log

Example log output:

```
2025-11-26 13:14:31,437 - __main__ - INFO - Injecting alert: SOC-PHISHING-20251126-001
2025-11-26 13:14:31,447 - __main__ - INFO - [DRY-RUN] Would POST to https://...
2025-11-26 13:14:31,448 - __main__ - INFO - File processing complete: 1 successful, 0 failed
```

### Results File: `injection_results.json`

Persistent JSON file tracking all injections:

```json
[
  {
    "alert_id": "SOC-PHISHING-20251126-001",
    "status": "success",
    "external_id": "alert_ext_123456",
    "error": null,
    "http_code": 200,
    "timestamp": "2025-11-26T11:14:31.447926Z"
  },
  {
    "alert_id": "SOC-IMPOSSIBLE-TRAVEL-20220504-001",
    "status": "failed",
    "external_id": null,
    "error": "HTTP 400: Invalid severity value",
    "http_code": 400,
    "timestamp": "2025-11-26T11:14:32.123456Z"
  }
]
```

### Summary Report

```
============================================================
INJECTION SUMMARY
============================================================
Total Alerts: 3
Successful: 2
Failed: 1
Skipped: 0
Success Rate: 66.67%
============================================================
```

## Rate Limiting

The injector automatically enforces rate limiting:

- **Limit**: 600 alerts/minute
- **Delay**: ~0.1 second per alert (60s / 600)
- **Behavior**: Sleeps between requests as needed

This ensures compliance with XSIAM API constraints.

## Validation Rules

Alerts are validated against these required fields:

| Field | Type | Description |
|-------|------|-------------|
| `vendor` | string | Alert source/vendor name |
| `product` | string | Alert product/instance |
| `severity` | string | One of: Informational, Low, Medium, High, Critical |
| `category` | string | Alert category (MITRE or custom) |

Optional fields include: `title`, `details`, `alert_id`, `timestamp`, `remote_ip`, `host_name`, `initiated_by`, `mitre_defs`, and many others.

See `data/SCHEMA_GUIDE.md` for complete field reference.

## Error Handling

### Validation Errors

```
Alert SOC-PHISHING-001: Validation failed: 'severity' is a required property
```

**Solution**: Ensure all required fields (vendor, product, severity, category) are present and valid.

### API Errors

```
Alert SOC-PHISHING-001: HTTP 401: Unauthorized
```

**Solution**: Check API credentials in environment variables or command-line options.

```
Alert SOC-PHISHING-001: HTTP 429: Too Many Requests
```

**Solution**: Reduce batch size or wait before retrying. Rate limit is 600/minute.

### Connection Errors

```
Alert SOC-PHISHING-001: Request failed: Connection timeout
```

**Solution**: Verify XSIAM API URL is correct and accessible.

## Workflow Examples

### Example 1: Validate Then Inject

```bash
# Step 1: Validate all alerts
python3 src/injector.py --validate issues_jsons/phishing_alert_clean.json

# Step 2: Dry-run
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json --dry-run

# Step 3: Actual injection
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json
```

### Example 2: Batch Processing with Progress

```bash
# Inject 500 alerts with progress every 50
python3 src/injector.py --dir /path/to/alerts/ --batch-size 50
```

Output:
```
Progress: 50 alerts processed. Success: 50, Failed: 0
Progress: 100 alerts processed. Success: 100, Failed: 0
Progress: 150 alerts processed. Success: 148, Failed: 2
...
```

### Example 3: Review Failed Alerts

After injection, check `injection_results.json`:

```python
import json

with open("injection_results.json") as f:
    results = json.load(f)
    
failed = [r for r in results if r["status"] == "failed"]
for r in failed:
    print(f"{r['alert_id']}: {r['error']}")
```

## Best Practices

1. **Always validate first** - Use `--validate` before injecting production alerts
2. **Use dry-run** - Test with `--dry-run` to verify payload structure
3. **Monitor results** - Review `injection_results.json` after injection
4. **Batch intelligently** - Large batches may exceed rate limits
5. **Check logs** - Review `injector.log` for detailed error messages
6. **Secure credentials** - Use environment variables, never hardcode API keys
7. **Test with examples** - Start with our clean alert examples

## Troubleshooting

### Q: "Schema file not found"
**A**: Ensure you're running from the project root directory or specify `--schema` path.

### Q: "All alerts failed validation"
**A**: Check that your JSON files have all 4 required fields: vendor, product, severity, category.

### Q: "HTTP 400 errors"
**A**: Severity must be exactly one of: "Informational", "Low", "Medium", "High", "Critical" (case-sensitive).

### Q: "Rate limit errors"
**A**: The injector includes automatic rate limiting. If still getting 429 errors, reduce batch size.

### Q: "Validation passes but injection fails"
**A**: Check API credentials, URL, and network connectivity. Review detailed logs with `--verbose`.

## Integration with XSIAM

After successful injection:

1. **Alerts appear in XSIAM UI** with the external ID
2. **External ID maps back** to source alert for correlation
3. **Results are logged** in `injection_results.json` for audit
4. **Alerts are queryable** in XSIAM's alert management dashboard

## Performance Metrics

- **Validation**: ~1ms per alert
- **Injection**: ~100ms per alert (including rate limit delay)
- **Throughput**: ~600 alerts/minute (at rate limit)
- **Batch size**: Recommended 100-500 for optimal performance

## Next Steps (Step 4)

The injector completes Step 3. Step 4 will focus on:
- Advanced API client wrapper
- Retry mechanisms for failed alerts
- Webhook support for real-time injection
- Alert enrichment pipeline

## Support

For issues or questions:
1. Check `injector.log` for detailed error messages
2. Review validation errors in console output
3. Verify API credentials and network connectivity
4. Test with provided clean alert examples
5. Review XSIAM API documentation for response codes
