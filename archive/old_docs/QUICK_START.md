# Quick Start - Injector Commands

## Setup (one-time)

```bash
cd /Users/mabutbul/Desktop/agentix_issues
pip install -r requirements.txt
export XSIAM_API_URL="https://your-xsiam.api.com"
export XSIAM_API_KEY="your-api-key"
export XSIAM_API_KEY_ID="your-api-key-id"
```

## Common Commands

### Validate Alerts
```bash
# Single file
python3 src/injector.py --validate issues_jsons/phishing_alert_clean.json

# Show all alerts valid
# Output: ✓ All 1 alert(s) are valid
```

### Test with Dry-Run (No API calls)
```bash
# Single file
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json --dry-run

# Directory
python3 src/injector.py --dir issues_jsons/ --dry-run

# With verbose logging
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json --dry-run --verbose
```

### Actually Inject to XSIAM
```bash
# Single file
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json

# Both clean alerts
python3 src/injector.py --dir issues_jsons/ --batch-size 50

# Custom API URL (overrides env var)
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json \
    --api-url https://custom-xsiam.com
```

## Check Results

```bash
# View real-time log
tail -f injector.log

# View all results in JSON
cat injection_results.json | python3 -m json.tool

# Get just external IDs
python3 -c "
import json
with open('injection_results.json') as f:
    results = json.load(f)
    for r in results:
        if r['status'] == 'success':
            print(f\"{r['alert_id']}: {r['external_id']}\")
"

# Check failed alerts
python3 -c "
import json
with open('injection_results.json') as f:
    results = json.load(f)
    for r in results:
        if r['status'] == 'failed':
            print(f\"{r['alert_id']}: {r['error']}\")
"
```

## Error Troubleshooting

### Error: "Schema file not found"
```bash
# Solution: Make sure you're in the project root
pwd  # Should be /Users/mabutbul/Desktop/agentix_issues
ls data/schema.json  # Should exist
```

### Error: "HTTP 401 Unauthorized"
```bash
# Solution: Check API credentials
echo $XSIAM_API_KEY
echo $XSIAM_API_KEY_ID
# If empty, re-export them
```

### Error: "Validation failed"
```bash
# Solution: Check alert has 4 required fields
python3 src/injector.py --validate your_alert.json --verbose
```

### Error: "HTTP 429 Too Many Requests"
```bash
# Solution: Reduce batch size or wait
python3 src/injector.py --dir issues_jsons/ --batch-size 50
```

## File Locations

```
Project Root: /Users/mabutbul/Desktop/agentix_issues/

Key Files:
  data/schema.json                    # Alert schema (required)
  issues_jsons/phishing_alert_clean.json           # Example alert 1
  issues_jsons/impossible_travel_alert_clean.json  # Example alert 2
  src/injector.py                     # Main script
  
Generated Files:
  injector.log                        # Detailed log
  injection_results.json              # Results (created after first injection)
```

## Output Examples

### Successful Validation
```
2025-11-26 13:14:23,463 - validator - INFO - All 1 alert(s) from issues_jsons/phishing_alert_clean.json are valid
2025-11-26 13:14:23,463 - __main__ - INFO - ✓ All 1 alert(s) are valid
```

### Successful Injection (Dry-Run)
```
2025-11-26 13:14:31,437 - __main__ - INFO - Injecting alert: SOC-PHISHING-20251126-001
2025-11-26 13:14:31,447 - __main__ - INFO - [DRY-RUN] Would POST to https://api.xsiam.example.com/...
2025-11-26 13:14:31,448 - result_logger - INFO - Success Rate: 100.00%
```

### Results JSON (After Actual Injection)
```json
[
  {
    "alert_id": "SOC-PHISHING-20251126-001",
    "status": "success",
    "external_id": "alert_ext_123456",
    "http_code": 200,
    "timestamp": "2025-11-26T11:14:31.447926Z"
  }
]
```

## Complete Workflow

```bash
# 1. Install and configure
pip install -r requirements.txt
export XSIAM_API_KEY="..."
export XSIAM_API_KEY_ID="..."

# 2. Validate
python3 src/injector.py --validate issues_jsons/phishing_alert_clean.json
# Output: ✓ All 1 alert(s) are valid

# 3. Dry-run
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json --dry-run
# Output: [DRY-RUN] Would POST to https://...

# 4. Inject
python3 src/injector.py --file issues_jsons/phishing_alert_clean.json
# Output: Alert SOC-PHISHING-20251126-001 injected successfully. External ID: alert_ext_123456

# 5. Check results
cat injection_results.json
```

## For More Information

See:
- `INJECTOR_GUIDE.md` - Complete documentation
- `PROJECT_STATUS.md` - Project overview
- `data/SCHEMA_GUIDE.md` - Alert field reference
- `data/VENDOR_REFERENCE.md` - Vendor best practices
