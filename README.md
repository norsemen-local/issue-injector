# XSIAM Alert Injector

A Python tool for injecting realistic, multi-campaign security alerts into Palo Alto Networks Cortex XSIAM. Built for security testing, SOC training, detection validation, and incident response exercises.

## 📋 Project Description

This tool enables security teams to inject complete attack campaigns into XSIAM with realistic temporal sequencing and multi-layer detection coverage. Each campaign is based on real-world threat intelligence from Unit42 and includes alerts across email gateways, DNS security, firewalls, and endpoints.

**Key Capabilities:**
- Inject single alerts or complete attack campaigns
- Automatic timestamp generation with relative time offsets
- 318 validated XSIAM custom fields with proper type conversions
- Alert correlation for incident grouping
- 86% success rate across 39 production-tested alerts

## 🔧 Prerequisites

- Python 3.8+
- Cortex XSIAM tenant with API access
- API Key and API Key ID from XSIAM

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/xsiam-alert-injector.git
cd xsiam-alert-injector

# Install dependencies
pip install -r requirements.txt

# Configure API credentials
cp .env.template .env
# Edit .env with your XSIAM credentials
```

## ⚙️ Configuration

Edit `.env` with your XSIAM tenant API credentials:

```bash
XSIAM_API_URL=https://api-your-tenant.xdr.us.paloaltonetworks.com
XSIAM_API_KEY=your-api-key-here
XSIAM_API_KEY_ID=your-api-key-id-here
```

**To obtain API credentials:**
1. Log into your XSIAM tenant
2. Navigate to **Settings → Configurations → API Keys**
3. Create a new API key with alert creation permissions
4. Copy the API Key and API Key ID to your `.env` file

## 🚀 How to Run Injections

### Quick Start - Single Alert

```bash
python3 src/injector.py --file examples/campaigns/medusa/medusa_campaign_01_initial_access.json
```

### Inject Multiple Alerts from a Campaign

```bash
# Inject entire Medusa ransomware campaign (6 alerts)
python3 src/injector.py --dir examples/campaigns/medusa/
```

### Inject Specific Alerts

```bash
# Single alert with verbose output
python3 src/injector.py --file examples/campaigns/adaptixc2/adaptix_campaign_01_email_phishing.json --verbose

# Multiple specific alerts
python3 src/injector.py --file examples/campaigns/clickfix/clickfix_campaign_01_phishing.json
python3 src/injector.py --file examples/campaigns/clickfix/clickfix_campaign_02_dns.json
```

### Dry-Run Mode (Validation Only)

```bash
# Validate alert structure without injecting
python3 src/injector.py --file examples/campaigns/phantomvai/phantomvai_campaign_01_phishing.json --dry-run
```

### Command Options

- `--file <path>` - Inject a single alert JSON file
- `--dir <path>` - Inject all alerts in a directory
- `--verbose` - Enable detailed logging
- `--dry-run` - Validate alerts without sending to XSIAM

## 📁 Project Structure

```
xsiam-alert-injector/
├── src/                          # Core application code
│   ├── injector.py               # Main alert injector with auto-timestamp
│   ├── validator.py              # Schema validation
│   ├── result_logger.py          # Results tracking
│   └── api_client.py             # XSIAM API client
│
├── examples/                     # Alert examples and campaigns
│   └── campaigns/                # Complete attack campaigns
│       ├── medusa/               # Medusa ransomware (6 alerts)
│       ├── phantomvai/           # PhantomVAI loader (7 alerts)
│       ├── operation_rewrite/    # BadIIS SEO poisoning (8 alerts)
│       ├── clickfix/             # ClickFix-DeerStealer (8 alerts)
│       ├── adaptixc2/            # AdaptixC2 framework (10 alerts)
│       └── standalone_issues/    # Individual alert examples
│
├── docs/                         # Documentation and reference
│   ├── schema.json               # Complete XSIAM field reference (318 fields)
│   └── analytics_rules.jsonl    # XSIAM detection rules database (735 rules)
│
├── archive/                      # Research and development artifacts
│   ├── test_scripts/             # Field discovery test scripts
│   ├── test_results/             # API testing results
│   ├── old_docs/                 # Historical documentation
│   └── scripts/                  # Utility scripts
│
├── .env.template                 # Environment variables template
├── .gitignore                    # Git ignore patterns
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

### Component Descriptions

**`src/`** - Core Python application
- **injector.py** - Main script that handles alert injection, automatic timestamp generation, and API communication
- **validator.py** - Validates alert JSON against XSIAM schema requirements
- **result_logger.py** - Tracks injection results and logs outcomes
- **api_client.py** - Manages XSIAM API authentication and requests

**`examples/campaigns/`** - Pre-built attack campaigns
- Each campaign directory contains a complete attack story with multiple alerts
- Alerts are numbered sequentially (01, 02, 03...) representing attack progression
- All alerts use `relative_timestamp_hours` for realistic temporal sequencing
- Campaigns correlate into single incidents in XSIAM through common grouping fields

**`examples/campaigns/standalone_issues/`** - Individual alert examples
- Single-alert scenarios for testing specific detection use cases
- Useful for learning alert structure or testing specific field combinations

**`docs/schema.json`** - Complete XSIAM field reference
- Documents all 318 validated custom fields
- Includes field types, transformations, and usage examples
- **Tested on Cortex XSIAM v3.4** (Last validated: February 2nd, 2026)
- Contains required fields (7), custom field categories (23), and field type specifications

**`docs/analytics_rules.jsonl`** - XSIAM detection rules database
- 735 XSIAM analytics rules with alert mappings
- Shows which rules should fire for campaign alerts
- Useful for detection validation and alert correlation

**`archive/`** - Research artifacts
- Historical test scripts used for field discovery
- API testing results and validation data
- Legacy documentation preserved for reference

## 📊 Available Campaigns

| Campaign | Alerts | Timeline | Description | Reference |
|----------|--------|----------|-------------|-----------|
| **Medusa Ransomware** | 6 | 4 hours | TOR RDP login → Credential dump → Lateral movement → Encryption | [Unit42 Blog](https://unit42.paloaltonetworks.com/medusa-ransomware-escalation-new-leak-site/) |
| **PhantomVAI Loader** | 7 | 1.5 hours | Phishing → PowerShell → Steganography → Credential theft | [Unit42 Blog](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/) |
| **Operation Rewrite** | 8 | 4 days | Web shell → Code exfiltration → BadIIS → SEO poisoning | [Unit42 Blog](https://unit42.paloaltonetworks.com/operation-rewrite-seo-poisoning-campaign/) |
| **ClickFix-DeerStealer** | 8 | 1.5 hours | Browser hijacking → Clipboard abuse → Credential harvesting | [Unit42 Blog](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/) |
| **AdaptixC2** | 10 | 2.4 hours | RMM abuse → AI-generated loader → Data exfiltration | [Unit42 Blog](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/) |

### Campaign Details

**1. Medusa Ransomware Campaign**
- **Attack Flow:** TOR RDP login → LSASS credential dump → PSExec lateral movement → SMB enumeration → Mass exfiltration → File encryption
- **Victim:** VictimCorp | **User:** jsmith@victimcorp.local
- **Detection Layers:** Endpoint, Firewall, Network

**2. PhantomVAI Loader Campaign**
- **Attack Flow:** Phishing → Obfuscated PowerShell → Firewall CDN detection → Steganographic GIF payload → C2 beacon → Process injection → Credential exfiltration (488 total credentials)
- **Victim:** TechCorp | **User:** mthomas@techcorp.local
- **Detection Layers:** Email Gateway, DNS, Firewall, Endpoint

**3. Operation Rewrite - BadIIS SEO Poisoning**
- **Attack Flow:** ASP.NET web shell → Lateral movement → Source code exfiltration (473MB) → BadIIS module installation → SEO poisoning → 2,847 victim redirections
- **Victim:** Vietnamese government entity | **Threat Actor:** CL-UNK-1037
- **Detection Layers:** Firewall, Endpoint, Network

**4. ClickFix-DeerStealer Campaign**
- **Attack Flow:** Phishing → Fake browser verification → DNS detection → URL filtering → JavaScript clipboard hijacking → PowerShell execution → DeerStealer → Credential harvesting (1,420 total credentials) → Exfiltration
- **Victim:** MarketingCorp | **User:** jdavis@marketingcorp.com
- **Detection Layers:** Email Gateway, DNS, Firewall, Endpoint

**5. AdaptixC2 Campaign**
- **Attack Flow:** Fake Teams helpdesk phishing → QuickAssist RMM abuse → AI-generated PowerShell loader → DLL hijacking persistence → C2 beacon → AD reconnaissance → Data staging (127 files, 87.3MB) → Mass exfiltration (34.2MB) → SMB lateral movement
- **Victim:** FinancialCorp | **User:** rbrown@financialcorp.com
- **Critical Data Exposed:** Q4 2025 earnings ($847M), M&A intelligence, PII
- **Detection Layers:** Email Gateway, DNS, Firewall, Endpoint

## 📖 Schema Documentation (docs/schema.json)

The `schema.json` file is the complete reference for all XSIAM alert fields validated through systematic API testing.

### Version Information
- **XSIAM Version Tested:** Cortex XSIAM v3.4
- **Last Validation Date:** February 2nd, 2026
- **Total Fields Validated:** 318 custom fields
- **Success Rate:** ~65% of tested fields accepted by API

### What's in schema.json

**1. Required Fields (7)**
- `vendor`, `product`, `severity`, `category`, `alert_id`, `timestamp`, `description`
- These fields are mandatory for every alert

**2. Custom Fields (318) organized in 23 categories:**
- Core Alert (14 fields)
- Host/Device (16 fields)
- User/Identity (26 fields)
- Process (26 fields)
- Network (22 fields)
- Email/Phishing (37 fields)
- File/Hash (14 fields)
- Cloud/Container (19 fields)
- Detection/Source (14 fields)
- Threat Intelligence (23 fields)
- MITRE ATT&CK (2 fields)
- And 12 more categories...

**3. Field Type Specifications**
- **Arrays:** `"file_path": ["C:\\Users\\file.exe"]` (must be arrays, not strings)
- **Integers:** `"local_port": 443` (not strings)
- **Strings:** `"file_size": "4096"` (some numeric fields expect strings)
- **Special conversions:** IP addresses to integers, timestamps in milliseconds

**4. Transformation Rules**
- Python code examples for IP-to-integer conversion
- Timestamp generation (milliseconds since epoch)
- Multi-select field formatting

**5. Known Limitations**
- 10 unsupported fields documented
- Common API error patterns explained

**6. Usage Examples**
- Minimal alert (required fields only)
- Phishing alert (email fields)
- Malware alert (file/process fields)

### Important Notes on Timestamps

**Automatic Timestamp Generation:**
The injector automatically generates timestamps if not provided. You can use `relative_timestamp_hours` to create realistic attack timelines:

```json
{
  "relative_timestamp_hours": 48.0  // 48 hours ago
}
```

This allows campaigns to have proper temporal sequencing without manual timestamp management. The injector converts this to milliseconds since epoch automatically.

### Common Field Type Issues

**HTTP 500 Errors** usually indicate schema validation failures:

❌ **Wrong:**
```json
{
  "file_path": "C:\\Users\\file.exe",      // String - will fail
  "local_port": "443",                      // String - will fail
  "mitre_att&ck_technique": "T1548, T1078"  // Multiple - will fail
}
```

✅ **Correct:**
```json
{
  "file_path": ["C:\\Users\\file.exe"],          // Array
  "local_port": 443,                              // Integer
  "mitre_att&ck_technique": "T1548 - Abuse Elevation Control Mechanism"  // Single value
}
```

## 🎯 Single Issues vs Campaigns

### Single Issues (`examples/campaigns/standalone_issues/`)

Individual alerts for testing specific scenarios:
- `auth_brute_force_attack.json` - Brute force authentication
- `malware_emotet_banking_trojan.json` - Banking trojan detection
- `phishing_alert_clean.json` - Phishing email detection
- `network_c2_dns_tunneling.json` - DNS tunneling C2
- And more...

**Use single issues when:**
- Testing specific XSIAM detection rules
- Validating field combinations
- Learning alert structure
- Quick one-off testing

### Campaigns (`examples/campaigns/<campaign_name>/`)

Complete multi-alert attack stories that correlate into single incidents:
- Multiple alerts representing attack progression
- Realistic temporal sequencing with `relative_timestamp_hours`
- Common victim/user/domain fields for incident correlation
- Based on real-world Unit42 threat intelligence

**Use campaigns when:**
- Demonstrating complete attack scenarios
- Training SOC analysts on incident response
- Validating multi-stage detection and correlation
- Testing XSIAM incident grouping

## 📊 Project Statistics

- **Total Campaigns:** 5 complete attack stories
- **Total Campaign Alerts:** 39 alerts
- **Standalone Issues:** 15+ individual alerts
- **Field Coverage:** 318 custom fields validated
- **Detection Layers:** Email, DNS, Firewall, Endpoint
- **Success Rate:** 86.41% (89/103 alerts successfully injected)
- **Analytics Rules Database:** 735 XSIAM rules documented

## 🔗 Resources

- [Cortex XSIAM Documentation](https://docs-cortex.paloaltonetworks.com/)
- [XSIAM API Reference](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-API-Reference)
- [Unit42 Threat Intelligence](https://unit42.paloaltonetworks.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## ⚠️ Disclaimer

This tool is intended for **authorized testing and training purposes only** in XSIAM environments. Users are responsible for:
- Obtaining proper authorization before injecting alerts
- Coordinating with SOC teams to avoid confusion with real incidents
- Ensuring compliance with organizational security policies
- Not using this tool in production without approval

---

**318 fields validated. 5 complete campaigns. Production ready.**
