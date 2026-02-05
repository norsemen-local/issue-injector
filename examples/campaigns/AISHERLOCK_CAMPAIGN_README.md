# EbjvPhishing-2026-01 Campaign: AI Sherlock Account Compromise

## Campaign Overview
**Victim User**: aisherlock@agentix.ad.bakerstreetlabs.io  
**Campaign Name**: EbjvPhishing-2026-01  
**Domain**: agentix.ad.bakerstreetlabs.io  
**Attack Vector**: Credential phishing via fake file-sharing site  
**Timeline**: 2 alerts over 4.42 hours  
**Status**: ✅ Both alerts successfully injected

---

## Attack Timeline

### Alert 1: Firewall - Phishing Site Access (83.85 hours ago)
**File**: `aisherlock_campaign_01_firewall_phishing.json`

- **Vendor**: Palo Alto Networks PA-5220
- **Severity**: High
- **Detection**: URL Filtering flagged access to https://ebjv.com.au/filesharer
- **Workstation**: LABS-WKS-221 (10.50.42.187)
- **Phishing Site IP**: 203.220.182.45 (Melbourne, Australia)
- **User Action**: Clicked phishing link, bypassed warning, submitted credentials
- **MITRE**: T1566.002 - Phishing: Spearphishing Link

**Key Details**:
- Domain registered 7 days prior (2026-01-15)
- Fake file-sharing lure mimicking OneDrive/Dropbox
- User overrode firewall warning ("Proceed Anyway")
- 3.2KB data sent (credential form submission)
- Session duration: 47 seconds

---

### Alert 2: Impossible Travel - Account Compromise (79.43 hours ago)
**File**: `aisherlock_campaign_02_impossible_travel.json`

- **Vendor**: Microsoft Azure AD Identity Protection
- **Severity**: Critical
- **Detection**: Authentication from two impossible locations
- **Travel**: London, UK → Sydney, Australia
- **Distance**: 17,015 km in 3 hours 25 minutes
- **Required Speed**: 4,975 km/h (physically impossible)
- **MITRE**: T1078.004 - Valid Accounts: Cloud Accounts

**Authentication Details**:

| Location | IP | Device | Activity |
|----------|-----|--------|----------|
| London | 81.2.69.142 | Windows 10 (Corporate Laptop) | Normal email/calendar access |
| Sydney | 1.128.0.10 | Android (Unknown device) | Bulk OneDrive download (47 files, 127MB) |

**Compromise Indicators**:
- Sydney IP associated with credential stuffing attacks
- Unfamiliar Android device (Samsung Galaxy)
- Legacy auth protocol used (bypassed MFA)
- Immediate data exfiltration behavior
- Accessed sensitive Teams channels

---

## Attack Narrative

1. **Initial Access (83.85h ago)**: User aisherlock received phishing email with link to ebjv.com.au/filesharer
2. **Credential Theft**: User clicked link, bypassed firewall warning, entered credentials on fake file-sharing site
3. **Harvesting**: Phishing site captured username/password via POST to /auth/validate
4. **Account Usage (79.43h ago)**: Attacker authenticated from Sydney using stolen credentials
5. **Detection**: Azure AD detected impossible travel (London→Sydney in 4.42 hours)
6. **Exfiltration**: Attacker downloaded 47 files (127MB) from OneDrive within 10 minutes

---

## Correlation Fields

Both alerts share these fields for incident grouping:
- `campaign_name`: "EbjvPhishing-2026-01"
- `user_name`: ["aisherlock@agentix.ad.bakerstreetlabs.io"]
- `domain`: "agentix.ad.bakerstreetlabs.io"
- `threat_actor`: "Unknown Phishing Operator"

---

## Technical Details

### IP Addresses (Converted to Integers)
- Internal Workstation: 10.50.42.187 → 171059899
- Phishing Site: 203.220.182.45 → 3420239405
- London IP: 81.2.69.142 → 1359103374
- Sydney IP: 1.128.0.10 → 25165834

### Firewall Details
- Device: PA-5220-FW-CORE-01
- Serial: 015351000098765
- Rule: Corporate-Web-Access-With-Filtering (rule-247)
- Zones: Trust-Corporate → Untrust-Internet
- Ports: 52847 (local) → 443 (remote)

### Phishing Site Intelligence
- Domain: ebjv.com.au
- Registration: 2026-01-15 (7 days old)
- Registrar: Namecheap (privacy-protected)
- Nameservers: Cloudflare
- TLS: Let's Encrypt (same-day issuance)
- Threat Score: 87/100

---

## Remediation Actions

### Immediate (Critical)
1. ✅ Reset password for aisherlock@agentix.ad.bakerstreetlabs.io
2. ✅ Revoke all active sessions and refresh tokens
3. ✅ Block ebjv.com.au and IPs at DNS/firewall
4. ✅ Isolate LABS-WKS-221 for forensic analysis
5. ✅ Review OneDrive audit logs for exfiltrated files

### Short-term (High)
- Disable legacy authentication protocols organization-wide
- Enable MFA enforcement for all protocols (no exceptions)
- Review URL Filtering policy (remove "Proceed Anyway" option for phishing)
- Hunt for similar phishing emails in organization
- Scan for credential reuse across user's accounts

### Long-term (Medium)
- Deploy FIDO2 hardware keys for high-risk users
- Enable Azure AD risk-based conditional access
- Implement continuous access evaluation (CAE)
- Security awareness training on phishing recognition
- Consider passwordless authentication migration

---

## Detection Opportunities

### Firewall Alerts
- URL Filtering: Phishing category detection
- User override of security warnings
- Newly registered domain access
- Credential form submission to external sites

### Identity Protection Alerts
- Impossible travel detection
- Unfamiliar device authentication
- Legacy authentication protocol usage
- IP reputation (VPN/credential stuffing indicators)
- Abnormal data access patterns (bulk downloads)

---

## Files Created
- `aisherlock_campaign_01_firewall_phishing.json` - Firewall phishing detection
- `aisherlock_campaign_02_impossible_travel.json` - Impossible travel alert
- `AISHERLOCK_CAMPAIGN_README.md` - This documentation

---

**Campaign Created**: 2026-01-22  
**Status**: ✅ Production Ready - Both alerts successfully injected  
**Success Rate**: 100% (2/2 alerts)  
**XSIAM Correlation**: Alerts should group into single incident via campaign_name and user_name
