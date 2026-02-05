# Alert to Detection Rule Mapping

This document tracks which of our injected alert JSONs correspond to detection rules in `analytics_rules.jsonl`.

## Analytics Rules Database
- **Total Rules**: 735 XDR detection rules
- **Source**: XDR Analytics BIOC
- **File**: `analytics_rules.jsonl`
- **Added**: 2025-11-27

## Coverage Tracking

### ✅ Alerts Created (37 total)

#### Cloud/SaaS Security (7 alerts)
1. **Google Drive External Sharing** → _Rule TBD_
2. **SharePoint Malware Upload** → _Rule TBD_
3. **Exchange Forwarding Rule** → _Rule TBD_
4. **Weak Kerberos Encryption** → _Rule TBD_
5. **Azure MFA Disabled** → _Rule TBD_
6. **Rare RDP Session** → _Rule TBD_
7. **Okta Admin Privilege Grant** → _Rule TBD_

#### Authentication & Identity (5 alerts)
8. **SSO Sign-in from TOR** → _Rule TBD_
9. **Suspicious LDAP Query** → _Rule TBD_
10. **Multiple Unusual SSO Resources** → _Rule TBD_
11. **User Added Member to Privileged Group (First Time)** → _Rule TBD_
12. **User Added to Privileged Group** → _Rule TBD_

#### Credential Access (3 alerts)
13. **Browser Credential Theft** → _Rule TBD_
14. **Mimikatz Detected** → Possible match: Rule analyzing LSASS access
15. **PowerShell Mailbox Log Removal** → _Rule TBD_

#### Defense Evasion (2 alerts)
16. **Windows Event Log Cleared** → _Rule TBD_
17. **Mailbox Export Log Removal** → _Rule TBD_

#### Network Activity (3 alerts)
18. **Netcat Connection** → _Rule TBD_
19. **Port Scan Detected** → _Rule TBD_
20. **Rare RDP Session** → _Rule TBD_

#### Container Security (1 alert)
21. **Kubernetes Container Escape** → _Rule TBD_

#### Legacy Alerts (16 previous alerts)
22-37. **Various malware, phishing, exploitation alerts** → _Rules TBD_

## Next Steps

### Immediate Actions
- [ ] Parse `analytics_rules.jsonl` to extract all rule names and MITRE mappings
- [ ] Match existing alerts to detection rules based on:
  - MITRE ATT&CK technique overlap
  - Description/behavior similarity
  - Alert category alignment
- [ ] Identify **gaps** - high-value detection rules without corresponding alert JSONs
- [ ] Create alert JSONs for top gaps

### Future Enhancements
- [ ] Add `detection_rule_id` field to alert JSONs for explicit mapping
- [ ] Create automated matching script based on MITRE techniques
- [ ] Generate coverage report: X% of detection rules have test alerts
- [ ] Prioritize alert creation for critical/high severity rules

## Value Proposition
This mapping enables:
1. **Comprehensive testing** - Ensure detection rules trigger on realistic alerts
2. **Gap analysis** - Identify missing alert coverage
3. **Documentation** - Clear linkage between alerts and detections
4. **Quality assurance** - Validate detection rule effectiveness

## Usage
```bash
# Search for specific detection rule
cat analytics_rules.jsonl | jq 'select(.name | contains("Mimikatz"))'

# Count rules by severity
cat analytics_rules.jsonl | jq -r '.severity' | sort | uniq -c

# Extract rules matching MITRE technique
cat analytics_rules.jsonl | jq 'select(.mitre_techniques[] | contains("T1003"))'
```
