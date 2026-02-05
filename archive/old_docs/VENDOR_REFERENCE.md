# Realistic Vendor & Product Reference

This guide provides examples of realistic vendor and product names to use in alert creation. Using real, recognizable vendors and products makes alerts more professional and production-ready.

## Common Security Vendors & Products

### Email Security
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Proofpoint** | Email Security Gateway | Phishing detection, spam filtering |
| **Proofpoint** | Threat Response | Advanced email threat investigation |
| **Mimecast** | Email Security | Email protection, archiving |
| **Microsoft** | Exchange Online Protection | Email filtering, ATP |
| **Cisco** | Email Security Appliance | Gateway-based email protection |

### Identity & Access Management
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Microsoft** | Azure AD Identity Protection | Impossible travel, risky sign-ins |
| **Microsoft** | Azure AD | User identity and authentication |
| **Okta** | Identity Cloud | Identity management, MFA |
| **Ping Identity** | PingOne | Identity platform |
| **CyberArk** | Privileged Access Security | PAM detection and prevention |

### Endpoint Security
| Vendor | Product | Use Case |
|--------|---------|----------|
| **CrowdStrike** | Falcon Platform | Endpoint detection and response |
| **CrowdStrike** | Falcon Insight | Threat intelligence |
| **Microsoft** | Defender for Endpoint | EDR, threat detection |
| **SentinelOne** | Singularity Platform | EDR, XDR |
| **VMware Carbon Black** | Cloud Workload Protection | Endpoint protection |

### SIEM & Log Management
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Splunk** | Enterprise Security | SIEM, threat detection |
| **Splunk** | Cloud Platform | Cloud-native SIEM |
| **Microsoft** | Sentinel | Cloud SIEM |
| **Elastic** | Security | SIEM and analytics |
| **Sumo Logic** | Cloud Security | Cloud-native SIEM |

### Network & Threat Detection
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Palo Alto Networks** | Cortex XDR | Extended detection and response |
| **Palo Alto Networks** | Firewall | Network security |
| **Fortinet** | FortiGate | Firewall, IPS/IDS |
| **Cisco** | Talos | Threat intelligence |
| **Zeek** | Network Monitor | Network intrusion detection |

### Threat Intelligence & Analysis
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Mandiant** | Mandiant Advantage | Threat intelligence |
| **Recorded Future** | Insikt Group | Threat intelligence |
| **VirusTotal** | VirusTotal API | File/URL reputation |
| **AbuseIPDB** | AbuseIPDB | IP reputation |

### Cloud & Container Security
| Vendor | Product | Use Case |
|--------|---------|----------|
| **Aqua Security** | Aqua Platform | Container security |
| **Wiz** | Cloud Security Platform | Cloud posture management |
| **Lacework** | Cloud Security Platform | Cloud workload protection |
| **Check Point** | CloudGuard | Cloud security |

## Alert ID Naming Conventions

Create professional, traceable alert IDs using these patterns:

### Pattern 1: Vendor-AlertType-Date-Sequence
```
PROOFPOINT-PHISHING-20251123-001
MICROSOFT-IMPOSSIBLETRAVEL-20251123-002
CROWDSTRIKE-MALWARE-20251123-003
```

### Pattern 2: Vendor-AlertType-Timestamp
```
PROOFPOINT-PHISHING-20251123T053000Z
MICROSOFT-UNAUTH-LOGIN-20251123T102000Z
```

### Pattern 3: Source-System-AlertID
```
AZURE-AD-RISK-20251123-001
SPLUNK-CORRELATION-20251123-002
```

## Real-World Examples

### Example 1: Proofpoint Phishing Alert
```json
{
  "vendor": "Proofpoint",
  "product": "Email Security Gateway",
  "severity": "High",
  "category": "Phishing",
  "alert_id": "PROOFPOINT-PHISHING-20251123-001",
  "title": "Phishing Email Detected - Credential Harvest Attempt"
}
```

### Example 2: Microsoft Azure AD Alert
```json
{
  "vendor": "Microsoft",
  "product": "Azure AD Identity Protection",
  "severity": "High",
  "category": "Credential Access",
  "alert_id": "AZURE-IMPOSSIBLE-TRAVEL-20251123-001",
  "title": "Impossible Travel Alert - Suspicious Account Activity"
}
```

### Example 3: CrowdStrike Endpoint Alert
```json
{
  "vendor": "CrowdStrike",
  "product": "Falcon Platform",
  "severity": "Critical",
  "category": "Execution",
  "alert_id": "CROWDSTRIKE-MALWARE-20251123-001",
  "title": "Malware Detected - Suspicious Process Execution"
}
```

### Example 4: Splunk SIEM Alert
```json
{
  "vendor": "Splunk",
  "product": "Enterprise Security",
  "severity": "Medium",
  "category": "Reconnaissance",
  "alert_id": "SPLUNK-RECON-20251123-001",
  "title": "Port Scanning Activity Detected"
}
```

## Best Practices

1. **Use Real Vendor Names**: Never use placeholder names like "DemoGenerator" or "TestSystem"
   - ✅ Proofpoint, Microsoft, CrowdStrike
   - ❌ DemoIncidentGenerator, TestVendor

2. **Match Product to Vendor**: Ensure the product actually exists from that vendor
   - ✅ Proofpoint + "Email Security Gateway"
   - ❌ Proofpoint + "Firewall Dashboard"

3. **Use Realistic Product Names**: Match the actual product names vendors use
   - ✅ "Azure AD Identity Protection"
   - ❌ "Azure Protection System"

4. **Create Meaningful Alert IDs**: Include vendor, alert type, and timestamp
   - ✅ PROOFPOINT-PHISHING-20251123-001
   - ❌ ALERT-001

5. **Be Consistent**: Stick to a naming convention across all your alerts

6. **Include Real Details**: Reference actual attack patterns, MITRE techniques, etc.
   - ✅ "Email spoofs legitimate Google login page"
   - ❌ "Suspicious email detected"

## Common Alert Types by Vendor

### Proofpoint
- PHISHING - Phishing email detection
- MALWARE - Malware attachment detected
- IMPERSONATION - Domain/user impersonation
- FRAUD - Credential fraud detection

### Microsoft / Azure
- IMPOSSIBLE-TRAVEL - Geographically impossible logins
- RISKY-SIGNIN - Risky sign-in detected
- UNAUTH-LOGIN - Unauthorized login attempt
- MFA-FAILURE - Multi-factor authentication failure

### CrowdStrike
- MALWARE - Malware detected
- SUSPICIOUS-PROCESS - Suspicious process execution
- RANSOMWARE - Ransomware detection
- LATERAL-MOVEMENT - Lateral movement detected

### Splunk
- DDOS - DDoS attack detected
- EXFILTRATION - Data exfiltration attempt
- RECONNAISSANCE - Reconnaissance activity
- BRUTEFORCE - Brute force attack

## Testing Your Alerts

Before using alerts in production:

1. Verify vendor exists and is recognizable
2. Verify product is actually from that vendor
3. Ensure alert ID follows consistent pattern
4. Confirm category matches MITRE or is realistic
5. Check details are descriptive and professional
6. Validate all required fields are present

## Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Vendor Security Tools](https://gartner.com/reviews/market/magic-quadrant-for-enterprise-information-archiving)
- [CIS Controls](https://www.cisecurity.org/cis-controls/)

---

**Note**: This reference guide helps ensure alerts are realistic and professional. Using real vendor names and proper formatting makes alerts suitable for production environments and security training.
