# XSIAM Injectable Fields - Extraction Summary

## Overview
This document summarizes the fields extracted from **3 real XSIAM incident exports** that can be used to create accurate custom alerts/issues for injection.

**Source Files Analyzed:**
- `entry_artifact_72e5686a-3c64-4d7a-8188-edd2c369338f@35.md` (Vulnerability alert - CVE)
- `entry_artifact_a6e394ad-03e6-4cd2-805c-7ca9df41d4a6@43.md` (Initial Access - SSO)
- `entry_artifact_d0263fd4-213d-48a5-87c2-41d7462e7553@18.md` (Spyware detection)

## Field Categories

### 1. Core Required Fields (6 fields)
Essential for every alert:
- `name` - Alert title
- `description` - Detailed description
- `severity` - critical/high/medium/low/informational
- `category` - Alert category (e.g., "VULNERABILITY", "Initial Access")
- `action` - DETECTED/BLOCKED/BLOCKED_2/SCANNED/PREVENTED
- `action_pretty` - Human-readable action

### 2. Identity Fields (5 fields)
User and host identification:
- `user_name`, `host_name`, `host_ip`, `host_ip_list`, `endpoint_id`

### 3. Network Fields (7 fields)
Network connections and traffic:
- `action_local_ip`, `action_local_port`, `action_remote_ip`, `action_remote_port`
- `action_country`, `action_external_hostname`, `dns_query_name`

### 4. Process/File Fields (12 fields)
Process execution and file operations:
- Process: `actor_process_image_name`, `actor_process_image_path`, `actor_process_command_line`
- Hashes: `actor_process_image_sha256`, `actor_process_image_md5`
- Signatures: `actor_process_signature_status`, `actor_process_signature_vendor`
- Files: `action_file_name`, `action_file_path`, `action_file_sha256`, `action_file_md5`

### 5. MITRE ATT&CK Fields (2 fields)
- `mitre_tactic_id_and_name` - e.g., "TA0001 - Initial Access"
- `mitre_technique_id_and_name` - e.g., "T1078.002 - Valid Accounts: Domain Accounts"

### 6. Firewall Fields (11 fields)
Firewall-specific data:
- App: `fw_app_id`, `fw_app_category`, `fw_app_subcategory`, `fw_app_technology`
- Device: `fw_device_name`, `fw_serial_number`, `fw_rule`, `fw_rule_id`
- Network: `fw_interface_from`, `fw_interface_to`, `fw_url_domain`, `fw_vsys`
- Detection: `fw_is_phishing`

### 7. Cloud/Container Fields (7 fields)
Cloud and Kubernetes environments:
- `cloud_provider`, `cluster_name`, `container_id`, `container_name`
- `namespace`, `image_name`, `image_id`

### 8. Agent Fields (5 fields)
XDR agent information:
- `agent_version`, `agent_os_type`, `agent_os_sub_type`
- `agent_install_type`, `agent_is_vdi`

### 9. Metadata Fields (9 fields)
Alert metadata:
- IDs: `alert_id`, `external_id`
- Time: `detection_timestamp`
- Classification: `source`, `alert_domain`, `alert_type`, `tags`
- Features: `contains_featured_host`, `contains_featured_ip`, `contains_featured_user`

### 10. Event Context Fields (5 fields)
Event-specific information:
- `event_type`, `event_sub_type`, `event_id`, `event_timestamp`, `malicious_urls`

## Total: 86 Injectable Fields

## Common Alert Scenarios

### Scenario 1: Vulnerability Alert
**Required:** name, description, severity, category, source  
**Recommended:** host_name, host_ip, agent_os_type, detection_timestamp  
**Category:** "VULNERABILITY"

### Scenario 2: Initial Access Alert
**Required:** name, description, severity, category, user_name, action  
**Recommended:** host_name, host_ip, action_country, mitre_tactic_id_and_name  
**Category:** "Initial Access"

### Scenario 3: Malware/Spyware Alert
**Required:** name, description, severity, category, action  
**Recommended:** host_name, host_ip, actor_process_image_name, dns_query_name, fw_rule  
**Category:** "Spyware Detected via Anti-Spyware profile"

### Scenario 4: Network Threat Alert
**Required:** name, description, severity, category, action  
**Recommended:** action_local_ip, action_remote_ip, dns_query_name, fw_app_id, fw_device_name

## Usage Notes

**Field Naming:** snake_case (lowercase with underscores)  
**Timestamps:** Epoch milliseconds  
**Null Values:** Use `null`, not empty strings  
**Arrays:** Can be arrays or comma-separated strings

**Severity Values:** informational, low, medium, high, critical  
**Action Values:** DETECTED, BLOCKED, BLOCKED_2, SCANNED, PREVENTED  
**Alert Domain:** DOMAIN_SECURITY, DOMAIN_POSTURE

## Reference File

Complete field definitions with types, descriptions, and examples:
📄 **`xsiam_injectable_fields.json`**

This JSON file contains:
- Full field specifications
- Data types and formats
- Enum values where applicable
- Real examples from XSIAM
- Usage guidelines per scenario

## Next Steps

1. Review `xsiam_injectable_fields.json` for complete field reference
2. Choose appropriate fields for your alert scenario
3. Create custom alert JSON matching XSIAM structure
4. Validate against schema before injection
5. Use injector tool to send to XSIAM

---

**Extracted:** 2025-11-26  
**Source:** Real XSIAM production data
