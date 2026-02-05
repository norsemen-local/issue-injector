# XSIAM Custom Alert API - Working Fields Summary
**Last Updated**: 2025-11-26  
**Total Working Fields**: 98 🎉

## 🎯 Critical Discovery: Alert Name Field
✅ **`alert_name`** - The field you were looking for!

## Quick Reference - All 98 Working Fields

### Core Alert Fields (7)
- `alert_name` ⭐ CRITICAL
- `alert_id`
- `alert_domain`
- `alert_type`
- `alert_type_id`
- `description`
- `title`

### Host Identification (5)
- `host_name`
- `host_fqdn`
- `host_mac_address`
- `host_ip` (array of IP integers)
- `host_risk_level`

### User/Identity (4)
- `user_name` (array)
- `user_id`
- `user_risk_level`
- `initiated_by` (array)

### Network - IP/Ports (6)
- `remote_ip` (array of IP integers)
- `local_ip` (array of IP integers)
- `remote_port` (array of integers)
- `local_port` (array of integers)
- `local_ipv6` (array)
- `remote_ipv6` (array)

### Network - DNS/Domains (3)
- `domain`
- `dns_query_name` (array)
- `url` (array)

### File Artifacts (6)
- `file_name` (array)
- `file_path` (array)
- `file_sha256` (array)
- `file_md5` (array)
- `file_macro_sha256` (array)

### CGO (Causality Group Owner) Process (7)
- `cgo_cmd` (array)
- `cgo_md5` (array)
- `cgo_name` (array)
- `cgo_path` (array)
- `cgo_sha256` (array)
- `cgo_signer` (array)

### Initiator Process (8)
- `initiator_cmd` (array)
- `initiator_md5` (array)
- `initiator_path` (array)
- `initiator_pid` (array of integers)
- `initiator_sha256` (array)
- `initiator_signer` (array)
- `initiator_tid` (array of integers)

### OS Parent Process (7)
- `os_parent_cmd` (array)
- `os_parent_name` (array)
- `os_parent_pid` (array of integers)
- `os_parent_sha256` (array)
- `os_parent_signer` (array)
- `os_parent_user_name` (array)
- `os_actor_process_image_md5` (array)

### Target Process (3)
- `target_process_cmd` (array)
- `target_process_name` (array)
- `target_process_sha256` (array)

### Firewall (5)
- `fw_name` (array)
- `fw_rule_name` (array)
- `fw_rule_id` (array)
- `fw_serial_number` (array)
- `ngfw_vsys_name` (array)

### Cloud/Container (6)
- `cloud_project` (array)
- `cloud_provider` (array)
- `cloud_service_name`
- `cloud_provider_account_id`
- `cluster_name` (array)
- `namespace` (array)

### Container (2)
- `container_name` (array)
- `image_name` (array)

### Email (3)
- `email_subject` (array)
- `email_sender` (array)
- `email_recipient` (array)

### Network Zones (2)
- `destination_zone_name` (array)
- `source_zone_name` (array)

### Detection/Source (2)
- `log_source`
- `module` (array)

### Asset/Device (2)
- `asset_id`
- `device_name`

### Category/Classification (4)
- `category`
- `sub_category`
- `action`
- `is_phishing` (array)

### Threat Names (4)
- `issue_name`
- `rule_name`
- `original_alert_name`
- `threat_name`
- `malware_name`

### Risk/Score (2)
- `risk_score`
- `risk_rating`

### Registry (2)
- `registry_data` (array)
- `registry_full_key` (array)

### Resolution (2)
- `resolution_status`
- `resolution_comment`

### Timestamps (3)
- `occurred`
- `start_time`
- `event_id`

### Status/Flags (3)
- `excluded` (boolean)
- `starred` (boolean)

### Featured Entities (2)
- `contains_featured_host` (array)
- `contains_featured_user` (array)

### Misc (6)
- `tags`
- `original_tags`
- `external_id`
- `malicious_urls` (array)
- `user_agent` (array)
- `agent_os_sub_type`

---

## 🔑 Key Patterns Discovered

1. **UI Field Names Work!** - Transform UI field names: spaces/hyphens → underscores, lowercase
2. **Underscore Notation Required** - Most fields need underscores (e.g., `host_name` not `hostname`)
3. **Process Fields** - CGO, Initiator, OS Parent, Target all work with proper naming
4. **Array Fields** - Most Multi Select UI fields require arrays
5. **IP Addresses** - Must be integers, not strings

## 📈 Testing Journey
- Initial: 18 fields
- Complete test: +10 = 28 fields
- Array format: +5 = 33 fields
- UI fields batch 1: +45 = 78 fields
- UI fields batch 2: +25 = **98 fields** 🚀

## Next Steps
Continue testing the remaining ~900 UI fields to discover even more!
