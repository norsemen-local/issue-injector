# XSIAM Alert Field Discovery - Statistics

## 🎯 Final Count: 159 Working Fields

### Discovery Journey:
1. **Initial Testing**: 18 fields → Started with basics
2. **Complete Test**: +10 = 28 fields → Tested underscore fields  
3. **Array Format**: +5 = 33 fields → Fixed array types
4. **UI Batch 1**: +45 = 78 fields → 🔥 UI field breakthrough!
5. **UI Batch 2**: +25 = 103 fields → Found `alert_name`! ⭐
6. **Batch 3 (Core)**: +35 = 138 fields → Cloud, app, network fields
7. **Batch 4 (Retry)**: +26 = **159 fields** → Fixed data types, more fields

### Success Rate:
- **Total fields tested**: ~230
- **Working fields**: 159
- **Success rate**: ~69%

### Key Patterns Discovered:
1. ✅ **UI field transformation works!** (spaces/hyphens → underscores, lowercase)
2. ✅ **Data type matters** - retry failed fields with different types
3. ✅ **Underscore notation required** for most fields
4. ✅ **IP addresses must be integers** (not strings)
5. ✅ **Multi Select = arrays, Short Text = strings**
6. ✅ **Enum fields need exact values** (e.g., AGENT_OS_WINDOWS)
7. ❌ **XDM prefix fields don't work** via this API
8. ❌ **Many internal fields aren't supported**

### Field Categories with Most Success:
- **Process fields**: CGO, Initiator, OS Parent, Target (30+ fields)
- **Network fields**: IPs, ports, zones, firewall (15+ fields)
- **Cloud/Container**: Cloud resources, containers, namespaces (15+ fields)
- **Email fields**: Subject, sender, recipient, body (7+ fields)
- **File artifacts**: Names, paths, hashes (7+ fields)
- **Threat intel**: Names, actors, families, campaigns (10+ fields)

### Remaining Opportunities:
- ~850 untested fields from UI list
- Retry more failed fields with different data types
- Test combinations of fields
- Test edge cases and special values
