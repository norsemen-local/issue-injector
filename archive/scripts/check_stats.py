import json

severity_counts = {}
source_counts = {}
detection_types = set()

with open("../nice things/analytics_rules.jsonl", "r") as f:
    for line in f:
        rule = json.loads(line)
        
        # Count severities
        sev = rule.get("severity", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Count sources
        src = rule.get("source", "Unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
        
        # Collect detection types
        for dt in rule.get("detection_types", []):
            detection_types.add(dt)

print("=== Analytics Rules Conversion Summary ===\n")
print(f"Total rules: {sum(severity_counts.values())}\n")

print("Severity breakdown:")
for sev in ["High", "Medium", "Low", "Informational"]:
    count = severity_counts.get(sev, 0)
    print(f"  {sev:15s}: {count:3d}")

print(f"\nUnique detection types: {len(detection_types)}")
print(f"\nSources:")
for src, count in sorted(source_counts.items()):
    print(f"  {src}: {count}")
