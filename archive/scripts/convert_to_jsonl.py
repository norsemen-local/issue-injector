#!/usr/bin/env python3
"""
Convert XDR Analytics Rules from TSV to JSONL format.
"""

import json
import re
from datetime import datetime
from pathlib import Path


def parse_date(date_str):
    """Convert date string to ISO 8601 format."""
    try:
        # Parse format like "Nov 18th 2025 15:00:43"
        date_str = re.sub(r'(\d+)(st|nd|rd|th)', r'\1', date_str)
        dt = datetime.strptime(date_str, '%b %d %Y %H:%M:%S')
        return dt.isoformat() + 'Z'
    except:
        return date_str


def parse_mitre_field(field):
    """Parse comma-separated MITRE tactics or techniques."""
    if not field or field.strip() == '':
        return []
    return [item.strip() for item in field.split(',') if item.strip()]


def parse_detection_types(field):
    """Parse detection types field."""
    if not field or field.strip() == '' or field == 'Any':
        return ['Any']
    return [dt.strip() for dt in field.split(',') if dt.strip()]


def convert_line_to_json(line, line_number):
    """Convert a single TSV line to JSON object."""
    parts = line.strip().split('\t')
    
    # Expected format: date, name, severity, [object Object], status, source, detection_type, description, tactics, techniques, count
    if len(parts) < 11:
        print(f"Warning: Line {line_number} has only {len(parts)} fields, skipping")
        return None
    
    try:
        last_modified = parse_date(parts[0])
        name = parts[1]
        severity = parts[2]
        # parts[3] is "[object Object]" - skip it
        status = parts[4]
        source = parts[5]
        detection_types = parse_detection_types(parts[6])
        description = parts[7]
        mitre_tactics = parse_mitre_field(parts[8])
        mitre_techniques = parse_mitre_field(parts[9])
        alert_count = int(parts[10]) if parts[10].isdigit() else 0
        
        return {
            "rule_id": line_number,
            "last_modified": last_modified,
            "name": name,
            "severity": severity,
            "status": status,
            "source": source,
            "detection_types": detection_types,
            "description": description,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "alert_count": alert_count
        }
    except Exception as e:
        print(f"Error parsing line {line_number}: {e}")
        return None


def convert_tsv_to_jsonl(input_file, output_file):
    """Convert TSV file to JSONL format."""
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        print(f"Error: Input file '{input_file}' not found")
        return
    
    print(f"Converting '{input_file}' to JSONL format...")
    
    converted_count = 0
    skipped_count = 0
    
    with open(input_path, 'r', encoding='utf-8') as infile, \
         open(output_path, 'w', encoding='utf-8') as outfile:
        
        for line_number, line in enumerate(infile, 1):
            if not line.strip():
                continue
            
            json_obj = convert_line_to_json(line, line_number)
            
            if json_obj:
                outfile.write(json.dumps(json_obj, ensure_ascii=False) + '\n')
                converted_count += 1
            else:
                skipped_count += 1
    
    print(f"✓ Conversion complete!")
    print(f"  - Converted: {converted_count} rules")
    print(f"  - Skipped: {skipped_count} rules")
    print(f"  - Output: {output_file}")


if __name__ == "__main__":
    input_file = "../nice things/analytics_rules_fixed.txt"
    output_file = "../nice things/analytics_rules.jsonl"
    
    convert_tsv_to_jsonl(input_file, output_file)
