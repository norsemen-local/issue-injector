#!/usr/bin/env python3
"""
Cleanup script to remove unsupported fields from alert JSON files.
Based on new tenant schema validation errors.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
import shutil
from datetime import datetime

# Fields that are not supported by the new tenant
UNSUPPORTED_FIELDS = [
    'threat_actor',
    'malware_family',
    'malware_name',
    'protocol',
    'detection_timestamp',
    'detection_source'
]

# Type conversions needed
TYPE_FIXES = {
    # Fields that should be integers (not strings)
    'int_fields': [
        'action_local_port',
        'action_remote_port',
        'local_port',
        'remote_port',
        'os_actor_process_os_pid',
        'dst_action_external_port'
    ],
    # Fields that should be strings (not integers or arrays)
    'string_fields': [
        'filesize',
        'file_size'
    ],
    # Fields that should be arrays (not strings)
    'array_fields': [
        'prisma_region',
        'action_file_path',
        'file_path'
    ],
    # Fields that should NOT be arrays (should be strings)
    'not_array_fields': [
        'filehash',
        'file_hash',
        'action_file_hash'
    ]
}

def backup_directory(source_dir: Path, backup_dir: Path):
    """Create a backup of the original files"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = backup_dir / f"backup_{timestamp}"
    backup_path.mkdir(parents=True, exist_ok=True)
    
    print(f"📦 Creating backup in: {backup_path}")
    
    for json_file in source_dir.rglob('*.json'):
        relative_path = json_file.relative_to(source_dir)
        backup_file = backup_path / relative_path
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(json_file, backup_file)
    
    print(f"✅ Backup created with {len(list(backup_path.rglob('*.json')))} files\n")
    return backup_path

def fix_mitre_technique(value: str) -> str:
    """Fix MITRE ATT&CK technique format - only keep first technique if multiple"""
    if not value:
        return value
    
    # If multiple techniques separated by comma, keep only first
    if ',' in value:
        value = value.split(',')[0].strip()
    
    # Ensure it starts with T-code
    if not value.startswith('T'):
        # Try to extract T-code if present
        import re
        match = re.search(r'(T\d+(?:\.\d+)?)', value)
        if match:
            value = match.group(1)
        else:
            return ""  # Invalid, remove it
    
    return value

def apply_type_fixes(alert: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    """Apply type conversions to fields"""
    changes = []
    
    # Convert to integers
    for field in TYPE_FIXES['int_fields']:
        if field in alert:
            if isinstance(alert[field], str):
                try:
                    alert[field] = int(alert[field])
                    changes.append(f"  - {field}: string → int")
                except ValueError:
                    changes.append(f"  - {field}: removed (invalid int value)")
                    del alert[field]
    
    # Convert to strings
    for field in TYPE_FIXES['string_fields']:
        if field in alert:
            if not isinstance(alert[field], str):
                alert[field] = str(alert[field])
                changes.append(f"  - {field}: {type(alert[field]).__name__} → string")
    
    # Convert to arrays
    for field in TYPE_FIXES['array_fields']:
        if field in alert:
            if not isinstance(alert[field], list):
                alert[field] = [alert[field]]
                changes.append(f"  - {field}: string → array")
    
    # Convert from arrays to strings
    for field in TYPE_FIXES['not_array_fields']:
        if field in alert:
            if isinstance(alert[field], list):
                if len(alert[field]) > 0:
                    alert[field] = alert[field][0]
                    changes.append(f"  - {field}: array → string (first element)")
                else:
                    del alert[field]
                    changes.append(f"  - {field}: removed (empty array)")
    
    return alert, changes

def clean_alert(alert: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    """Remove unsupported fields and fix types in a single alert"""
    removed = []
    
    # Remove unsupported fields
    for field in UNSUPPORTED_FIELDS:
        if field in alert:
            removed.append(f"  - Removed: {field}")
            del alert[field]
    
    # Fix MITRE technique
    if 'mitre_att&ck_technique' in alert:
        original = alert['mitre_att&ck_technique']
        fixed = fix_mitre_technique(original)
        if fixed != original:
            if fixed:
                alert['mitre_att&ck_technique'] = fixed
                removed.append(f"  - Fixed MITRE: '{original}' → '{fixed}'")
            else:
                del alert['mitre_att&ck_technique']
                removed.append(f"  - Removed invalid MITRE: '{original}'")
    
    # Apply type fixes
    alert, type_changes = apply_type_fixes(alert)
    removed.extend(type_changes)
    
    return alert, removed

def process_json_file(file_path: Path) -> tuple[bool, List[str]]:
    """Process a single JSON file"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Handle both single alert and array of alerts
        if isinstance(data, list):
            all_changes = []
            for i, alert in enumerate(data):
                alert, changes = clean_alert(alert)
                if changes:
                    all_changes.extend([f"Alert {i+1}:"] + changes)
                data[i] = alert
        else:
            data, all_changes = clean_alert(data)
        
        # Write back to file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return True, all_changes
    
    except Exception as e:
        return False, [f"Error: {str(e)}"]

def main():
    """Main cleanup function"""
    print("🧹 Alert JSON Cleanup Script")
    print("=" * 60)
    print("Removing unsupported fields for new tenant:\n")
    print("Fields to remove:")
    for field in UNSUPPORTED_FIELDS:
        print(f"  ❌ {field}")
    print("\nType fixes:")
    print(f"  🔢 Convert to int: {', '.join(TYPE_FIXES['int_fields'][:3])}...")
    print(f"  📝 Convert to string: {', '.join(TYPE_FIXES['string_fields'])}")
    print(f"  📋 Convert to array: {', '.join(TYPE_FIXES['array_fields'][:2])}...")
    print(f"  🔤 Convert from array: {', '.join(TYPE_FIXES['not_array_fields'])}")
    print("\n" + "=" * 60 + "\n")
    
    # Setup paths
    base_dir = Path.cwd()
    issues_dir = base_dir / 'issues_jsons'
    backup_dir = base_dir / 'backups'
    
    if not issues_dir.exists():
        print(f"❌ Error: {issues_dir} not found")
        return
    
    # Create backup
    backup_path = backup_directory(issues_dir, backup_dir)
    
    # Process all JSON files
    print("🔄 Processing JSON files...\n")
    
    json_files = list(issues_dir.rglob('*.json'))
    total_files = len(json_files)
    processed = 0
    modified = 0
    errors = 0
    
    for json_file in json_files:
        relative_path = json_file.relative_to(issues_dir)
        success, changes = process_json_file(json_file)
        
        processed += 1
        
        if success:
            if changes:
                modified += 1
                print(f"✅ {relative_path}")
                for change in changes:
                    print(change)
                print()
        else:
            errors += 1
            print(f"❌ {relative_path}")
            for change in changes:
                print(change)
            print()
    
    # Summary
    print("=" * 60)
    print("📊 CLEANUP SUMMARY")
    print("=" * 60)
    print(f"Total files processed: {processed}")
    print(f"Files modified: {modified}")
    print(f"Files unchanged: {processed - modified - errors}")
    print(f"Errors: {errors}")
    print(f"\n📦 Backup location: {backup_path}")
    print("\n✅ Cleanup complete! Ready for re-injection.")

if __name__ == '__main__':
    main()
