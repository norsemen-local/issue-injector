#!/usr/bin/env python3
"""
Fix Field Names Script
======================
Renames underscore-based field names to camelCase format for XSIAM API compatibility.

Breaking Change (Jan 2026): XSIAM API changed from snake_case to camelCase field names.

Usage:
    python3 fix_field_names.py                    # Dry run - show changes
    python3 fix_field_names.py --apply           # Apply changes
    python3 fix_field_names.py --dir issues_jsons/sherlock_investigation --apply
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Field name mapping: old (with underscores) -> new (no underscores)
FIELD_MAPPINGS = {
    # Email fields
    "email_body": "emailbody",
    "email_message_id": "emailmessageid",
    
    # Threat intelligence fields
    "threat_actor": "threatactor",
    "malware_family": "malwarefamily",
    "malware_name": "malwarename",
    
    # Detection fields
    "detection_timestamp": "detectiontimestamp",
    "detection_source": "detectionsource",
    
    # File fields
    "file_size": "filesize",

    # Process fields
    "parent_process_id": "parentprocessid",
    
    # Add more mappings as discovered
}


def rename_fields_in_dict(data: dict) -> Tuple[dict, List[str]]:
    """
    Recursively rename fields in a dictionary.
    
    Returns:
        Tuple of (modified_dict, list_of_changes)
    """
    changes = []
    new_data = {}
    
    for key, value in data.items():
        # Check if this key needs to be renamed
        if key in FIELD_MAPPINGS:
            new_key = FIELD_MAPPINGS[key]
            new_data[new_key] = value
            changes.append(f"  - Renamed: {key} → {new_key}")
        else:
            new_data[key] = value
    
    return new_data, changes


def process_json_file(file_path: Path, apply: bool = False) -> Tuple[bool, List[str]]:
    """
    Process a single JSON file to rename fields.
    
    Returns:
        Tuple of (has_changes, list_of_changes)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both single alert and array of alerts
        if isinstance(data, list):
            all_changes = []
            new_data = []
            for i, alert in enumerate(data):
                modified_alert, changes = rename_fields_in_dict(alert)
                new_data.append(modified_alert)
                if changes:
                    all_changes.append(f"Alert {i+1}:")
                    all_changes.extend(changes)
        else:
            new_data, all_changes = rename_fields_in_dict(data)
        
        if all_changes and apply:
            # Write back to file with proper formatting
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(new_data, f, indent=2, ensure_ascii=False)
            return True, all_changes
        
        return bool(all_changes), all_changes
    
    except json.JSONDecodeError as e:
        return False, [f"ERROR: Invalid JSON - {e}"]
    except Exception as e:
        return False, [f"ERROR: {e}"]


def find_json_files(directory: Path) -> List[Path]:
    """Find all JSON files in directory and subdirectories."""
    return list(directory.rglob("*.json"))


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Fix field names in XSIAM alert JSON files (remove underscores)"
    )
    parser.add_argument(
        "--dir",
        type=str,
        default="issues_jsons",
        help="Directory containing JSON files (default: issues_jsons)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default is dry-run mode)"
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Process a single file instead of directory"
    )
    
    args = parser.parse_args()
    
    # Determine files to process
    if args.file:
        json_files = [Path(args.file)]
    else:
        directory = Path(args.dir)
        if not directory.exists():
            print(f"❌ Error: Directory '{args.dir}' does not exist")
            sys.exit(1)
        json_files = find_json_files(directory)
    
    if not json_files:
        print(f"❌ No JSON files found in {args.dir}")
        sys.exit(1)
    
    # Print header
    mode = "APPLYING CHANGES" if args.apply else "DRY RUN (no changes will be made)"
    print("=" * 80)
    print(f"XSIAM Field Name Fixer - {mode}")
    print("=" * 80)
    print(f"Files to process: {len(json_files)}")
    print()
    
    # Process files
    files_modified = 0
    files_with_changes = 0
    total_changes = 0
    
    for json_file in sorted(json_files):
        has_changes, changes = process_json_file(json_file, apply=args.apply)
        
        if has_changes:
            files_with_changes += 1
            total_changes += len([c for c in changes if c.startswith("  -")])
            
            print(f"📄 {json_file}")
            for change in changes:
                print(change)
            print()
            
            if args.apply:
                files_modified += 1
    
    # Print summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total files scanned: {len(json_files)}")
    print(f"Files with changes: {files_with_changes}")
    print(f"Total field renames: {total_changes}")
    
    if args.apply:
        print(f"✅ Files modified: {files_modified}")
    else:
        print()
        print("⚠️  DRY RUN MODE - No files were modified")
        print("   Run with --apply to make changes")
    
    print("=" * 80)


if __name__ == "__main__":
    main()
