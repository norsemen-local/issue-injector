#!/usr/bin/env python3
"""
Fix multi-line descriptions in analytics_rules.txt by merging continuation lines.
Lines that don't start with a date pattern should be appended to the previous line.
"""

import re
from pathlib import Path


def starts_with_date(line):
    """Check if a line starts with a date pattern like 'Nov 18th 2025' or 'Sep 2nd 2025'."""
    # Pattern: Month name followed by day with ordinal, then year
    date_pattern = r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}(st|nd|rd|th)\s+\d{4}'
    return bool(re.match(date_pattern, line.strip()))


def fix_multiline_file(input_file, output_file):
    """Merge continuation lines into the previous line's description."""
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        print(f"Error: Input file '{input_file}' not found")
        return
    
    print(f"Fixing multi-line descriptions in '{input_file}'...")
    
    lines = []
    current_line = None
    merged_count = 0
    
    with open(input_path, 'r', encoding='utf-8') as infile:
        for line_num, line in enumerate(infile, 1):
            # Skip empty lines
            if not line.strip():
                continue
            
            # Check if this line starts with a date (new record)
            if starts_with_date(line):
                # Save the previous complete line
                if current_line:
                    lines.append(current_line)
                # Start a new line
                current_line = line.rstrip('\n')
            else:
                # This is a continuation line
                if current_line:
                    # Append to current line with a space separator
                    current_line += ' ' + line.strip()
                    merged_count += 1
                    print(f"  Merged line {line_num}: {line.strip()[:60]}...")
                else:
                    # First line doesn't start with date - this is unexpected
                    print(f"  Warning: Line {line_num} doesn't start with date and no previous line exists")
                    current_line = line.rstrip('\n')
        
        # Don't forget the last line
        if current_line:
            lines.append(current_line)
    
    # Write fixed lines to output
    with open(output_path, 'w', encoding='utf-8') as outfile:
        for line in lines:
            outfile.write(line + '\n')
    
    print(f"\n✓ Fix complete!")
    print(f"  - Total lines: {len(lines)}")
    print(f"  - Merged continuation lines: {merged_count}")
    print(f"  - Output: {output_file}")


if __name__ == "__main__":
    input_file = "../nice things/analytics_rules.txt"
    output_file = "../nice things/analytics_rules_fixed.txt"
    
    fix_multiline_file(input_file, output_file)
