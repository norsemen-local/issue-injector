#!/usr/bin/env python3
"""
Experimental Deep-Dive: Important Failed Fields
Testing 2-3 critical fields that failed with multiple data types and formats.

Focus fields:
1. mitre_tactic_id / mitre_technique_id (MITRE ATT&CK - very important for threat intel)
2. event_type (Core alert field - important for categorization)
3. country (Location - commonly needed)

For each field, we'll try:
- String
- Array of strings
- Integer
- Array of integers
- Different value formats
- Empty values
- Single vs multiple values
"""

import os
import sys
import requests
import json
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv('XSIAM_API_URL')
API_KEY = os.getenv('XSIAM_API_KEY')
API_KEY_ID = os.getenv('XSIAM_API_KEY_ID')

if not all([API_URL, API_KEY, API_KEY_ID]):
    print("❌ Missing required environment variables")
    sys.exit(1)

TIMESTAMP = int(datetime.now().timestamp() * 1000)

def test_field_variant(field_name, field_value, variant_description):
    """Test a specific field with a specific value variant."""
    
    base_alert = {
        "vendor": "TestVendor_Experimental",
        "product": "DeepDive",
        "severity": "medium",
        "category": "TestCategory",
        "alert_id": f"exp-{field_name}-{int(time.time() * 1000)}",
        "timestamp": TIMESTAMP,
        "description": f"Experimental test: {field_name}"
    }
    
    base_alert[field_name] = field_value
    
    payload = {"request_data": {"alert": base_alert}}
    
    headers = {
        "x-xdr-auth-id": API_KEY_ID,
        "Authorization": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{API_URL}/public_api/v1/alerts/create_alert",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        success = response.status_code == 200
        
        if success:
            response_data = response.json()
        else:
            try:
                response_data = response.json()
                error_detail = response_data.get("reply", {})
            except:
                error_detail = response.text
        
        return {
            "field": field_name,
            "variant": variant_description,
            "value": field_value,
            "value_type": type(field_value).__name__,
            "status_code": response.status_code,
            "success": success,
            "response": response_data if success else error_detail
        }
        
    except Exception as e:
        return {
            "field": field_name,
            "variant": variant_description,
            "value": field_value,
            "value_type": type(field_value).__name__,
            "success": False,
            "error": str(e)
        }

def test_all_variants():
    """Test all field variants."""
    
    test_cases = {
        # MITRE Tactic ID - Very important for threat intelligence
        "mitre_tactic_id": [
            ("String - Single ID", "TA0001"),
            ("String - Multiple IDs comma", "TA0001,TA0002"),
            ("String - Multiple IDs space", "TA0001 TA0002"),
            ("Array - Single ID", ["TA0001"]),
            ("Array - Multiple IDs", ["TA0001", "TA0002"]),
            ("String - With description", "TA0001 - Initial Access"),
            ("Array - With descriptions", ["TA0001 - Initial Access", "TA0002 - Execution"]),
            ("Empty string", ""),
            ("Empty array", []),
            ("Just number", "1"),
            ("Array of numbers", [1, 2]),
        ],
        
        # MITRE Technique ID - Very important for threat intelligence
        "mitre_technique_id": [
            ("String - Single ID", "T1078"),
            ("String - Multiple IDs comma", "T1078,T1059"),
            ("String - Sub-technique", "T1078.002"),
            ("Array - Single ID", ["T1078"]),
            ("Array - Multiple IDs", ["T1078", "T1059"]),
            ("Array - Sub-techniques", ["T1078.002", "T1059.001"]),
            ("String - With description", "T1078 - Valid Accounts"),
            ("Array - With descriptions", ["T1078 - Valid Accounts", "T1059 - Command and Scripting"]),
            ("Empty string", ""),
            ("Empty array", []),
        ],
        
        # Event Type - Core field for categorization
        "event_type": [
            ("String - Simple", "PROCESS_START"),
            ("String - Lowercase", "process_start"),
            ("String - Mixed case", "Process_Start"),
            ("Array - Single", ["PROCESS_START"]),
            ("Array - Multiple", ["PROCESS_START", "NETWORK_CONNECTION"]),
            ("Integer", 1),
            ("Array of integers", [1, 2]),
            ("String number", "1"),
            ("Array of string numbers", ["1", "2"]),
            ("Empty string", ""),
            ("Empty array", []),
        ],
        
        # Country - Important location field
        "country": [
            ("String - ISO Code", "US"),
            ("String - Full name", "United States"),
            ("Array - ISO Code", ["US"]),
            ("Array - Full names", ["United States"]),
            ("Array - Multiple ISO", ["US", "CN", "RU"]),
            ("String - Mixed", "United States (US)"),
            ("Empty string", ""),
            ("Empty array", []),
        ],
    }
    
    results = {
        "working": [],
        "failed": []
    }
    
    total_tests = sum(len(variants) for variants in test_cases.values())
    current = 0
    
    print(f"\n{'='*80}")
    print(f"EXPERIMENTAL DEEP-DIVE: Testing {len(test_cases)} Important Failed Fields")
    print(f"Total variant tests: {total_tests}")
    print(f"{'='*80}\n")
    
    for field_name, variants in test_cases.items():
        print(f"\n{'='*80}")
        print(f"FIELD: {field_name}")
        print(f"Testing {len(variants)} variants")
        print(f"{'='*80}\n")
        
        for variant_desc, value in variants:
            current += 1
            print(f"[{current}/{total_tests}] {variant_desc}:", end=" ", flush=True)
            print(f"value={repr(value)[:50]}...", end=" ")
            
            result = test_field_variant(field_name, value, variant_desc)
            
            if result["success"]:
                print("✅ SUCCESS!")
                results["working"].append(result)
            else:
                error_msg = result.get("response", result.get("error", "Unknown"))
                
                # Extract meaningful error message
                if isinstance(error_msg, dict):
                    if "reply" in error_msg:
                        err_code = error_msg["reply"].get("err_code", "")
                        err_msg = error_msg["reply"].get("err_msg", "")
                        err_extra = error_msg["reply"].get("err_extra", "")
                        error_display = f"Code:{err_code} {err_msg}"
                        if err_extra and len(err_extra) < 100:
                            error_display += f" - {err_extra}"
                    else:
                        error_display = str(error_msg)[:100]
                else:
                    error_display = str(error_msg)[:100]
                
                print(f"❌ {error_display}")
                results["failed"].append(result)
            
            time.sleep(0.3)
        
        print()  # Extra newline between fields
    
    return results

def generate_report(results):
    """Generate detailed analysis report."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n\n{'='*80}")
    print(f"EXPERIMENTAL TEST RESULTS - {timestamp}")
    print(f"{'='*80}\n")
    
    working_count = len(results["working"])
    failed_count = len(results["failed"])
    total_count = working_count + failed_count
    
    print(f"Total Variants Tested: {total_count}")
    print(f"✅ Working: {working_count} ({working_count/total_count*100:.1f}%)")
    print(f"❌ Failed: {failed_count} ({failed_count/total_count*100:.1f}%)")
    
    if results["working"]:
        print(f"\n{'='*80}")
        print(f"✅ WORKING VARIANTS ({working_count})")
        print(f"{'='*80}\n")
        
        by_field = {}
        for result in results["working"]:
            field = result["field"]
            if field not in by_field:
                by_field[field] = []
            by_field[field].append(result)
        
        for field, variants in by_field.items():
            print(f"\n{field}: {len(variants)} working variants")
            print("-" * 60)
            for v in variants:
                print(f"  ✓ {v['variant']}")
                print(f"    Type: {v['value_type']}, Value: {repr(v['value'])[:80]}")
    
    if results["failed"]:
        print(f"\n{'='*80}")
        print(f"❌ FAILED VARIANTS - ERROR ANALYSIS")
        print(f"{'='*80}\n")
        
        # Group by field and error pattern
        by_field = {}
        for result in results["failed"]:
            field = result["field"]
            if field not in by_field:
                by_field[field] = []
            by_field[field].append(result)
        
        for field, variants in by_field.items():
            print(f"\n{field}: {len(variants)} failed variants")
            print("-" * 60)
            
            # Analyze error patterns
            error_patterns = {}
            for v in variants:
                resp = v.get("response", {})
                if isinstance(resp, dict) and "reply" in resp:
                    err_msg = resp["reply"].get("err_msg", "Unknown")
                    err_code = resp["reply"].get("err_code", "")
                    pattern = f"{err_code}: {err_msg}"
                else:
                    pattern = str(resp)[:100]
                
                if pattern not in error_patterns:
                    error_patterns[pattern] = []
                error_patterns[pattern].append(v)
            
            print(f"\nError patterns found: {len(error_patterns)}")
            for pattern, variants_list in error_patterns.items():
                print(f"\n  Error: {pattern}")
                print(f"  Affected variants ({len(variants_list)}):")
                for v in variants_list[:3]:  # Show first 3
                    print(f"    - {v['variant']} (type: {v['value_type']})")
                if len(variants_list) > 3:
                    print(f"    ... and {len(variants_list) - 3} more")
    
    # Save detailed results
    output_file = f"experimental_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {output_file}")
    print(f"{'='*80}\n")
    
    # Key insights
    print(f"\n{'='*80}")
    print(f"KEY INSIGHTS")
    print(f"{'='*80}\n")
    
    if results["working"]:
        print("✓ Some variants worked! This means the fields ARE supported.")
        print("✓ Check the working variants above for the correct format.\n")
    else:
        print("✗ NO variants worked for these fields.")
        print("✗ These fields may not be supported via the Public API.")
        print("✗ They might be internal-only or UI-only fields.\n")
    
    # Error analysis
    all_errors = set()
    for r in results["failed"]:
        resp = r.get("response", {})
        if isinstance(resp, dict) and "reply" in resp:
            err_msg = resp["reply"].get("err_msg", "")
            if err_msg:
                all_errors.add(err_msg)
    
    if all_errors:
        print("Common error messages:")
        for err in all_errors:
            print(f"  • {err}")

def main():
    """Main execution."""
    print("\n🔬 Starting Experimental Deep-Dive Test")
    print(f"Testing important failed fields with multiple data types and formats")
    print(f"Goal: Understand WHY they fail and if there's a working format\n")
    
    results = test_all_variants()
    generate_report(results)
    
    print("\n✅ Experimental testing complete!")
    print("\n💡 Use the insights above to understand field requirements")

if __name__ == "__main__":
    main()
