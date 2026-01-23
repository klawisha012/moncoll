#!/usr/bin/env python3

import subprocess
import sys
import os
import pytest
from collections import defaultdict

def get_category(test_file):
    """Determine the category of a test file based on its name."""
    if 'exclusion' in test_file:
        return 'exclusion'
    elif 'initialization' in test_file:
        return 'initialization'
    elif 'exceptions' in test_file:
        return 'exceptions'
    elif any(x in test_file for x in ['method', 'scanner', 'protocol', 'multipart']):
        return 'enforcement'
    elif any(x in test_file for x in ['lfi', 'rfi', 'rce', 'php', 'generic', 'xss', 'sqli', 'session_fixation', 'java']):
        return 'application_attacks'
    elif 'blocking' in test_file:
        return 'blocking'
    elif any(x in test_file for x in ['leakages', 'web_shells']):
        return 'data_leakages'
    elif 'correlation' in test_file:
        return 'correlation'
    else:
        return 'advanced'

def run_test(test_file):
    """Run a single test file using pytest and return its output and success status."""
    try:
        # Run pytest on the test file
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', test_file, '-v', '--tb=short'],
            capture_output=True,
            text=True,
            cwd='tests'
        )
        return result.stdout, result.stderr, result.returncode == 0
    except Exception as e:
        return "", str(e), False

def main():
    # List of test files to run in logical order
    test_files = [
        'test_exclusion_900.py',
        'test_initialization_901.py',
        'test_exceptions_905.py',
        'test_method_911.py',
        'test_scanner_913.py',
        'test_protocol_enforcement_920.py',
        'test_protocol_attack_921.py',
        'test_multipart_922.py',
        'test_lfi_930.py',
        'test_rfi_931.py',
        'test_rce_932.py',
        'test_php_933.py',
        'test_generic_934.py',
        'test_xss_941.py',
        'test_sqli_942.py',
        'test_session_fixation_943.py',
        'test_java_944.py',
        'test_blocking_949.py',
        'test_data_leakages_950.py',
        'test_sql_leakages_951.py',
        'test_java_leakages_952.py',
        'test_php_leakages_953.py',
        'test_iis_leakages_954.py',
        'test_web_shells_955.py',
        'test_blocking_response_959.py',
        'test_correlation_980.py',
        'test_exclusion_after_999.py',
        'test_modsecurity_advanced.py'
    ]

    results = []
    total_passed = 0
    total_failed = 0
    counters = defaultdict(lambda: {'passed': 0, 'failed': 0})

    for test_file in test_files:
        category = get_category(test_file)
        print(f"Running {test_file} (category: {category})...")
        stdout, stderr, success = run_test(test_file)
        if success:
            print(f"OK {test_file} passed")
            total_passed += 1
            counters[category]['passed'] += 1
        else:
            print(f"FAIL {test_file} failed")
            total_failed += 1
            counters[category]['failed'] += 1

        # Print the output if any
        if stdout:
            print(f"Output from {test_file}:\n{stdout}")
        if stderr:
            print(f"Errors from {test_file}:\n{stderr}")

        results.append((test_file, success, stdout, stderr))

    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    print(f"Total tests: {len(test_files)}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")

    print("\nPer category summary:")
    for category in sorted(counters.keys()):
        counts = counters[category]
        print(f"  {category}: {counts['passed']} passed, {counts['failed']} failed")

    if total_failed > 0:
        print("\nFailed tests:")
        for test_file, success, _, _ in results:
            if not success:
                print(f"  - {test_file}")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()