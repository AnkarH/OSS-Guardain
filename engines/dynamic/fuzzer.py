#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Fuzzer
Generates random command line arguments and tests target script execution.
"""

import random
import string
from typing import List, Dict, Any
from engines.dynamic.sandbox import run_in_sandbox, run_direct


def generate_random_string(min_length: int = 1, max_length: int = 100) -> str:
    """
    Generate a random string for fuzzing.
    
    Args:
        min_length: Minimum string length
        max_length: Maximum string length
        
    Returns:
        str: Random string containing letters, digits, and special characters
    """
    length = random.randint(min_length, max_length)
    
    # Character sets
    letters = string.ascii_letters
    digits = string.digits
    special_chars = ';|&><$`"\'\\'
    
    # Mix of all character types
    all_chars = letters + digits + special_chars
    
    # Generate random string
    result = ''.join(random.choice(all_chars) for _ in range(length))
    
    return result


def generate_fuzz_cases(num_tests: int = 3) -> List[str]:
    """
    Generate multiple fuzz test cases.
    
    Args:
        num_tests: Number of test cases to generate
        
    Returns:
        List[str]: List of random test strings
    """
    test_cases = []
    
    # Generate various types of test cases
    for i in range(num_tests):
        # Random length test case
        test_cases.append(generate_random_string(1, 50))
    
    # Add some specific injection patterns
    injection_patterns = [
        '; ls',
        '| cat /etc/passwd',
        '& whoami',
        '`id`',
        '$(whoami)',
        '"> /tmp/test',
        "' || 1=1 --",
        '; rm -rf /',
        '| nc -l 1234',
    ]
    
    # Add injection patterns (up to num_tests)
    for pattern in injection_patterns[:min(num_tests, len(injection_patterns))]:
        test_cases.append(pattern)
    
    return test_cases[:num_tests * 2]  # Return up to 2x num_tests cases


def fuzz_execution(
    file_path: str,
    num_tests: int = 3,
    timeout: int = 10,
    use_sandbox: bool = True,
    log_mode: str = "queue"
) -> List[Dict[str, Any]]:
    """
    Fuzz test a Python script by running it with random arguments.
    
    Args:
        file_path: Path to target Python file
        num_tests: Number of fuzz test cases to run
        timeout: Timeout per test in seconds
        use_sandbox: Whether to run with hooks/sandbox
        log_mode: "queue" for in-memory logs, "file" for file logs
        
    Returns:
        List[Dict]: List of test results, each containing:
            - 'test_input': str - Input that was tested
            - 'return_code': int - Process return code
            - 'crashed': bool - Whether the test caused a crash
            - 'stdout': str - Standard output
            - 'stderr': str - Standard error
            - 'execution_time': float - Execution time
            - 'log_file': str - Path to log file
            - 'network_activities': List[Dict] - Network activities detected
    """
    test_cases = generate_fuzz_cases(num_tests)
    results = []
    
    for test_input in test_cases:
        try:
            # Run with or without sandbox
            if use_sandbox:
                result = run_in_sandbox(
                    file_path=file_path,
                    args=[test_input],
                    timeout=timeout,
                    log_mode=log_mode
                )
            else:
                result = run_direct(
                    file_path=file_path,
                    args=[test_input],
                    timeout=timeout
                )
            
            # Determine if crashed
            crashed = (
                (result['return_code'] != 0 and not result.get('timed_out')) or
                'Traceback' in result['stderr'] or
                'Error' in result['stderr']
            )

            # Extract line numbers from stderr (if any)
            line_numbers = []
            if result.get('stderr'):
                import re
                for match in re.finditer(r'File \"[^\"]+\", line (\\d+)', result['stderr']):
                    try:
                        line_numbers.append(int(match.group(1)))
                    except ValueError:
                        continue
            
            # Analyze network activities from log (sandbox mode only)
            network_activities = []
            if use_sandbox:
                from engines.dynamic.network_monitor import analyze_network_activity
                log_entries = result.get('log_entries', [])
                if log_entries:
                    network_activities = analyze_network_activity(log_entries)
                elif result.get('log_file'):
                    network_activities = analyze_network_activity(result['log_file'])
            
            results.append({
                'test_input': test_input,
                'return_code': result['return_code'],
                'crashed': crashed,
                'stdout': result['stdout'],
                'stderr': result['stderr'],
                'execution_time': result['execution_time'],
                'log_file': result.get('log_file', ''),
                'network_activities': network_activities,
                'timed_out': result.get('timed_out', False),
                'line_numbers': line_numbers
            })
        
        except Exception as e:
            # If execution fails completely, record as crash
            results.append({
                'test_input': test_input,
                'return_code': -1,
                'crashed': True,
                'stdout': '',
                'stderr': str(e),
                'execution_time': 0.0,
                'log_file': '',
                'network_activities': [],
                'timed_out': False,
                'error': str(e)
            })
    
    return results
