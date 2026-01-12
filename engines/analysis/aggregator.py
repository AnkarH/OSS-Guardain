#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Result Aggregator
Merges static and dynamic analysis results into a unified structure.
"""

from typing import Dict, List, Any


def aggregate_results(
    static_results: Dict[str, Any],
    dynamic_results: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Aggregate static and dynamic analysis results.
    
    Args:
        static_results: Dictionary containing static analysis results:
            - 'pattern_matches': List of pattern match results
            - 'taint_flows': List of taint flow results
            - 'cfg_structures': List of CFG structures
            - 'syntax_valid': bool - Syntax check result
            - 'symbols': Dict - Symbol table
        dynamic_results: Dictionary containing dynamic analysis results:
            - 'syscalls': List of system call logs
            - 'network_activities': List of network activities
            - 'fuzz_results': List of fuzz test results
            - 'execution_log': str - Path to execution log file
    
    Returns:
        dict: Aggregated results with summary statistics
    """
    if dynamic_results is None:
        dynamic_results = {
            'syscalls': [],
            'network_activities': [],
            'fuzz_results': [],
            'execution_log': ''
        }
    
    # Extract results
    pattern_matches = static_results.get('pattern_matches', [])
    taint_flows = static_results.get('taint_flows', [])
    cfg_structures = static_results.get('cfg_structures', [])
    syntax_valid = static_results.get('syntax_valid', True)
    symbols = static_results.get('symbols', {})
    
    syscalls = dynamic_results.get('syscalls', [])
    network_activities = dynamic_results.get('network_activities', [])
    fuzz_results = dynamic_results.get('fuzz_results', [])
    execution_log = dynamic_results.get('execution_log', '')
    
    # Count threats by severity
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    # Count from pattern matches
    for match in pattern_matches:
        severity = match.get('severity', 'medium').lower()
        if severity == 'critical':
            critical_count += 1
        elif severity == 'high':
            high_count += 1
        elif severity == 'medium':
            medium_count += 1
        else:
            low_count += 1
    
    # Count from taint flows (usually critical)
    critical_count += len(taint_flows)
    
    # Count from dynamic syscalls (usually critical or high)
    for syscall in syscalls:
        if 'os.system' in str(syscall) or 'subprocess' in str(syscall):
            critical_count += 1
        elif 'socket' in str(syscall):
            medium_count += 1
    
    # Count from network activities (usually medium)
    medium_count += len(network_activities)
    
    # Count from fuzz results (crashes are high severity)
    for fuzz_result in fuzz_results:
        if fuzz_result.get('crashed', False):
            high_count += 1
    
    total_threats = critical_count + high_count + medium_count + low_count
    
    return {
        'static': {
            'pattern_matches': pattern_matches,
            'taint_flows': taint_flows,
            'cfg_structures': cfg_structures,
            'syntax_valid': syntax_valid,
            'symbols': symbols
        },
        'dynamic': {
            'syscalls': syscalls,
            'network_activities': network_activities,
            'fuzz_results': fuzz_results,
            'execution_log': execution_log
        },
        'summary': {
            'total_threats': total_threats,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count
        }
    }
