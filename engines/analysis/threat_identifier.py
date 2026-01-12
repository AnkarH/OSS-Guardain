#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Threat Identifier
Maps detected patterns to threat names and categories.
"""

from typing import List, Dict, Any


def identify_threats(aggregated_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Identify threats from aggregated analysis results.
    
    Args:
        aggregated_results: Aggregated results from aggregator.aggregate_results()
        
    Returns:
        List[Dict]: List of identified threats, each containing:
            - 'threat_type': str - Threat category
            - 'severity': str - Severity level
            - 'description': str - Threat description
            - 'evidence': List[Dict] - Supporting evidence
            - 'line_numbers': List[int] - Relevant line numbers
    """
    threats = []
    static = aggregated_results.get('static', {})
    dynamic = aggregated_results.get('dynamic', {})
    
    pattern_matches = static.get('pattern_matches', [])
    taint_flows = static.get('taint_flows', [])
    network_activities = dynamic.get('network_activities', [])
    syscalls = dynamic.get('syscalls', [])
    fuzz_results = dynamic.get('fuzz_results', [])
    
    # 1. Identify RCE (Remote Code Execution) threats
    rce_evidence = []
    rce_lines = []
    
    # From pattern matches
    for match in pattern_matches:
        rule_id = match.get('rule_id', '')
        if 'rce_' in rule_id or 'os.system' in match.get('matched_text', ''):
            rce_evidence.append(match)
            rce_lines.append(match.get('line', 0))
    
    # From taint flows (command injection)
    for flow in taint_flows:
        if flow.get('sink', '').startswith('os.system') or 'subprocess' in flow.get('sink', ''):
            rce_evidence.append(flow)
            rce_lines.append(flow.get('sink_line', 0))
    
    # From dynamic syscalls
    for syscall in syscalls:
        if isinstance(syscall, dict):
            if 'os.system' in str(syscall) or 'subprocess' in str(syscall):
                rce_evidence.append(syscall)
        elif isinstance(syscall, str):
            if 'os.system' in syscall or 'subprocess' in syscall:
                rce_evidence.append({'log_entry': syscall})
    
    if rce_evidence:
        threats.append({
            'threat_type': 'RCE',
            'severity': 'critical',
            'description': 'Remote code execution detected via os.system/subprocess calls',
            'evidence': rce_evidence,
            'line_numbers': sorted(set([l for l in rce_lines if l > 0]))
        })
    
    # 2. Identify Command Injection threats
    cmd_injection_evidence = []
    cmd_injection_lines = []
    
    for flow in taint_flows:
        if flow.get('source', '').startswith('sys.argv') and flow.get('sink', '').startswith('os.system'):
            cmd_injection_evidence.append(flow)
            cmd_injection_lines.append(flow.get('sink_line', 0))
    
    if cmd_injection_evidence:
        threats.append({
            'threat_type': 'Command Injection',
            'severity': 'critical',
            'description': 'Command injection detected: user input (sys.argv) flows to os.system without sanitization',
            'evidence': cmd_injection_evidence,
            'line_numbers': sorted(set([l for l in cmd_injection_lines if l > 0]))
        })
    
    # 3. Identify WebShell threats
    webshell_evidence = []
    webshell_lines = []
    
    for match in pattern_matches:
        rule_id = match.get('rule_id', '')
        if 'webshell_' in rule_id:
            webshell_evidence.append(match)
            webshell_lines.append(match.get('line', 0))
    
    if webshell_evidence:
        threats.append({
            'threat_type': 'WebShell',
            'severity': 'critical',
            'description': 'WebShell detected: usage of eval/exec/__import__/compile functions',
            'evidence': webshell_evidence,
            'line_numbers': sorted(set([l for l in webshell_lines if l > 0]))
        })
    
    # 4. Identify Backdoor threats
    backdoor_evidence = []
    backdoor_lines = []
    
    for match in pattern_matches:
        rule_id = match.get('rule_id', '')
        if 'backdoor_' in rule_id:
            backdoor_evidence.append(match)
            backdoor_lines.append(match.get('line', 0))
    
    if backdoor_evidence:
        threats.append({
            'threat_type': 'Backdoor',
            'severity': 'high',
            'description': 'Backdoor detected: hardcoded passwords, secret keys, or obfuscated code',
            'evidence': backdoor_evidence,
            'line_numbers': sorted(set([l for l in backdoor_lines if l > 0]))
        })
    
    # 5. Identify SQL Injection threats
    sql_injection_evidence = []
    sql_injection_lines = []
    
    for match in pattern_matches:
        rule_id = match.get('rule_id', '')
        if 'sql_injection' in rule_id:
            sql_injection_evidence.append(match)
            sql_injection_lines.append(match.get('line', 0))
    
    if sql_injection_evidence:
        threats.append({
            'threat_type': 'SQL Injection',
            'severity': 'high',
            'description': 'SQL injection vulnerability detected: unsafe string concatenation in SQL queries',
            'evidence': sql_injection_evidence,
            'line_numbers': sorted(set([l for l in sql_injection_lines if l > 0]))
        })
    
    # 6. Identify Network Exfiltration threats
    network_evidence = []
    network_lines = []
    
    for activity in network_activities:
        network_evidence.append(activity)
        # Try to extract line number from log entry
        if isinstance(activity, dict) and 'line' in activity:
            line_str = activity.get('line', '')
            # Try to extract line number from stack trace in log
            import re
            line_match = re.search(r':(\d+):', line_str)
            if line_match:
                network_lines.append(int(line_match.group(1)))
    
    if network_evidence:
        threats.append({
            'threat_type': 'Network Exfiltration',
            'severity': 'medium',
            'description': 'Network connection activity detected: potential data exfiltration',
            'evidence': network_evidence,
            'line_numbers': sorted(set([l for l in network_lines if l > 0]))
        })
    
    # 7. Identify File Operation risks
    file_risk_evidence = []
    file_risk_lines = []
    
    for match in pattern_matches:
        rule_id = match.get('rule_id', '')
        if 'file_' in rule_id:
            file_risk_evidence.append(match)
            file_risk_lines.append(match.get('line', 0))
    
    if file_risk_evidence:
        threats.append({
            'threat_type': 'File Operation Risk',
            'severity': 'medium',
            'description': 'Risky file operations detected: path traversal or sensitive file access',
            'evidence': file_risk_evidence,
            'line_numbers': sorted(set([l for l in file_risk_lines if l > 0]))
        })
    
    # 8. Identify Fuzzing crashes
    crash_evidence = []
    for fuzz_result in fuzz_results:
        if fuzz_result.get('crashed', False):
            crash_evidence.append(fuzz_result)
    
    if crash_evidence:
        threats.append({
            'threat_type': 'Runtime Vulnerability',
            'severity': 'high',
            'description': 'Runtime crashes detected during fuzzing: potential buffer overflow or exception handling issues',
            'evidence': crash_evidence,
            'line_numbers': []
        })
    
    return threats
