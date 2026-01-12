#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go Taint Analysis
Tracks taint data flow in Go source code.
"""

import re
from typing import List, Dict, Any
from engines.preprocessing.go_parser import parse_go_file


def analyze(file_path: str) -> List[Dict[str, Any]]:
    """
    Perform taint analysis on Go source code.
    
    Args:
        file_path: Path to Go source file
        
    Returns:
        List[Dict]: Taint flow information
    """
    taint_flows = []
    
    try:
        parsed_data = parse_go_file(file_path)
        source_code = parsed_data.get('source_code', '')
        lines = source_code.split('\n')
    except Exception:
        return taint_flows
    
    # Taint sources in Go
    taint_sources = [
        r'os\.Args',
        r'flag\.String\(',
        r'flag\.Int\(',
        r'flag\.Bool\(',
        r'http\.Request\.FormValue\(',
        r'http\.Request\.PostFormValue\(',
        r'http\.Request\.Header\.Get\(',
        r'c\.Query\(',  # Gin framework
        r'c\.Param\(',  # Gin framework
    ]
    
    # Sink functions (dangerous operations)
    sinks = [
        r'exec\.Command\(',
        r'exec\.Run\(',
        r'os\.Exec\(',
        r'os\.OpenFile\(',
        r'os\.Create\(',
        r'os\.WriteFile\(',
        r'fmt\.Sprintf\(',
        r'sql\.DB\.Query\(',
        r'sql\.DB\.Exec\(',
    ]
    
    # Find taint sources
    source_lines = {}
    for i, line in enumerate(lines, 1):
        for pattern in taint_sources:
            if re.search(pattern, line):
                source_lines[i] = line.strip()
                break
    
    # Find sinks
    sink_lines = {}
    for i, line in enumerate(lines, 1):
        for pattern in sinks:
            if re.search(pattern, line):
                sink_lines[i] = line.strip()
                break
    
    # Create taint flows (simplified: if source and sink exist, create flow)
    for source_line, source_code in source_lines.items():
        for sink_line, sink_code in sink_lines.items():
            if sink_line > source_line:  # Sink must come after source
                taint_flows.append({
                    'source_line': source_line,
                    'source_code': source_code,
                    'sink_line': sink_line,
                    'sink_code': sink_code,
                    'description': f"Taint data from line {source_line} flows to sink at line {sink_line}"
                })
    
    return taint_flows
