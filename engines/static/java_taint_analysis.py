#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java Taint Analysis
Tracks taint data flow in Java source code.
"""

import re
from typing import List, Dict, Any
from engines.preprocessing.java_parser import parse_java_file


def analyze(file_path: str) -> List[Dict[str, Any]]:
    """
    Perform taint analysis on Java source code.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        List[Dict]: Taint flow information
    """
    taint_flows = []
    
    try:
        parsed_data = parse_java_file(file_path)
        source_code = parsed_data.get('source_code', '')
        lines = source_code.split('\n')
    except Exception:
        return taint_flows
    
    # Taint sources in Java
    taint_sources = [
        r'System\.in',
        r'args\s*\[',
        r'request\.getParameter\(',
        r'request\.getHeader\(',
        r'request\.getQueryString\(',
        r'request\.getCookies\(',
        r'session\.getAttribute\(',
    ]
    
    # Sink functions (dangerous operations)
    sinks = [
        r'Runtime\.getRuntime\(\)\.exec\(',
        r'ProcessBuilder\(',
        r'new\s+ProcessBuilder\(',
        r'FileWriter\(',
        r'FileOutputStream\(',
        r'PrintWriter\(',
        r'Statement\.executeQuery\(',
        r'Statement\.executeUpdate\(',
        r'PreparedStatement\.executeQuery\(',
        r'PreparedStatement\.executeUpdate\(',
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
