#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Network Monitor
Analyzes dynamic execution logs to extract network connection activities.
"""

import os
import re
from typing import List, Dict, Any, Optional


def analyze_network_activity(log_source) -> List[Dict[str, Any]]:
    """
    Analyze log file to extract network connection activities.
    
    Args:
        log_source: Log file path or list of log entries
        
    Returns:
        List[Dict]: List of network activities, each containing:
            - 'type': str - Activity type ('connect', 'bind', etc.)
            - 'target': str - Target address (IP:port)
            - 'timestamp': str - Timestamp of activity
            - 'line': str - Original log line
            - 'raw_address': tuple or str - Raw address from log
    """
    if not log_source:
        return []

    activities = []
    lines: List[str] = []

    if isinstance(log_source, list):
        lines = log_source
    elif isinstance(log_source, str):
        if not os.path.exists(log_source):
            return []
        try:
            with open(log_source, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception:
            return []
    else:
        return []
    
    # Pattern to match network activity log entries
    # Format: [TIMESTAMP] [ALERT] NETWORK: socket.connect called with address='IP:PORT' | stack=...
    network_pattern = re.compile(
        r'\[([^\]]+)\]\s+\[ALERT\]\s+NETWORK:\s+socket\.(connect|connect_ex|bind|create_connection)\s+called\s+with\s+address=[\'"]([^\'"]+)[\'"]'
    )
    
    for line in lines:
        match = network_pattern.search(line)
        if match:
            timestamp = match.group(1)
            activity_type = match.group(2)  # 'connect' or 'bind'
            address_str = match.group(3)
            
            # Parse address (format: "IP:PORT" or tuple representation)
            target = address_str
            raw_address = address_str
            
            # Try to parse as tuple if it looks like one
            tuple_match = re.match(r'\(([^,]+),\s*(\d+)\)', address_str)
            if tuple_match:
                ip = tuple_match.group(1).strip("'\"")
                port = tuple_match.group(2)
                target = f"{ip}:{port}"
                raw_address = (ip, int(port))
            
            activities.append({
                'type': activity_type,
                'target': target,
                'timestamp': timestamp,
                'line': line.strip(),
                'raw_address': raw_address
            })
    
    return activities


def get_network_summary(activities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate summary statistics from network activities.
    
    Args:
        activities: List of network activities
        
    Returns:
        dict: Summary containing:
            - 'total_connections': int
            - 'unique_targets': List[str]
            - 'connect_count': int
            - 'bind_count': int
    """
    if not activities:
        return {
            'total_connections': 0,
            'unique_targets': [],
            'connect_count': 0,
            'bind_count': 0
        }
    
    unique_targets = set()
    connect_count = 0
    bind_count = 0
    
    for activity in activities:
        unique_targets.add(activity['target'])
        if activity['type'] == 'connect':
            connect_count += 1
        elif activity['type'] == 'bind':
            bind_count += 1
    
    return {
        'total_connections': len(activities),
        'unique_targets': sorted(list(unique_targets)),
        'connect_count': connect_count,
        'bind_count': bind_count
    }
