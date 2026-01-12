#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
File Activity Monitor
Monitors file read/write/delete operations during dynamic analysis.
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime


class FileMonitor:
    """Monitors file operations during execution."""
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize file monitor.
        
        Args:
            log_file: Path to log file for file operations
        """
        self.log_file = log_file
        self.file_operations = []
        self.sensitive_files = [
            '/etc/passwd',
            '/etc/shadow',
            '.env',
            '.git/config',
            'config.json',
            'secrets.json',
            'credentials.json',
            'private_key',
            'id_rsa',
            'id_dsa'
        ]
    
    def log_file_operation(self, operation: str, file_path: str, mode: str = 'r'):
        """
        Log a file operation.
        
        Args:
            operation: Operation type ('read', 'write', 'delete', 'open')
            file_path: Path to file
            mode: File mode (for open operations)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Check if file is sensitive
        is_sensitive = any(sensitive in file_path for sensitive in self.sensitive_files)
        
        entry = {
            'timestamp': timestamp,
            'operation': operation,
            'file_path': file_path,
            'mode': mode,
            'is_sensitive': is_sensitive
        }
        
        self.file_operations.append(entry)
        
        # Write to log file if provided
        if self.log_file:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    alert_level = '[ALERT]' if is_sensitive else '[INFO]'
                    f.write(f"[{timestamp}] {alert_level} FILE {operation.upper()}: {file_path} (mode: {mode})\n")
            except Exception:
                pass
    
    def get_file_operations(self) -> List[Dict[str, Any]]:
        """Get all recorded file operations."""
        return self.file_operations
    
    def get_sensitive_operations(self) -> List[Dict[str, Any]]:
        """Get only sensitive file operations."""
        return [op for op in self.file_operations if op.get('is_sensitive', False)]


def analyze_file_activity(log_file: str) -> List[Dict[str, Any]]:
    """
    Analyze file activity from log file.
    
    Args:
        log_file: Path to log file containing file operations
        
    Returns:
        List[Dict]: List of file operations
    """
    operations = []
    
    if not os.path.exists(log_file):
        return operations
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if 'FILE' in line:
                    # Parse log entry
                    # Format: [timestamp] [ALERT/INFO] FILE OPERATION: path (mode: mode)
                    parts = line.strip().split('FILE')
                    if len(parts) == 2:
                        operation_part = parts[1].strip()
                        operation_match = operation_part.split(':')
                        if len(operation_match) >= 2:
                            operation = operation_match[0].strip()
                            file_path = operation_match[1].split('(mode:')[0].strip()
                            
                            operations.append({
                                'operation': operation.lower(),
                                'file_path': file_path,
                                'is_sensitive': '[ALERT]' in line
                            })
    except Exception:
        pass
    
    return operations
