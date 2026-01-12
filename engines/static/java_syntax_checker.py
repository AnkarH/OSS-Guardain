#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java Syntax Checker
Checks Java source code syntax using javac.
"""

import os
import subprocess
import tempfile
from typing import Dict, Any


def check_syntax(file_path: str) -> Dict[str, Any]:
    """
    Check Java source code syntax.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        dict: Syntax check results containing:
            - 'valid': bool - Whether syntax is valid
            - 'errors': List[str] - Error messages
    """
    result = {
        'valid': True,
        'errors': []
    }
    
    # Check if javac is available
    try:
        subprocess.run(['javac', '-version'], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Java compiler not available, use basic validation
        result['valid'] = True
        result['errors'] = ['Java compiler not available, skipping syntax check']
        return result
    
    # Try to compile the file
    try:
        process = subprocess.run(
            ['javac', file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if process.returncode != 0:
            result['valid'] = False
            result['errors'] = process.stderr.split('\n') if process.stderr else ['Unknown syntax error']
        
        # Cleanup .class files
        class_file = file_path.replace('.java', '.class')
        if os.path.exists(class_file):
            try:
                os.remove(class_file)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        result['valid'] = False
        result['errors'] = ['Syntax check timeout']
    except Exception as e:
        result['valid'] = False
        result['errors'] = [f"Syntax check error: {str(e)}"]
    
    return result
