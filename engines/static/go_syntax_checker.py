#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go Syntax Checker
Checks Go source code syntax using go build or go vet.
"""

import os
import subprocess
import tempfile
from typing import Dict, Any


def check_syntax(file_path: str) -> Dict[str, Any]:
    """
    Check Go source code syntax.
    
    Args:
        file_path: Path to Go source file
        
    Returns:
        dict: Syntax check results containing:
            - 'valid': bool - Whether syntax is valid
            - 'errors': List[str] - Error messages
    """
    result = {
        'valid': True,
        'errors': []
    }
    
    # Check if go command is available
    try:
        subprocess.run(['go', 'version'], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        # Go not available, use basic validation
        result['valid'] = True
        result['errors'] = ['Go compiler not available, skipping syntax check']
        return result
    
    # Try to compile the file
    try:
        # Create a temporary directory with the file
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, os.path.basename(file_path))
        
        # Copy file to temp directory
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Try to build
        process = subprocess.run(
            ['go', 'build', '-o', os.devnull, temp_file],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=temp_dir
        )
        
        if process.returncode != 0:
            result['valid'] = False
            result['errors'] = process.stderr.split('\n') if process.stderr else ['Unknown syntax error']
        
        # Cleanup
        try:
            os.remove(temp_file)
            os.rmdir(temp_dir)
        except:
            pass
            
    except subprocess.TimeoutExpired:
        result['valid'] = False
        result['errors'] = ['Syntax check timeout']
    except Exception as e:
        result['valid'] = False
        result['errors'] = [f"Syntax check error: {str(e)}"]
    
    return result
