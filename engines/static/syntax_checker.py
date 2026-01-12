#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Syntax Checker
Checks Python source code for syntax errors using compile().
"""

import sys
from typing import Dict, List, Any


def check_syntax(source_code: str, filename: str = "<unknown>") -> Dict[str, Any]:
    """
    Check Python source code for syntax errors.
    
    Args:
        source_code: Python source code as string
        filename: Optional filename for error reporting
        
    Returns:
        dict: Dictionary containing:
            - 'valid': bool - Whether syntax is valid
            - 'errors': List[dict] - List of error dictionaries (if any)
            - 'error_message': str - Error message string
    """
    if source_code is None or len(source_code.strip()) == 0:
        return {
            'valid': False,
            'errors': [{
                'type': 'EmptySource',
                'message': 'Source code is empty',
                'line': 0,
                'offset': 0
            }],
            'error_message': 'Source code is empty'
        }
    
    try:
        # Try to compile the source code
        compile(source_code, filename, 'exec')
        
        return {
            'valid': True,
            'errors': [],
            'error_message': ''
        }
    except SyntaxError as e:
        error_info = {
            'type': 'SyntaxError',
            'message': e.msg,
            'line': e.lineno if e.lineno else 0,
            'offset': e.offset if e.offset else 0,
            'text': e.text if e.text else ''
        }
        
        return {
            'valid': False,
            'errors': [error_info],
            'error_message': f"Syntax error at line {e.lineno}: {e.msg}"
        }
    except IndentationError as e:
        error_info = {
            'type': 'IndentationError',
            'message': e.msg,
            'line': e.lineno if e.lineno else 0,
            'offset': e.offset if e.offset else 0,
            'text': e.text if e.text else ''
        }
        
        return {
            'valid': False,
            'errors': [error_info],
            'error_message': f"Indentation error at line {e.lineno}: {e.msg}"
        }
    except TabError as e:
        error_info = {
            'type': 'TabError',
            'message': e.msg,
            'line': e.lineno if e.lineno else 0,
            'offset': e.offset if e.offset else 0,
            'text': e.text if e.text else ''
        }
        
        return {
            'valid': False,
            'errors': [error_info],
            'error_message': f"Tab error at line {e.lineno}: {e.msg}"
        }
    except Exception as e:
        error_info = {
            'type': type(e).__name__,
            'message': str(e),
            'line': 0,
            'offset': 0,
            'text': ''
        }
        
        return {
            'valid': False,
            'errors': [error_info],
            'error_message': f"Unexpected error: {str(e)}"
        }
