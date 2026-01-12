#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Source Code Parser
Reads Python source code files and returns their content.
"""

import os


def read_file(file_path: str) -> str:
    """
    Read a Python source code file and return its content.
    
    Args:
        file_path: Path to the Python source file
        
    Returns:
        str: File content as string
        
    Raises:
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be read
        UnicodeDecodeError: If file encoding is invalid
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    try:
        # Try UTF-8 encoding first
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except UnicodeDecodeError:
        # Fallback to latin-1 if UTF-8 fails
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
            return content
        except Exception as e:
            raise UnicodeDecodeError(
                'utf-8',
                b'',
                0,
                1,
                f"Could not decode file {file_path}: {str(e)}"
            )
    except PermissionError:
        raise PermissionError(f"Permission denied: {file_path}")
    except Exception as e:
        raise IOError(f"Error reading file {file_path}: {str(e)}")
