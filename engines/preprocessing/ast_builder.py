#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AST Builder
Converts Python source code to Abstract Syntax Tree (AST) objects.
"""

import ast
import sys


def build_ast(source_code: str, filename: str = "<unknown>") -> ast.AST:
    """
    Parse Python source code and build an AST tree.
    
    Args:
        source_code: Python source code as string
        filename: Optional filename for error reporting
        
    Returns:
        ast.AST: Root node of the AST tree
        
    Raises:
        SyntaxError: If source code contains syntax errors
        ValueError: If source_code is empty or None
    """
    if source_code is None:
        raise ValueError("Source code cannot be None")
    
    if not isinstance(source_code, str):
        raise TypeError(f"Source code must be a string, got {type(source_code)}")
    
    if len(source_code.strip()) == 0:
        raise ValueError("Source code cannot be empty")
    
    try:
        # Parse source code into AST
        tree = ast.parse(source_code, filename=filename, mode='exec')
        return tree
    except SyntaxError as e:
        # Re-raise with more context
        error_msg = f"Syntax error in {filename} at line {e.lineno}: {e.msg}"
        if e.text:
            error_msg += f"\n{e.text}"
            if e.offset:
                error_msg += " " * (e.offset - 1) + "^"
        raise SyntaxError(error_msg) from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error parsing source code: {str(e)}") from e
