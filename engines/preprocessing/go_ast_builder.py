#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go AST Builder
Builds AST representation for Go source code.
"""

from typing import Dict, Any
from engines.preprocessing.go_parser import parse_go_file, build_go_ast


def build_ast(file_path: str) -> Dict[str, Any]:
    """
    Build AST for Go source file.
    
    Args:
        file_path: Path to Go source file
        
    Returns:
        dict: AST structure
    """
    parsed_data = parse_go_file(file_path)
    return build_go_ast(parsed_data)
