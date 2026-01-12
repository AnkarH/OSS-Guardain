#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java AST Builder
Builds AST representation for Java source code.
"""

from typing import Dict, Any
from engines.preprocessing.java_parser import parse_java_file, build_java_ast


def build_ast(file_path: str) -> Dict[str, Any]:
    """
    Build AST for Java source file.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        dict: AST structure
    """
    parsed_data = parse_java_file(file_path)
    return build_java_ast(parsed_data)
