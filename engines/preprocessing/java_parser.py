#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java Language Parser
Parses Java source code files and extracts basic structure.
"""

import os
import re
from typing import Dict, List, Any, Optional


def parse_java_file(file_path: str) -> Dict[str, Any]:
    """
    Parse a Java source file and extract basic structure.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        dict: Parsed structure containing:
            - 'package': str - Package name
            - 'imports': List[str] - Import statements
            - 'classes': List[Dict] - Class definitions
            - 'methods': List[Dict] - Method definitions
            - 'variables': List[Dict] - Variable declarations
            - 'source_code': str - Original source code
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
    except Exception as e:
        raise IOError(f"Failed to read Java file {file_path}: {str(e)}")
    
    result = {
        'package': '',
        'imports': [],
        'classes': [],
        'methods': [],
        'variables': [],
        'source_code': source_code,
        'file_path': file_path
    }
    
    lines = source_code.split('\n')
    
    # Extract package name
    package_pattern = r'^package\s+([\w.]+);'
    for line in lines:
        match = re.match(package_pattern, line.strip())
        if match:
            result['package'] = match.group(1)
            break
    
    # Extract imports
    import_pattern = r'^import\s+(?:static\s+)?([\w.*]+);'
    for line in lines:
        match = re.match(import_pattern, line.strip())
        if match:
            result['imports'].append(match.group(1))
    
    # Extract class definitions
    class_pattern = r'^(?:public\s+|private\s+|protected\s+)?(?:abstract\s+|final\s+)?class\s+(\w+)'
    for i, line in enumerate(lines):
        match = re.search(class_pattern, line.strip())
        if match:
            class_name = match.group(1)
            # Find class end (simplified)
            start_line = i + 1
            brace_count = line.count('{') - line.count('}')
            end_line = start_line
            
            for j in range(i + 1, len(lines)):
                brace_count += lines[j].count('{') - lines[j].count('}')
                if brace_count == 0:
                    end_line = j + 1
                    break
            
            result['classes'].append({
                'name': class_name,
                'start_line': start_line,
                'end_line': end_line,
                'line': i + 1
            })
    
    # Extract method definitions
    method_pattern = r'^(?:public|private|protected|static|\s)*\s*(?:[\w<>\[\]]+\s+)?(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{'
    for i, line in enumerate(lines):
        # Skip if it's a class declaration
        if re.search(r'^\s*class\s+', line):
            continue
        
        match = re.search(method_pattern, line.strip())
        if match:
            method_name = match.group(1)
            # Skip constructors (same name as class)
            is_constructor = False
            for cls in result['classes']:
                if method_name == cls['name']:
                    is_constructor = True
                    break
            
            if not is_constructor:
                result['methods'].append({
                    'name': method_name,
                    'line': i + 1
                })
    
    # Extract variable declarations
    var_patterns = [
        r'^(?:public|private|protected|static|\s)*\s*([\w<>\[\]]+)\s+(\w+)\s*[=;]',
    ]
    for i, line in enumerate(lines):
        for pattern in var_patterns:
            match = re.match(pattern, line.strip())
            if match:
                var_name = match.group(2) if len(match.groups()) > 1 else match.group(1)
                result['variables'].append({
                    'name': var_name,
                    'line': i + 1
                })
                break
    
    return result


def build_java_ast(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a simplified AST structure from parsed Java data.
    
    Args:
        parsed_data: Output from parse_java_file()
        
    Returns:
        dict: AST-like structure
    """
    return {
        'type': 'java_file',
        'package': parsed_data.get('package', ''),
        'imports': [{'path': imp} for imp in parsed_data.get('imports', [])],
        'classes': parsed_data.get('classes', []),
        'methods': parsed_data.get('methods', []),
        'variables': parsed_data.get('variables', []),
        'source_code': parsed_data.get('source_code', '')
    }
