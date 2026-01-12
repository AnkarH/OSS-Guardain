#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go Language Parser
Parses Go source code files and extracts basic structure.
"""

import os
import re
from typing import Dict, List, Any, Optional


def parse_go_file(file_path: str) -> Dict[str, Any]:
    """
    Parse a Go source file and extract basic structure.
    
    Args:
        file_path: Path to Go source file
        
    Returns:
        dict: Parsed structure containing:
            - 'package': str - Package name
            - 'imports': List[str] - Import statements
            - 'functions': List[Dict] - Function definitions
            - 'variables': List[Dict] - Variable declarations
            - 'source_code': str - Original source code
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
    except Exception as e:
        raise IOError(f"Failed to read Go file {file_path}: {str(e)}")
    
    result = {
        'package': '',
        'imports': [],
        'functions': [],
        'variables': [],
        'source_code': source_code,
        'file_path': file_path
    }
    
    lines = source_code.split('\n')
    
    # Extract package name
    package_pattern = r'^package\s+(\w+)'
    for line in lines:
        match = re.match(package_pattern, line.strip())
        if match:
            result['package'] = match.group(1)
            break
    
    # Extract imports
    in_import_block = False
    import_block = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Single line import
        if re.match(r'^import\s+"[^"]+"', stripped):
            match = re.search(r'"([^"]+)"', stripped)
            if match:
                result['imports'].append(match.group(1))
        
        # Multi-line import block
        if stripped == 'import (':
            in_import_block = True
            continue
        elif in_import_block:
            if stripped == ')':
                in_import_block = False
                # Parse collected import block
                for imp_line in import_block:
                    match = re.search(r'"([^"]+)"', imp_line)
                    if match:
                        result['imports'].append(match.group(1))
                import_block = []
            else:
                import_block.append(stripped)
    
    # Extract function definitions
    func_pattern = r'^func\s+(\w+)\s*\([^)]*\)\s*(?:\([^)]*\))?\s*(?:\w+)?\s*\{'
    for i, line in enumerate(lines):
        match = re.match(func_pattern, line.strip())
        if match:
            func_name = match.group(1)
            # Find function end (simplified - looks for matching braces)
            start_line = i + 1
            brace_count = 1
            end_line = start_line
            
            for j in range(i + 1, len(lines)):
                brace_count += lines[j].count('{') - lines[j].count('}')
                if brace_count == 0:
                    end_line = j + 1
                    break
            
            result['functions'].append({
                'name': func_name,
                'start_line': start_line,
                'end_line': end_line,
                'line': i + 1
            })
    
    # Extract variable declarations
    var_patterns = [
        r'^var\s+(\w+)\s+',
        r'^(\w+)\s*:=\s*',
    ]
    for i, line in enumerate(lines):
        for pattern in var_patterns:
            match = re.match(pattern, line.strip())
            if match:
                var_name = match.group(1)
                result['variables'].append({
                    'name': var_name,
                    'line': i + 1
                })
                break
    
    return result


def build_go_ast(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a simplified AST structure from parsed Go data.
    
    Args:
        parsed_data: Output from parse_go_file()
        
    Returns:
        dict: AST-like structure
    """
    return {
        'type': 'go_file',
        'package': parsed_data.get('package', ''),
        'imports': [{'path': imp} for imp in parsed_data.get('imports', [])],
        'functions': parsed_data.get('functions', []),
        'variables': parsed_data.get('variables', []),
        'source_code': parsed_data.get('source_code', '')
    }
