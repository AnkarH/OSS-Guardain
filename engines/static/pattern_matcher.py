#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pattern Matcher
Uses regular expressions to match security rules from rules.yaml against source code.
"""

import re
from typing import List, Dict, Any, Optional


def match_patterns(source_code: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Match security patterns against source code using regular expressions.
    
    Args:
        source_code: Python source code as string
        rules: List of rule dictionaries from rules.yaml, each containing:
            - 'id': str - Rule identifier
            - 'name': str - Rule name
            - 'pattern': str - Regular expression pattern
            - 'severity': str - Severity level
            - 'description': str - Rule description
            
    Returns:
        List[Dict]: List of matched patterns, each containing:
            - 'rule_id': str - Rule identifier
            - 'rule_name': str - Rule name
            - 'severity': str - Severity level
            - 'line': int - Line number where match occurred
            - 'matched_text': str - Text that matched the pattern
            - 'description': str - Rule description
    """
    if not source_code or not rules:
        return []
    
    matches = []
    lines = source_code.split('\n')
    
    for rule in rules:
        rule_id = rule.get('id', '')
        rule_name = rule.get('name', '')
        pattern = rule.get('pattern', '')
        severity = rule.get('severity', 'medium')
        description = rule.get('description', '')
        
        if not pattern:
            continue
        
        try:
            # Compile regex pattern
            regex = re.compile(pattern)
            
            # Match against each line
            for line_num, line in enumerate(lines, start=1):
                # Find all matches in the line
                for match in regex.finditer(line):
                    matched_text = match.group(0)
                    
                    # Get some context (surrounding lines if available)
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 2)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    matches.append({
                        'rule_id': rule_id,
                        'rule_name': rule_name,
                        'severity': severity,
                        'line': line_num,
                        'matched_text': matched_text,
                        'description': description,
                        'context': context,
                        'col_offset': match.start()
                    })
        except re.error as e:
            # Skip invalid regex patterns
            continue
        except Exception as e:
            # Skip rules that cause errors
            continue
    
    # Sort matches by line number
    matches.sort(key=lambda x: x['line'])
    
    return matches


def load_rules_from_yaml(yaml_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract rules list from YAML data structure.
    
    Args:
        yaml_data: Dictionary loaded from rules.yaml
        
    Returns:
        List[Dict]: List of rule dictionaries
    """
    if not isinstance(yaml_data, dict):
        return []
    
    rules = yaml_data.get('rules', [])
    if not isinstance(rules, list):
        return []
    
    return rules
