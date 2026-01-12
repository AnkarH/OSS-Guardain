#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CVE Matcher
Matches dependencies against CVE database to find known vulnerabilities.
"""

import os
import json
from typing import List, Dict, Any, Optional


def match_cve(dependencies: List[Dict[str, Any]], cve_db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Match dependencies against CVE database.
    
    Args:
        dependencies: List of dependency dictionaries
        cve_db_path: Path to CVE database JSON file
        
    Returns:
        List[Dict]: List of matched CVEs
    """
    if cve_db_path is None:
        cve_db_path = os.path.join(os.path.dirname(__file__), '../../data/cve_database.json')
    
    # Load CVE database
    cve_db = _load_cve_database(cve_db_path)
    
    matches = []
    
    for dep in dependencies:
        dep_name = dep.get('name', '').lower()
        dep_version = dep.get('version', 'unknown')
        
        # Search in CVE database
        for cve_entry in cve_db:
            if _match_dependency(dep_name, dep_version, cve_entry):
                matches.append({
                    'dependency': dep,
                    'cve_id': cve_entry.get('cve_id', ''),
                    'description': cve_entry.get('description', ''),
                    'severity': cve_entry.get('severity', 'medium'),
                    'vulnerable_versions': cve_entry.get('vulnerable_versions', ''),
                    'fixed_version': cve_entry.get('fixed_version', '')
                })
    
    return matches


def _load_cve_database(db_path: str) -> List[Dict[str, Any]]:
    """Load CVE database from JSON file."""
    if not os.path.exists(db_path):
        # Return empty database if file doesn't exist
        return []
    
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'cves' in data:
                return data['cves']
            else:
                return []
    except Exception:
        return []


def _match_dependency(dep_name: str, dep_version: str, cve_entry: Dict[str, Any]) -> bool:
    """Check if dependency matches CVE entry."""
    cve_package = cve_entry.get('package', '').lower()
    
    # Check package name match
    if cve_package not in dep_name and dep_name not in cve_package:
        return False
    
    # Check version range (simplified)
    vulnerable_versions = cve_entry.get('vulnerable_versions', '')
    if not vulnerable_versions or dep_version == 'unknown':
        return True  # If version unknown, assume vulnerable
    
    # Simple version matching (can be enhanced)
    if vulnerable_versions in dep_version:
        return True
    
    return False
