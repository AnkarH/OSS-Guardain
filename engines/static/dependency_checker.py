#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dependency Checker
Extracts dependencies from project files and checks for known vulnerabilities.
"""

import os
import re
import json
from typing import List, Dict, Any, Optional


def check_dependencies(file_path: str, language: str) -> List[Dict[str, Any]]:
    """
    Extract dependencies from project files.
    
    Args:
        file_path: Path to source file
        language: Programming language ('python', 'go', 'java')
        
    Returns:
        List[Dict]: List of dependencies with name and version
    """
    dependencies = []
    project_dir = os.path.dirname(os.path.abspath(file_path))
    
    if language == 'python':
        dependencies.extend(_extract_python_dependencies(project_dir))
    elif language == 'go':
        dependencies.extend(_extract_go_dependencies(project_dir))
    elif language == 'java':
        dependencies.extend(_extract_java_dependencies(project_dir))
    
    return dependencies


def _extract_python_dependencies(project_dir: str) -> List[Dict[str, Any]]:
    """Extract Python dependencies from requirements.txt, setup.py, pyproject.toml"""
    deps = []
    
    # Check requirements.txt
    req_file = os.path.join(project_dir, 'requirements.txt')
    if os.path.exists(req_file):
        try:
            with open(req_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse format: package==version or package>=version
                        match = re.match(r'^([\w\-_\.]+)(?:([><=!]+)([\d\.\w]+))?', line)
                        if match:
                            deps.append({
                                'name': match.group(1),
                                'version': match.group(3) if match.group(3) else 'unknown',
                                'constraint': match.group(2) if match.group(2) else '==',
                                'source': 'requirements.txt'
                            })
        except Exception:
            pass
    
    # Check setup.py (simplified parsing)
    setup_file = os.path.join(project_dir, 'setup.py')
    if os.path.exists(setup_file):
        try:
            with open(setup_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Look for install_requires
                match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if match:
                    requires = match.group(1)
                    for req in re.findall(r'["\']([^"\']+)["\']', requires):
                        dep_match = re.match(r'^([\w\-_\.]+)(?:([><=!]+)([\d\.\w]+))?', req)
                        if dep_match:
                            deps.append({
                                'name': dep_match.group(1),
                                'version': dep_match.group(3) if dep_match.group(3) else 'unknown',
                                'constraint': dep_match.group(2) if dep_match.group(2) else '==',
                                'source': 'setup.py'
                            })
        except Exception:
            pass
    
    return deps


def _extract_go_dependencies(project_dir: str) -> List[Dict[str, Any]]:
    """Extract Go dependencies from go.mod"""
    deps = []
    
    go_mod = os.path.join(project_dir, 'go.mod')
    if os.path.exists(go_mod):
        try:
            with open(go_mod, 'r', encoding='utf-8') as f:
                in_require_block = False
                for line in f:
                    line = line.strip()
                    if line == 'require (':
                        in_require_block = True
                        continue
                    elif line == ')' and in_require_block:
                        in_require_block = False
                        continue
                    elif line.startswith('require ') or in_require_block:
                        # Parse: module_path version or module_path v1.2.3
                        parts = line.replace('require', '').strip().split()
                        if len(parts) >= 1:
                            module = parts[0]
                            version = parts[1] if len(parts) > 1 else 'unknown'
                            deps.append({
                                'name': module,
                                'version': version,
                                'source': 'go.mod'
                            })
        except Exception:
            pass
    
    return deps


def _extract_java_dependencies(project_dir: str) -> List[Dict[str, Any]]:
    """Extract Java dependencies from pom.xml or build.gradle"""
    deps = []
    
    # Check pom.xml (Maven)
    pom_file = os.path.join(project_dir, 'pom.xml')
    if os.path.exists(pom_file):
        try:
            with open(pom_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Find dependency blocks
                dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
                for match in re.finditer(dep_pattern, content, re.DOTALL):
                    group_id = match.group(1).strip()
                    artifact_id = match.group(2).strip()
                    version = match.group(3).strip()
                    deps.append({
                        'name': f"{group_id}:{artifact_id}",
                        'version': version,
                        'source': 'pom.xml'
                    })
        except Exception:
            pass
    
    # Check build.gradle (Gradle)
    gradle_file = os.path.join(project_dir, 'build.gradle')
    if os.path.exists(gradle_file):
        try:
            with open(gradle_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Find dependencies block
                deps_block = re.search(r'dependencies\s*\{([^}]+)\}', content, re.DOTALL)
                if deps_block:
                    deps_content = deps_block.group(1)
                    # Parse implementation/compile/compileOnly lines
                    for line in deps_content.split('\n'):
                        match = re.search(r'["\']([^"\']+):([^"\']+):([^"\']+)["\']', line)
                        if match:
                            deps.append({
                                'name': f"{match.group(1)}:{match.group(2)}",
                                'version': match.group(3),
                                'source': 'build.gradle'
                            })
        except Exception:
            pass
    
    return deps
