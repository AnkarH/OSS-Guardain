#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Language Detector
Detects programming language from file extension and content.
"""

import os
from typing import Optional


def detect_language(file_path: str) -> str:
    """
    Detect programming language from file path.
    
    Args:
        file_path: Path to source code file
        
    Returns:
        str: Language identifier ('python', 'go', 'java', or 'unknown')
    """
    if not file_path:
        return 'unknown'
    
    # Get file extension
    _, ext = os.path.splitext(file_path.lower())
    
    # Language mapping
    language_map = {
        '.py': 'python',
        '.go': 'go',
        '.java': 'java',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.rb': 'ruby',
        '.php': 'php'
    }
    
    # Check extension first
    if ext in language_map:
        return language_map[ext]
    
    # Fallback: try to detect from file content (for files without extension)
    try:
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = ''.join([f.readline() for _ in range(5)])
                
            # Check for language-specific patterns
            if 'package main' in first_lines or 'import (' in first_lines:
                return 'go'
            elif 'package ' in first_lines and 'import ' in first_lines:
                return 'java'
            elif '#!/usr/bin/env python' in first_lines or 'def ' in first_lines:
                return 'python'
    except Exception:
        pass
    
    return 'unknown'


def is_supported_language(language: str) -> bool:
    """
    Check if a language is currently supported for analysis.
    
    Args:
        language: Language identifier
        
    Returns:
        bool: True if language is supported
    """
    supported = {'python', 'go', 'java'}
    return language in supported


def get_language_display_name(language: str) -> str:
    """
    Get display name for a language.
    
    Args:
        language: Language identifier
        
    Returns:
        str: Display name
    """
    display_names = {
        'python': 'Python',
        'go': 'Go',
        'java': 'Java',
        'javascript': 'JavaScript',
        'typescript': 'TypeScript',
        'cpp': 'C++',
        'c': 'C',
        'csharp': 'C#',
        'ruby': 'Ruby',
        'php': 'PHP',
        'unknown': 'Unknown'
    }
    return display_names.get(language, language.capitalize())
