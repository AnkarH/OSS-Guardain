#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Symbol Table Extractor
Traverses AST to extract all symbols: functions, variables, imports, classes.
"""

import ast
from typing import Dict, List, Any


class SymbolExtractor(ast.NodeVisitor):
    """AST visitor to extract symbols from code."""
    
    def __init__(self):
        self.functions = []  # List of (name, line_no)
        self.variables = []  # List of (name, line_no)
        self.imports = []  # List of (module_name, line_no, alias)
        self.classes = []  # List of (name, line_no)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Extract function definitions."""
        self.functions.append({
            'name': node.name,
            'line': node.lineno,
            'is_method': False  # Will be set to True if inside a class
        })
        # Visit function body to find nested functions
        self.generic_visit(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Extract async function definitions."""
        self.functions.append({
            'name': node.name,
            'line': node.lineno,
            'is_method': False
        })
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Extract class definitions."""
        self.classes.append({
            'name': node.name,
            'line': node.lineno
        })
        # Mark functions inside class as methods
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.append({
                    'name': item.name,
                    'line': item.lineno,
                    'is_method': True,
                    'class_name': node.name
                })
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        """Extract import statements."""
        for alias in node.names:
            self.imports.append({
                'module': alias.name,
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'type': 'import'
            })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Extract from ... import statements."""
        module_name = node.module if node.module else ''
        for alias in node.names:
            self.imports.append({
                'module': module_name,
                'name': alias.name,
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'type': 'from_import'
            })
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Extract variable assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variables.append({
                    'name': target.id,
                    'line': node.lineno,
                    'type': 'variable'
                })
            elif isinstance(target, ast.Attribute):
                # Class attribute or module attribute
                if isinstance(target.value, ast.Name):
                    self.variables.append({
                        'name': f"{target.value.id}.{target.attr}",
                        'line': node.lineno,
                        'type': 'attribute'
                    })
        self.generic_visit(node)
    
    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Extract annotated assignments (Python 3.6+)."""
        if isinstance(node.target, ast.Name):
            self.variables.append({
                'name': node.target.id,
                'line': node.lineno,
                'type': 'variable'
            })
        self.generic_visit(node)


def extract_symbols(ast_tree: ast.AST) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract all symbols from AST tree.
    
    Args:
        ast_tree: Root AST node
        
    Returns:
        dict: Dictionary containing:
            - 'functions': List of function information
            - 'variables': List of variable information
            - 'imports': List of import information
            - 'classes': List of class information
    """
    if ast_tree is None:
        return {
            'functions': [],
            'variables': [],
            'imports': [],
            'classes': []
        }
    
    extractor = SymbolExtractor()
    extractor.visit(ast_tree)
    
    return {
        'functions': extractor.functions,
        'variables': extractor.variables,
        'imports': extractor.imports,
        'classes': extractor.classes
    }
