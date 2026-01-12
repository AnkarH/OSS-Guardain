#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Intermediate Representation Generator
Converts AST to simplified linear intermediate representation (List of Dicts).
"""

import ast
from typing import List, Dict, Any, Optional


class IRGenerator(ast.NodeVisitor):
    """AST visitor to generate intermediate representation."""
    
    def __init__(self):
        self.ir = []  # List of IR dictionaries
    
    def _get_node_name(self, node: ast.AST) -> str:
        """Get a string representation of a node for display."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_node_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Str):  # Python < 3.8
            return repr(node.s)
        elif isinstance(node, ast.Num):  # Python < 3.8
            return repr(node.n)
        elif isinstance(node, ast.Call):
            func_name = self._get_node_name(node.func)
            return f"{func_name}(...)"
        else:
            return ast.dump(node)
    
    def _get_call_args(self, node: ast.Call) -> List[str]:
        """Extract argument representations from a Call node."""
        args = []
        for arg in node.args:
            args.append(self._get_node_name(arg))
        return args
    
    def visit_Call(self, node: ast.Call):
        """Extract function calls."""
        func_name = self._get_node_name(node.func)
        args = self._get_call_args(node)
        
        self.ir.append({
            'type': 'CALL',
            'func': func_name,
            'args': args,
            'line': node.lineno,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Extract assignments."""
        targets = []
        for target in node.targets:
            targets.append(self._get_node_name(target))
        
        value_repr = self._get_node_name(node.value)
        
        self.ir.append({
            'type': 'ASSIGN',
            'target': ', '.join(targets),
            'value': value_repr,
            'line': node.lineno,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        """Extract import statements."""
        for alias in node.names:
            self.ir.append({
                'type': 'IMPORT',
                'module': alias.name,
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'col_offset': node.col_offset
            })
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Extract from ... import statements."""
        module_name = node.module if node.module else ''
        for alias in node.names:
            self.ir.append({
                'type': 'IMPORT',
                'module': module_name,
                'name': alias.name,
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'col_offset': node.col_offset
            })
        self.generic_visit(node)
    
    def visit_If(self, node: ast.If):
        """Extract if statements."""
        condition = self._get_node_name(node.test)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        
        self.ir.append({
            'type': 'IF',
            'condition': condition,
            'line': node.lineno,
            'body_lines': body_lines,
            'else_lines': else_lines,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For):
        """Extract for loops."""
        target = self._get_node_name(node.target)
        iter_expr = self._get_node_name(node.iter)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        
        self.ir.append({
            'type': 'FOR',
            'target': target,
            'iter': iter_expr,
            'line': node.lineno,
            'body_lines': body_lines,
            'else_lines': else_lines,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_While(self, node: ast.While):
        """Extract while loops."""
        condition = self._get_node_name(node.test)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        
        self.ir.append({
            'type': 'WHILE',
            'condition': condition,
            'line': node.lineno,
            'body_lines': body_lines,
            'else_lines': else_lines,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_Try(self, node: ast.Try):
        """Extract try-except blocks."""
        body_lines = self._get_body_lines(node.body)
        except_lines = []
        for handler in node.handlers:
            except_lines.extend(self._get_body_lines(handler.body))
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        finally_lines = self._get_body_lines(node.finalbody) if node.finalbody else []
        
        self.ir.append({
            'type': 'TRY',
            'line': node.lineno,
            'body_lines': body_lines,
            'except_lines': except_lines,
            'else_lines': else_lines,
            'finally_lines': finally_lines,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def _get_body_lines(self, body: List[ast.AST]) -> List[int]:
        """Extract line numbers from a body of statements."""
        lines = []
        for stmt in body:
            if hasattr(stmt, 'lineno'):
                lines.append(stmt.lineno)
        return lines
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Extract function definitions."""
        self.ir.append({
            'type': 'FUNCTION_DEF',
            'name': node.name,
            'line': node.lineno,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Extract class definitions."""
        self.ir.append({
            'type': 'CLASS_DEF',
            'name': node.name,
            'line': node.lineno,
            'col_offset': node.col_offset
        })
        self.generic_visit(node)


def generate(ast_tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Generate intermediate representation from AST.
    
    Args:
        ast_tree: Root AST node
        
    Returns:
        List[Dict]: List of IR dictionaries, each representing an operation
    """
    if ast_tree is None:
        return []
    
    generator = IRGenerator()
    generator.visit(ast_tree)
    
    return generator.ir
