#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Control Flow Graph Analysis
Identifies control flow structures (if, for, while, try) and records line number relationships.
"""

import ast
from typing import List, Dict, Any


class CFGAnalyzer(ast.NodeVisitor):
    """AST visitor for control flow analysis."""
    
    def __init__(self):
        self.cfg_structures = []
    
    def _get_node_repr(self, node: ast.AST) -> str:
        """Get simplified string representation of a node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        elif isinstance(node, ast.Compare):
            # Simplify comparison expressions
            if len(node.ops) > 0 and len(node.comparators) > 0:
                left = self._get_node_repr(node.left)
                right = self._get_node_repr(node.comparators[0])
                op = type(node.ops[0]).__name__
                return f"{left} {op} {right}"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}(...)"
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    return f"{node.func.value.id}.{node.func.attr}(...)"
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Str):  # Python < 3.8
            return repr(node.s)
        elif isinstance(node, ast.Num):  # Python < 3.8
            return repr(node.n)
        
        return ast.dump(node)[:50]  # Limit length
    
    def _get_body_lines(self, body: List[ast.AST]) -> List[int]:
        """Extract all line numbers from a body of statements."""
        lines = []
        for stmt in body:
            if hasattr(stmt, 'lineno'):
                lines.append(stmt.lineno)
            # Recursively get lines from nested structures
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try)):
                lines.extend(self._get_body_lines(stmt.body))
                if isinstance(stmt, ast.If) and stmt.orelse:
                    lines.extend(self._get_body_lines(stmt.orelse))
                elif isinstance(stmt, (ast.For, ast.While)) and stmt.orelse:
                    lines.extend(self._get_body_lines(stmt.orelse))
                elif isinstance(stmt, ast.Try):
                    for handler in stmt.handlers:
                        lines.extend(self._get_body_lines(handler.body))
                    if stmt.orelse:
                        lines.extend(self._get_body_lines(stmt.orelse))
                    if stmt.finalbody:
                        lines.extend(self._get_body_lines(stmt.finalbody))
        return sorted(set(lines))  # Remove duplicates and sort
    
    def _get_end_line(self, node: ast.AST) -> int:
        """Estimate end line of a node by finding the maximum line in its body."""
        max_line = node.lineno
        if hasattr(node, 'body'):
            for stmt in node.body:
                if hasattr(stmt, 'lineno'):
                    max_line = max(max_line, stmt.lineno)
                # Recursively check nested structures
                if isinstance(stmt, (ast.If, ast.For, ast.While, ast.Try)):
                    max_line = max(max_line, self._get_end_line(stmt))
        if hasattr(node, 'orelse') and node.orelse:
            for stmt in node.orelse:
                if hasattr(stmt, 'lineno'):
                    max_line = max(max_line, stmt.lineno)
        if hasattr(node, 'finalbody') and node.finalbody:
            for stmt in node.finalbody:
                if hasattr(stmt, 'lineno'):
                    max_line = max(max_line, stmt.lineno)
        return max_line
    
    def visit_If(self, node: ast.If):
        """Extract if statement structure."""
        condition = self._get_node_repr(node.test)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        end_line = self._get_end_line(node)
        
        self.cfg_structures.append({
            'type': 'if',
            'start_line': node.lineno,
            'end_line': end_line,
            'condition': condition,
            'body_lines': body_lines,
            'else_lines': else_lines
        })
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For):
        """Extract for loop structure."""
        target = self._get_node_repr(node.target)
        iter_expr = self._get_node_repr(node.iter)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        end_line = self._get_end_line(node)
        
        self.cfg_structures.append({
            'type': 'for',
            'start_line': node.lineno,
            'end_line': end_line,
            'target': target,
            'iter': iter_expr,
            'body_lines': body_lines,
            'else_lines': else_lines
        })
        self.generic_visit(node)
    
    def visit_While(self, node: ast.While):
        """Extract while loop structure."""
        condition = self._get_node_repr(node.test)
        body_lines = self._get_body_lines(node.body)
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        end_line = self._get_end_line(node)
        
        self.cfg_structures.append({
            'type': 'while',
            'start_line': node.lineno,
            'end_line': end_line,
            'condition': condition,
            'body_lines': body_lines,
            'else_lines': else_lines
        })
        self.generic_visit(node)
    
    def visit_Try(self, node: ast.Try):
        """Extract try-except structure."""
        body_lines = self._get_body_lines(node.body)
        except_lines = []
        for handler in node.handlers:
            except_lines.extend(self._get_body_lines(handler.body))
        else_lines = self._get_body_lines(node.orelse) if node.orelse else []
        finally_lines = self._get_body_lines(node.finalbody) if node.finalbody else []
        end_line = self._get_end_line(node)
        
        self.cfg_structures.append({
            'type': 'try',
            'start_line': node.lineno,
            'end_line': end_line,
            'body_lines': body_lines,
            'except_lines': except_lines,
            'else_lines': else_lines,
            'finally_lines': finally_lines
        })
        self.generic_visit(node)


def analyze(ast_tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Analyze control flow structures in AST tree.
    
    Args:
        ast_tree: Root AST node
        
    Returns:
        List[Dict]: List of control flow structures, each containing:
            - 'type': str - Type of structure ('if', 'for', 'while', 'try')
            - 'start_line': int - Starting line number
            - 'end_line': int - Ending line number
            - 'body_lines': List[int] - Line numbers in the body
            - Additional fields depending on structure type
    """
    if ast_tree is None:
        return []
    
    analyzer = CFGAnalyzer()
    analyzer.visit(ast_tree)
    
    return analyzer.cfg_structures
