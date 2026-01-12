#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Taint Analysis
Tracks data flow from taint sources (sys.argv, input) to dangerous sinks (os.system, eval, etc.).
"""

import ast
from typing import List, Dict, Any, Set, Optional


class TaintAnalyzer(ast.NodeVisitor):
    """AST visitor for taint analysis."""
    
    def __init__(self):
        self.taint_sources = []  # List of (source, line_no)
        self.taint_sinks = []  # List of (sink, line_no, func_name)
        self.taint_flows = []  # List of detected taint flows
        self.current_tainted_vars = set()  # Variables currently tainted
        self.var_assignments = {}  # Map variable name to assignment line
    
    def _is_taint_source(self, node: ast.AST) -> bool:
        """Check if a node represents a taint source."""
        # Check for sys.argv access
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if isinstance(node.value.value, ast.Name) and node.value.value.id == 'sys':
                    if node.value.attr == 'argv':
                        return True
        
        # Check for input() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ('input', 'raw_input'):
                    return True
        
        return False
    
    def _is_taint_sink(self, node: ast.Call) -> Optional[str]:
        """Check if a call node represents a taint sink. Returns function name if yes."""
        if isinstance(node.func, ast.Attribute):
            # os.system, os.popen, etc.
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == 'os':
                    if node.func.attr in ('system', 'popen'):
                        return f"os.{node.func.attr}"
                elif node.func.value.id == 'subprocess':
                    if node.func.attr in ('call', 'run', 'Popen'):
                        return f"subprocess.{node.func.attr}"
        
        # eval, exec calls
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                return node.func.id
        
        return None
    
    def _get_variable_name(self, node: ast.AST) -> Optional[str]:
        """Extract variable name from a node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # For attributes, return the full path
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        return None
    
    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments and taint propagation."""
        # Check if the value is a taint source
        is_tainted = self._is_taint_source(node.value)
        
        # Check if assigned from a tainted variable
        if not is_tainted:
            var_name = self._get_variable_name(node.value)
            if var_name and var_name in self.current_tainted_vars:
                is_tainted = True
        
        # Mark target variables as tainted
        if is_tainted:
            for target in node.targets:
                var_name = self._get_variable_name(target)
                if var_name:
                    self.current_tainted_vars.add(var_name)
                    self.var_assignments[var_name] = node.lineno
                    
                    # Record taint source
                    source_repr = self._get_node_repr(node.value)
                    self.taint_sources.append({
                        'source': source_repr,
                        'line': node.lineno,
                        'tainted_var': var_name
                    })
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Detect taint sinks and check for taint flow."""
        sink_name = self._is_taint_sink(node)
        
        if sink_name:
            # Record sink
            self.taint_sinks.append({
                'sink': sink_name,
                'line': node.lineno,
                'args': [self._get_node_repr(arg) for arg in node.args]
            })
            
            # Check if any argument is tainted
            for arg in node.args:
                arg_repr = self._get_node_repr(arg)
                var_name = self._get_variable_name(arg)
                
                # Check if argument is a taint source directly
                if self._is_taint_source(arg):
                    self.taint_flows.append({
                        'source': arg_repr,
                        'sink': sink_name,
                        'source_line': node.lineno,
                        'sink_line': node.lineno,
                        'severity': 'critical',
                        'type': 'direct'
                    })
                # Check if argument is a tainted variable
                elif var_name and var_name in self.current_tainted_vars:
                    source_line = self.var_assignments.get(var_name, node.lineno)
                    self.taint_flows.append({
                        'source': arg_repr,
                        'sink': sink_name,
                        'source_line': source_line,
                        'sink_line': node.lineno,
                        'severity': 'critical',
                        'type': 'variable_flow',
                        'tainted_var': var_name
                    })
        
        self.generic_visit(node)
    
    def _get_node_repr(self, node: ast.AST) -> str:
        """Get string representation of a node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if isinstance(node.value.value, ast.Name):
                    return f"{node.value.value.id}.{node.value.attr}[...]"
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return f"{node.func.id}(...)"
        elif isinstance(node, ast.BinOp):
            # For string concatenation like "echo " + user_command
            left = self._get_node_repr(node.left)
            right = self._get_node_repr(node.right)
            return f"{left} + {right}"
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Str):  # Python < 3.8
            return repr(node.s)
        
        return ast.dump(node)


def analyze(ast_tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Perform taint analysis on AST tree.
    
    Args:
        ast_tree: Root AST node
        
    Returns:
        List[Dict]: List of detected taint flows, each containing:
            - 'source': str - Taint source (e.g., 'sys.argv[1]')
            - 'sink': str - Taint sink (e.g., 'os.system')
            - 'source_line': int - Line number of source
            - 'sink_line': int - Line number of sink
            - 'severity': str - Severity level
            - 'type': str - Type of flow ('direct' or 'variable_flow')
    """
    if ast_tree is None:
        return []
    
    analyzer = TaintAnalyzer()
    analyzer.visit(ast_tree)
    
    return analyzer.taint_flows
