#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
System Call Monitor
Core hooking logic using Monkey Patch to intercept dangerous system calls.
"""

import os
import socket
import subprocess
import sys
import traceback
from datetime import datetime
from typing import Optional, Callable, Any
import threading


class HookedRuntime:
    """Manages hooks for system calls and network operations."""
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize hook runtime.
        
        Args:
            log_file: Path to log file. If None, logs to stdout.
        """
        self.log_file = log_file
        self.log_lock = threading.Lock()
        self.hooks_installed = False
        
        # Store original functions
        self._original_system = None
        self._original_popen = None
        self._original_socket_connect = None
        self._original_subprocess_call = None
        self._original_subprocess_run = None
        self._original_subprocess_Popen = None
        self._original_open = None
        self._original_os_open = None
    
    def _log(self, message: str):
        """Write log entry to file or stdout."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message}\n"
        
        if self.log_file:
            try:
                with self.log_lock:
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(log_entry)
            except Exception as e:
                # Don't fail if logging fails
                sys.stderr.write(f"Logging error: {e}\n")
        else:
            sys.stdout.write(log_entry)
    
    def _get_call_stack(self) -> str:
        """Get simplified call stack for debugging."""
        try:
            stack = traceback.extract_stack()
            # Get last 3 frames (excluding this function)
            frames = stack[-4:-1] if len(stack) > 4 else stack[:-1]
            return " -> ".join([f"{f.filename}:{f.lineno}" for f in frames])
        except:
            return "unknown"
    
    def _hooked_system(self, command: str) -> int:
        """Hook for os.system()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] SYSCALL: os.system called with command='{command}' | stack={stack}")
        
        # Execute original function
        try:
            return self._original_system(command)
        except Exception as e:
            self._log(f"[ERROR] os.system execution failed: {e}")
            raise
    
    def _hooked_popen(self, command: str, mode: str = 'r', buffering: int = -1) -> Any:
        """Hook for os.popen()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] SYSCALL: os.popen called with command='{command}', mode='{mode}' | stack={stack}")
        
        try:
            return self._original_popen(command, mode, buffering)
        except Exception as e:
            self._log(f"[ERROR] os.popen execution failed: {e}")
            raise
    
    def _hooked_socket_connect(self, self_socket, address):
        """Hook for socket.socket.connect()."""
        stack = self._get_call_stack()
        addr_str = f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)
        self._log(f"[ALERT] NETWORK: socket.connect called with address='{addr_str}' | stack={stack}")
        
        try:
            return self._original_socket_connect(self_socket, address)
        except Exception as e:
            self._log(f"[ERROR] socket.connect execution failed: {e}")
            raise
    
    def _hooked_subprocess_call(self, *args, **kwargs) -> int:
        """Hook for subprocess.call()."""
        stack = self._get_call_stack()
        args_str = str(args) if args else ""
        kwargs_str = str(kwargs) if kwargs else ""
        self._log(f"[ALERT] SYSCALL: subprocess.call called with args={args_str}, kwargs={kwargs_str} | stack={stack}")
        
        try:
            return self._original_subprocess_call(*args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] subprocess.call execution failed: {e}")
            raise
    
    def _hooked_subprocess_run(self, *args, **kwargs) -> subprocess.CompletedProcess:
        """Hook for subprocess.run()."""
        stack = self._get_call_stack()
        args_str = str(args) if args else ""
        kwargs_str = str(kwargs) if kwargs else ""
        self._log(f"[ALERT] SYSCALL: subprocess.run called with args={args_str}, kwargs={kwargs_str} | stack={stack}")
        
        try:
            return self._original_subprocess_run(*args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] subprocess.run execution failed: {e}")
            raise
    
    def _hooked_subprocess_Popen(self, *args, **kwargs) -> subprocess.Popen:
        """Hook for subprocess.Popen()."""
        stack = self._get_call_stack()
        args_str = str(args) if args else ""
        kwargs_str = str(kwargs) if kwargs else ""
        self._log(f"[ALERT] SYSCALL: subprocess.Popen called with args={args_str}, kwargs={kwargs_str} | stack={stack}")
        
        try:
            return self._original_subprocess_Popen(*args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] subprocess.Popen execution failed: {e}")
            raise
    
    def _hooked_open(self, file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
        """Hook for builtin open() function."""
        stack = self._get_call_stack()
        file_path = str(file) if hasattr(file, '__str__') else file
        self._log(f"[ALERT] FILE OPEN: open() called with file='{file_path}', mode='{mode}' | stack={stack}")
        
        try:
            # Call original open
            if self._original_open:
                return self._original_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
            else:
                # Fallback to builtin open
                import builtins
                return builtins.open(file, mode, buffering, encoding, errors, newline, closefd, opener)
        except Exception as e:
            self._log(f"[ERROR] open() execution failed: {e}")
            raise
    
    def _hooked_os_open(self, path, flags, mode=0o777, *, dir_fd=None):
        """Hook for os.open()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] FILE OPEN: os.open() called with path='{path}', flags={flags}, mode={mode} | stack={stack}")
        
        try:
            return self._original_os_open(path, flags, mode, dir_fd=dir_fd)
        except Exception as e:
            self._log(f"[ERROR] os.open() execution failed: {e}")
            raise
    
    def install_hooks(self):
        """Install all hooks by replacing original functions."""
        if self.hooks_installed:
            return
        
        # Save original functions
        import builtins
        self._original_system = os.system
        self._original_popen = os.popen
        self._original_socket_connect = socket.socket.connect
        self._original_subprocess_call = subprocess.call
        self._original_subprocess_run = subprocess.run
        self._original_subprocess_Popen = subprocess.Popen
        self._original_open = builtins.open
        self._original_os_open = os.open
        
        # Replace with hooked versions
        os.system = self._hooked_system
        os.popen = self._hooked_popen
        socket.socket.connect = self._hooked_socket_connect
        subprocess.call = self._hooked_subprocess_call
        subprocess.run = self._hooked_subprocess_run
        subprocess.Popen = self._hooked_subprocess_Popen
        builtins.open = self._hooked_open
        os.open = self._hooked_os_open
        
        self.hooks_installed = True
        self._log("[INFO] Hooks installed successfully")
    
    def uninstall_hooks(self):
        """Uninstall all hooks by restoring original functions."""
        if not self.hooks_installed:
            return
        
        # Restore original functions
        import builtins
        if self._original_system:
            os.system = self._original_system
        if self._original_popen:
            os.popen = self._original_popen
        if self._original_socket_connect:
            socket.socket.connect = self._original_socket_connect
        if self._original_subprocess_call:
            subprocess.call = self._original_subprocess_call
        if self._original_subprocess_run:
            subprocess.run = self._original_subprocess_run
        if self._original_subprocess_Popen:
            subprocess.Popen = self._original_subprocess_Popen
        if self._original_open:
            builtins.open = self._original_open
        if self._original_os_open:
            os.open = self._original_os_open
        
        self.hooks_installed = False
        self._log("[INFO] Hooks uninstalled successfully")


# Global hook runtime instance (for module-level usage)
_hook_runtime: Optional[HookedRuntime] = None


def install_hooks(log_file: Optional[str] = None):
    """
    Install hooks at module level.
    
    Args:
        log_file: Path to log file
    """
    global _hook_runtime
    _hook_runtime = HookedRuntime(log_file)
    _hook_runtime.install_hooks()


def uninstall_hooks():
    """Uninstall hooks at module level."""
    global _hook_runtime
    if _hook_runtime:
        _hook_runtime.uninstall_hooks()
