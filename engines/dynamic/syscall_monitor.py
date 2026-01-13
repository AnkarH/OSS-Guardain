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
from engines.dynamic.file_monitor import FileMonitor


class HookedRuntime:
    """Manages hooks for system calls and network operations."""
    
    def __init__(self, log_file: Optional[str] = None, log_queue: Optional[Any] = None):
        """
        Initialize hook runtime.
        
        Args:
            log_file: Path to log file. If None, logs to stdout.
        """
        self.log_file = log_file
        self.log_queue = log_queue
        self.log_lock = threading.Lock()
        self.hooks_installed = False
        self._file_monitor = FileMonitor(None)
        
        # Store original functions
        self._original_system = None
        self._original_popen = None
        self._original_socket_connect = None
        self._original_socket_connect_ex = None
        self._original_socket_create_connection = None
        self._original_subprocess_call = None
        self._original_subprocess_run = None
        self._original_subprocess_Popen = None
        self._original_open = None
        self._original_os_open = None
        self._original_remove = None
        self._original_unlink = None
        self._original_eval = None
        self._original_exec = None
        self._original_compile = None
        self._original_ctypes_cdll = None
        self._original_ctypes_windll = None
        self._original_mmap = None
        self._ctypes_module = None
        self._mmap_module = None
    
    def _safe_open(self, *args, **kwargs):
        """Open files using the original open to avoid hook recursion."""
        open_func = self._original_open
        if open_func is None:
            import builtins
            open_func = builtins.open
        return open_func(*args, **kwargs)

    def _truncate_value(self, value: Any, limit: int = 200) -> str:
        """Limit log value length to keep logs readable."""
        try:
            text = value if isinstance(value, str) else str(value)
        except Exception:
            text = "<unprintable>"
        if len(text) <= limit:
            return text
        return text[:limit] + "...(truncated)"

    def _operation_from_mode(self, mode: str) -> str:
        mode = mode or ""
        if any(flag in mode for flag in ("w", "a", "+", "x")):
            return "write"
        return "read"

    def _operation_from_flags(self, flags: int) -> str:
        try:
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC):
                return "write"
        except Exception:
            pass
        return "read"

    def _is_sensitive_file(self, file_path: str) -> bool:
        return any(sensitive in file_path for sensitive in self._file_monitor.sensitive_files)

    def _log_file_operation(self, operation: str, file_path: str, mode: str = "", stack: str = ""):
        safe_path = self._truncate_value(file_path)
        level = "[ALERT]" if self._is_sensitive_file(file_path) else "[INFO]"
        stack_info = f" | stack={stack}" if stack else ""
        self._log(f"{level} FILE {operation.upper()}: {safe_path} (mode: {mode}){stack_info}")

    def _format_code_source(self, source: Any) -> str:
        if isinstance(source, bytes):
            try:
                return self._truncate_value(source.decode("utf-8", "replace"))
            except Exception:
                return "<bytes>"
        if isinstance(source, str):
            return self._truncate_value(source)
        if hasattr(source, "co_filename"):
            return f"code:{getattr(source, 'co_filename', '<unknown>')}"
        return f"<{type(source).__name__}>"

    def _log(self, message: str):
        """Write log entry to file or stdout."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {message}\n"
        
        if self.log_queue is not None:
            try:
                self.log_queue.put(log_entry)
            except Exception:
                pass
        elif self.log_file:
            try:
                with self.log_lock:
                    with self._safe_open(self.log_file, 'a', encoding='utf-8') as f:
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
    

    def _hooked_socket_connect_ex(self, self_socket, address):
        """Hook for socket.socket.connect_ex()."""
        stack = self._get_call_stack()
        addr_str = f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)
        self._log(f"[ALERT] NETWORK: socket.connect_ex called with address='{addr_str}' | stack={stack}")
        try:
            return self._original_socket_connect_ex(self_socket, address)
        except Exception as e:
            self._log(f"[ERROR] socket.connect_ex execution failed: {e}")
            raise

    def _hooked_socket_create_connection(self, *args, **kwargs):
        """Hook for socket.create_connection()."""
        stack = self._get_call_stack()
        address = args[0] if args else kwargs.get('address')
        addr_str = f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)
        self._log(f"[ALERT] NETWORK: socket.create_connection called with address='{addr_str}' | stack={stack}")
        try:
            return self._original_socket_create_connection(*args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] socket.create_connection execution failed: {e}")
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
        file_path = str(file) if hasattr(file, '__str__') else file
        operation = self._operation_from_mode(mode)
        self._log_file_operation(operation, file_path, mode, self._get_call_stack())
        
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
        operation = self._operation_from_flags(flags)
        self._log_file_operation(operation, str(path), str(flags), self._get_call_stack())
        
        try:
            return self._original_os_open(path, flags, mode, dir_fd=dir_fd)
        except Exception as e:
            self._log(f"[ERROR] os.open() execution failed: {e}")
            raise

    def _hooked_remove(self, path):
        """Hook for os.remove()."""
        self._log_file_operation("delete", str(path), "", self._get_call_stack())
        try:
            return self._original_remove(path)
        except Exception as e:
            self._log(f"[ERROR] os.remove execution failed: {e}")
            raise

    def _hooked_unlink(self, path):
        """Hook for os.unlink()."""
        self._log_file_operation("delete", str(path), "", self._get_call_stack())
        try:
            return self._original_unlink(path)
        except Exception as e:
            self._log(f"[ERROR] os.unlink execution failed: {e}")
            raise

    def _hooked_eval(self, source, globals=None, locals=None):
        """Hook for eval()."""
        if isinstance(source, (str, bytes)):
            stack = self._get_call_stack()
            source_preview = self._format_code_source(source)
            self._log(f"[ALERT] CODE_EXEC: eval called with source='{source_preview}' | stack={stack}")
        try:
            return self._original_eval(source, globals, locals)
        except Exception as e:
            self._log(f"[ERROR] eval execution failed: {e}")
            raise

    def _hooked_exec(self, source, globals=None, locals=None):
        """Hook for exec()."""
        if isinstance(source, (str, bytes)):
            stack = self._get_call_stack()
            source_preview = self._format_code_source(source)
            self._log(f"[ALERT] CODE_EXEC: exec called with source='{source_preview}' | stack={stack}")
        try:
            return self._original_exec(source, globals, locals)
        except Exception as e:
            self._log(f"[ERROR] exec execution failed: {e}")
            raise

    def _hooked_compile(self, source, filename, mode, flags=0, dont_inherit=False, optimize=-1):
        """Hook for compile()."""
        if isinstance(filename, str) and filename and os.path.exists(filename):
            return self._original_compile(source, filename, mode, flags, dont_inherit, optimize)
        stack = self._get_call_stack()
        source_preview = self._format_code_source(source)
        self._log(f"[ALERT] CODE_EXEC: compile called with source='{source_preview}', filename='{filename}', mode='{mode}' | stack={stack}")
        try:
            return self._original_compile(source, filename, mode, flags, dont_inherit, optimize)
        except Exception as e:
            self._log(f"[ERROR] compile execution failed: {e}")
            raise

    def _hooked_ctypes_cdll(self, name, *args, **kwargs):
        """Hook for ctypes.CDLL()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] MEMORY: ctypes.CDLL loaded '{name}' | stack={stack}")
        try:
            return self._original_ctypes_cdll(name, *args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] ctypes.CDLL failed: {e}")
            raise

    def _hooked_ctypes_windll(self, name, *args, **kwargs):
        """Hook for ctypes.WinDLL()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] MEMORY: ctypes.WinDLL loaded '{name}' | stack={stack}")
        try:
            return self._original_ctypes_windll(name, *args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] ctypes.WinDLL failed: {e}")
            raise

    def _hooked_mmap(self, *args, **kwargs):
        """Hook for mmap.mmap()."""
        stack = self._get_call_stack()
        self._log(f"[ALERT] MEMORY: mmap.mmap called with args={self._truncate_value(args)}, kwargs={self._truncate_value(kwargs)} | stack={stack}")
        try:
            return self._original_mmap(*args, **kwargs)
        except Exception as e:
            self._log(f"[ERROR] mmap.mmap failed: {e}")
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
        self._original_socket_connect_ex = socket.socket.connect_ex
        self._original_socket_create_connection = socket.create_connection
        self._original_subprocess_call = subprocess.call
        self._original_subprocess_run = subprocess.run
        self._original_subprocess_Popen = subprocess.Popen
        self._original_open = builtins.open
        self._original_os_open = os.open
        self._original_remove = os.remove
        self._original_unlink = os.unlink
        self._original_eval = builtins.eval
        self._original_exec = builtins.exec
        self._original_compile = builtins.compile
        
        # Replace with hooked versions
        os.system = self._hooked_system
        os.popen = self._hooked_popen
        socket.socket.connect = self._hooked_socket_connect
        socket.socket.connect_ex = self._hooked_socket_connect_ex
        socket.create_connection = self._hooked_socket_create_connection
        subprocess.call = self._hooked_subprocess_call
        subprocess.run = self._hooked_subprocess_run
        subprocess.Popen = self._hooked_subprocess_Popen
        builtins.open = self._hooked_open
        os.open = self._hooked_os_open
        os.remove = self._hooked_remove
        os.unlink = self._hooked_unlink
        builtins.eval = self._hooked_eval
        builtins.exec = self._hooked_exec
        builtins.compile = self._hooked_compile

        try:
            import ctypes
            self._ctypes_module = ctypes
            self._original_ctypes_cdll = ctypes.CDLL
            ctypes.CDLL = self._hooked_ctypes_cdll
            if hasattr(ctypes, "WinDLL"):
                self._original_ctypes_windll = ctypes.WinDLL
                ctypes.WinDLL = self._hooked_ctypes_windll
        except Exception:
            pass

        try:
            import mmap
            self._mmap_module = mmap
            self._original_mmap = mmap.mmap
            mmap.mmap = self._hooked_mmap
        except Exception:
            pass
        
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
        if self._original_socket_connect_ex:
            socket.socket.connect_ex = self._original_socket_connect_ex
        if self._original_socket_create_connection:
            socket.create_connection = self._original_socket_create_connection
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
        if self._original_remove:
            os.remove = self._original_remove
        if self._original_unlink:
            os.unlink = self._original_unlink
        if self._original_eval:
            builtins.eval = self._original_eval
        if self._original_exec:
            builtins.exec = self._original_exec
        if self._original_compile:
            builtins.compile = self._original_compile
        if self._ctypes_module and self._original_ctypes_cdll:
            self._ctypes_module.CDLL = self._original_ctypes_cdll
        if self._ctypes_module and self._original_ctypes_windll and hasattr(self._ctypes_module, "WinDLL"):
            self._ctypes_module.WinDLL = self._original_ctypes_windll
        if self._mmap_module and self._original_mmap:
            self._mmap_module.mmap = self._original_mmap
        
        self.hooks_installed = False
        self._log("[INFO] Hooks uninstalled successfully")


# Global hook runtime instance (for module-level usage)
_hook_runtime: Optional[HookedRuntime] = None


def install_hooks(log_file: Optional[str] = None, log_queue: Optional[Any] = None):
    """
    Install hooks at module level.
    
    Args:
        log_file: Path to log file
        log_queue: Optional multiprocessing queue for log entries
    """
    global _hook_runtime
    _hook_runtime = HookedRuntime(log_file, log_queue)
    _hook_runtime.install_hooks()


def uninstall_hooks():
    """Uninstall hooks at module level."""
    global _hook_runtime
    if _hook_runtime:
        _hook_runtime.uninstall_hooks()
