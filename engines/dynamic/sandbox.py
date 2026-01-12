#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Sandbox Executor
Runs target code in a controlled environment with hooks installed.
"""

import os
import subprocess
import sys
import time
import tempfile
from typing import List, Dict, Any, Optional
from datetime import datetime


def _create_hook_runner_script(target_file: str, args: List[str], log_file: str) -> str:
    """
    Create a Python script that installs hooks and runs target file.
    
    Args:
        target_file: Path to target Python file
        args: Command line arguments
        log_file: Path to log file
        
    Returns:
        str: Path to created runner script
    """
    # Get absolute paths
    target_file = os.path.abspath(target_file)
    log_file = os.path.abspath(log_file)
    
    # Get the syscall_monitor module path
    monitor_module = os.path.abspath(os.path.join(
        os.path.dirname(__file__), 'syscall_monitor.py'
    ))
    
    # Create runner script content
    runner_content = f"""#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auto-generated hook runner script

import sys
import os

# Add engines directory to path
sys.path.insert(0, r'{os.path.dirname(os.path.dirname(os.path.dirname(monitor_module)))}')

# Import and install hooks
from engines.dynamic.syscall_monitor import install_hooks

# Install hooks before importing target
install_hooks(r'{log_file}')

# Now run the target file
target_file = r'{target_file}'
sys.argv = [target_file] + {repr(args)}

# Execute target file
with open(target_file, 'r', encoding='utf-8') as f:
    code = f.read()

exec(compile(code, target_file, 'exec'), {{'__name__': '__main__', '__file__': target_file}})
"""
    
    # Write runner script to temporary file
    fd, runner_path = tempfile.mkstemp(suffix='.py', prefix='hook_runner_', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(runner_content)
    except Exception as e:
        os.close(fd)
        raise RuntimeError(f"Failed to create runner script: {e}")
    
    return runner_path


def run_in_sandbox(
    file_path: str,
    args: List[str] = None,
    timeout: int = 30,
    log_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run target Python file in sandbox with hooks installed.
    
    Args:
        file_path: Path to target Python file
        args: Command line arguments to pass to target file
        timeout: Execution timeout in seconds
        log_file: Path to log file. If None, generates one automatically.
        
    Returns:
        dict: Execution results containing:
            - 'return_code': int - Process return code
            - 'stdout': str - Standard output
            - 'stderr': str - Standard error
            - 'execution_time': float - Execution time in seconds
            - 'log_file': str - Path to log file
            - 'log_entries': List[str] - Log entries
            - 'timed_out': bool - Whether execution timed out
    """
    if args is None:
        args = []
    
    # Generate log file path if not provided
    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        log_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'data', 'logs', f'sandbox_{timestamp}.log'
        )
    
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)
    
    # Create empty log file
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(f"[INFO] Sandbox execution started at {datetime.now()}\n")
        f.write(f"[INFO] Target file: {file_path}\n")
        f.write(f"[INFO] Arguments: {args}\n")
        f.write(f"[INFO] Timeout: {timeout}s\n\n")
    
    # Create hook runner script
    runner_script = None
    try:
        runner_script = _create_hook_runner_script(file_path, args, log_file)
        
        # Execute runner script
        start_time = time.time()
        try:
            result = subprocess.run(
                [sys.executable, runner_script],
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            execution_time = time.time() - start_time
            timed_out = False
        except subprocess.TimeoutExpired:
            execution_time = timeout
            timed_out = True
            result = subprocess.CompletedProcess(
                args=[sys.executable, runner_script],
                returncode=-1,
                stdout="",
                stderr=f"Execution timed out after {timeout} seconds"
            )
        
        # Read log entries
        log_entries = []
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_entries = f.readlines()
        except Exception as e:
            log_entries = [f"[ERROR] Failed to read log file: {e}\n"]
        
        return {
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'execution_time': execution_time,
            'log_file': log_file,
            'log_entries': log_entries,
            'timed_out': timed_out
        }
    
    finally:
        # Clean up runner script
        if runner_script and os.path.exists(runner_script):
            try:
                os.remove(runner_script)
            except:
                pass
