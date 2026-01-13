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
import multiprocessing as mp
import io
import contextlib
import queue
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
import traceback

# Add engines directory to path
sys.path.insert(0, r'{os.path.dirname(os.path.dirname(os.path.dirname(monitor_module)))}')

# Import and install hooks
from engines.dynamic.syscall_monitor import install_hooks

# Install hooks before importing target
install_hooks(r'{log_file}')
log_file = r'{log_file}'

# Now run the target file
target_file = r'{target_file}'
sys.argv = [target_file] + {repr(args)}
target_dir = os.path.dirname(target_file)
if target_dir and os.path.isdir(target_dir):
    sys.path.insert(0, target_dir)
    os.chdir(target_dir)

# Execute target file
with open(target_file, 'r', encoding='utf-8') as f:
    code = f.read()

try:
    exec(compile(code, target_file, 'exec'), {{'__name__': '__main__', '__file__': target_file}})
except Exception as exc:
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[ERROR] Unhandled exception: {{exc}}\\n")
            traceback.print_exc(file=f)
    except Exception:
        pass
    raise
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


def _drain_queue(log_queue: mp.Queue) -> List[str]:
    entries: List[str] = []
    try:
        while True:
            entries.append(log_queue.get_nowait())
    except queue.Empty:
        return entries


def _execute_with_hooks(
    file_path: str,
    args: List[str],
    log_queue: mp.Queue,
    result_queue: mp.Queue
) -> None:
    """Execute target file with hooks installed and send results back via queue."""
    from engines.dynamic.syscall_monitor import install_hooks
    file_path = os.path.abspath(file_path)
    target_dir = os.path.dirname(file_path)

    stdout_io = io.StringIO()
    stderr_io = io.StringIO()
    return_code = 0
    start_time = time.time()

    try:
        install_hooks(log_queue=log_queue)
        sys.argv = [file_path] + (args or [])
        if target_dir and os.path.isdir(target_dir):
            sys.path.insert(0, target_dir)
            os.chdir(target_dir)

        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()

        with contextlib.redirect_stdout(stdout_io), contextlib.redirect_stderr(stderr_io):
            exec(compile(code, file_path, 'exec'), {'__name__': '__main__', '__file__': file_path})
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return_code = exc.code
        else:
            return_code = 0
    except Exception:
        return_code = -1
        import traceback
        traceback.print_exc(file=stderr_io)

    execution_time = time.time() - start_time
    result_queue.put({
        'return_code': return_code,
        'stdout': stdout_io.getvalue(),
        'stderr': stderr_io.getvalue(),
        'execution_time': execution_time
    })


def run_in_sandbox(
    file_path: str,
    args: List[str] = None,
    timeout: int = 30,
    log_file: Optional[str] = None,
    log_mode: str = "queue"
) -> Dict[str, Any]:
    """
    Run target Python file in sandbox with hooks installed.
    
    Args:
        file_path: Path to target Python file
        args: Command line arguments to pass to target file
        timeout: Execution timeout in seconds
        log_file: Path to log file. If None, generates one automatically.
        log_mode: "queue" for in-memory logs, "file" for file logs
        
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
    
    if log_mode == "queue":
        log_queue: mp.Queue = mp.Queue()
        result_queue: mp.Queue = mp.Queue()
        worker = mp.Process(
            target=_execute_with_hooks,
            args=(file_path, args or [], log_queue, result_queue)
        )
        worker.start()
        worker.join(timeout)

        timed_out = False
        if worker.is_alive():
            timed_out = True
            worker.terminate()
            worker.join(1)

        result = {}
        try:
            if not result_queue.empty():
                result = result_queue.get_nowait()
        except Exception:
            result = {}

        log_entries = _drain_queue(log_queue)
        return {
            'return_code': result.get('return_code', -1),
            'stdout': result.get('stdout', ''),
            'stderr': result.get('stderr', f"Execution timed out after {timeout} seconds" if timed_out else ''),
            'execution_time': result.get('execution_time', float(timeout) if timed_out else 0.0),
            'log_file': '',
            'log_entries': log_entries,
            'timed_out': timed_out
        }

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


def run_direct(
    file_path: str,
    args: List[str] = None,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    Run target Python file directly (no hooks/sandbox).
    
    Args:
        file_path: Path to target Python file
        args: Command line arguments to pass to target file
        timeout: Execution timeout in seconds
        
    Returns:
        dict: Execution results containing:
            - 'return_code': int - Process return code
            - 'stdout': str - Standard output
            - 'stderr': str - Standard error
            - 'execution_time': float - Execution time in seconds
            - 'timed_out': bool - Whether execution timed out
    """
    if args is None:
        args = []
    
    file_path = os.path.abspath(file_path)
    target_dir = os.path.dirname(file_path)
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, file_path] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace',
            cwd=target_dir or None
        )
        execution_time = time.time() - start_time
        timed_out = False
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as exc:
        execution_time = timeout
        timed_out = True
        return_code = -1
        stdout = exc.stdout or ""
        stderr = exc.stderr or f"Execution timed out after {timeout} seconds"
    
    return {
        'return_code': return_code,
        'stdout': stdout,
        'stderr': stderr,
        'execution_time': execution_time,
        'timed_out': timed_out
    }
