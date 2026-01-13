#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Main Controller
Orchestrates the complete security analysis workflow.
"""

import os
import yaml
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, Any, Optional

# Preprocessing imports
from engines.preprocessing.parser import read_file
from engines.preprocessing.ast_builder import build_ast
from engines.preprocessing.symbol_table import extract_symbols
from engines.preprocessing.ir_generator import generate as generate_ir
from engines.preprocessing.language_detector import detect_language, is_supported_language

# Go language imports
from engines.preprocessing.go_ast_builder import build_ast as build_go_ast
from engines.static.go_syntax_checker import check_syntax as check_go_syntax
from engines.static.go_taint_analysis import analyze as go_taint_analyze

# Java language imports
from engines.preprocessing.java_ast_builder import build_ast as build_java_ast
from engines.static.java_syntax_checker import check_syntax as check_java_syntax
from engines.static.java_taint_analysis import analyze as java_taint_analyze

# Static analysis imports
from engines.static.syntax_checker import check_syntax
from engines.static.pattern_matcher import match_patterns, load_rules_from_yaml
from engines.static.taint_analysis import analyze as taint_analyze
from engines.static.cfg_analysis import analyze as cfg_analyze

# Dynamic analysis imports
from engines.dynamic.sandbox import run_in_sandbox, run_direct
from engines.dynamic.network_monitor import analyze_network_activity
from engines.dynamic.fuzzer import fuzz_execution
from engines.dynamic.file_monitor import analyze_file_activity
from engines.dynamic.memory_analyzer import analyze_memory

# Analysis imports
from engines.analysis.aggregator import aggregate_results
from engines.analysis.threat_identifier import identify_threats
from engines.analysis.risk_assessor import assess_risk
from engines.analysis.report_generator import generate_json_report, generate_html_report, generate_markdown_report, save_report

# Dependency checking imports
from engines.static.dependency_checker import check_dependencies
from engines.static.cve_matcher import match_cve


def load_config(config_dir: str = 'config') -> Dict[str, Any]:
    """
    Load configuration from YAML files.
    
    Args:
        config_dir: Directory containing config files
        
    Returns:
        dict: Configuration dictionary
    """
    config = {}
    
    # Load settings
    settings_path = os.path.join(config_dir, 'settings.yaml')
    if os.path.exists(settings_path):
        with open(settings_path, 'r', encoding='utf-8') as f:
            config['settings'] = yaml.safe_load(f)
    else:
        config['settings'] = {
            'timeout': 30,
            'log_path': 'data/logs/',
            'report_path': 'data/reports/',
            'enable_dynamic_analysis': True,
            'enable_static_analysis': True,
            'enable_sandbox': True,
            'dynamic_timeout': 2,
            'dynamic_log_mode': 'queue',
            'parallel_analysis': True,
            'parallel_workers': None
        }
    
    # Load rules
    rules_path = os.path.join(config_dir, 'rules.yaml')
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            config['rules'] = yaml.safe_load(f)
    else:
        config['rules'] = {'rules': []}
    
    return config


def analyze_file(
    file_path: str,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Perform complete security analysis on a source code file.
    Supports Python, Go, and Java languages.
    
    Args:
        file_path: Path to target source file
        config: Optional configuration dictionary. If None, loads from config files.
        
    Returns:
        dict: Complete analysis results containing:
            - 'file_path': str
            - 'language': str - Detected language
            - 'static_results': dict
            - 'dynamic_results': dict
            - 'aggregated_results': dict
            - 'threats': list
            - 'risk_assessment': dict
            - 'reports': dict (JSON and HTML report paths)
    """
    if config is None:
        config = load_config()
    
    def is_effectively_empty(path: str) -> bool:
        """Return True if file has no code (only whitespace/comments)."""
        try:
            if os.path.getsize(path) == 0:
                return True
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith(('#', '//', '/*', '*', '*/')):
                        continue
                    return False
            return True
        except Exception:
            return False
    
    # Skip empty / comment-only files quickly
    if is_effectively_empty(file_path):
        print(f"[INFO] Skipping empty/comment-only file: {file_path}")
        return {
            'file_path': file_path,
            'language': 'unknown',
            'static_results': {},
            'dynamic_results': {},
            'aggregated_results': {},
            'threats': [],
            'risk_assessment': {},
            'reports': {},
            'skipped': True,
            'reason': 'empty or comment-only file'
        }
    
    settings = config.get('settings', {})
    rules_data = config.get('rules', {})
    
    enable_static = settings.get('enable_static_analysis', True)
    enable_dynamic = settings.get('enable_dynamic_analysis', True)
    enable_sandbox = settings.get('enable_sandbox', True)
    timeout = settings.get('timeout', 30)
    dynamic_timeout = min(settings.get('dynamic_timeout', 2), timeout)
    dynamic_log_mode = settings.get('dynamic_log_mode', 'queue')
    
    # Detect language
    language = detect_language(file_path)
    if not is_supported_language(language):
        raise ValueError(f"Unsupported language: {language}. Supported languages: Python, Go, Java")
    
    results = {
        'file_path': file_path,
        'language': language,
        'static_results': {},
        'dynamic_results': {},
        'aggregated_results': {},
        'threats': [],
        'risk_assessment': {},
        'reports': {}
    }
    
    try:
        # Step 1: Preprocessing
        print(f"[INFO] Reading file: {file_path}")
        print(f"[INFO] Detected language: {language}")
        source_code = read_file(file_path)
        
        # Language-specific preprocessing
        if language == 'python':
            print("[INFO] Building AST...")
            ast_tree = build_ast(source_code, filename=file_path)
            
            print("[INFO] Extracting symbols...")
            symbols = extract_symbols(ast_tree)
            
            print("[INFO] Generating IR...")
            ir = generate_ir(ast_tree)
        elif language == 'go':
            print("[INFO] Building Go AST...")
            ast_tree = build_go_ast(file_path)
            symbols = ast_tree.get('functions', []) + ast_tree.get('variables', [])
            ir = []  # Go IR generation can be added later
        elif language == 'java':
            print("[INFO] Building Java AST...")
            ast_tree = build_java_ast(file_path)
            symbols = ast_tree.get('classes', []) + ast_tree.get('methods', []) + ast_tree.get('variables', [])
            ir = []  # Java IR generation can be added later
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        # Step 2: Static Analysis
        if enable_static:
            print("[INFO] Performing static analysis...")
            
            # Language-specific static analysis
            if language == 'python':
                # Syntax check
                syntax_result = check_syntax(source_code, filename=file_path)
                
                # Pattern matching
                rules = load_rules_from_yaml(rules_data)
                pattern_matches = match_patterns(source_code, rules)
                
                # Taint analysis
                taint_flows = taint_analyze(ast_tree)
                
                # CFG analysis
                cfg_structures = cfg_analyze(ast_tree)
                
                # Dependency checking
                dependencies = check_dependencies(file_path, language)
                cve_matches = match_cve(dependencies) if dependencies else []
                
                results['static_results'] = {
                    'pattern_matches': pattern_matches,
                    'taint_flows': taint_flows,
                    'cfg_structures': cfg_structures,
                    'syntax_valid': syntax_result['valid'],
                    'syntax_errors': syntax_result.get('errors', []),
                    'symbols': symbols,
                    'ir': ir,
                    'dependencies': dependencies,
                    'cve_matches': cve_matches
                }
            elif language == 'go':
                # Go syntax check
                syntax_result = check_go_syntax(file_path)
                
                # Pattern matching (use same rules, filter by language if needed)
                rules = load_rules_from_yaml(rules_data)
                # Filter rules for Go or use all rules
                go_rules = [r for r in rules if r.get('language', 'python') in ['go', 'all', '']]
                pattern_matches = match_patterns(source_code, go_rules)
                
                # Go taint analysis
                taint_flows = go_taint_analyze(file_path)
                
                # CFG analysis for Go (simplified)
                cfg_structures = []  # Can be implemented later
                
                # Dependency checking
                dependencies = check_dependencies(file_path, language)
                cve_matches = match_cve(dependencies) if dependencies else []
                
                results['static_results'] = {
                    'pattern_matches': pattern_matches,
                    'taint_flows': taint_flows,
                    'cfg_structures': cfg_structures,
                    'syntax_valid': syntax_result['valid'],
                    'syntax_errors': syntax_result.get('errors', []),
                    'symbols': symbols,
                    'ir': ir,
                    'dependencies': dependencies,
                    'cve_matches': cve_matches
                }
            elif language == 'java':
                # Java syntax check
                syntax_result = check_java_syntax(file_path)
                
                # Pattern matching
                rules = load_rules_from_yaml(rules_data)
                # Filter rules for Java or use all rules
                java_rules = [r for r in rules if r.get('language', 'python') in ['java', 'all', '']]
                pattern_matches = match_patterns(source_code, java_rules)
                
                # Java taint analysis
                taint_flows = java_taint_analyze(file_path)
                
                # CFG analysis for Java (simplified)
                cfg_structures = []  # Can be implemented later
                
                # Dependency checking
                dependencies = check_dependencies(file_path, language)
                cve_matches = match_cve(dependencies) if dependencies else []
                
                results['static_results'] = {
                    'pattern_matches': pattern_matches,
                    'taint_flows': taint_flows,
                    'cfg_structures': cfg_structures,
                    'syntax_valid': syntax_result['valid'],
                    'syntax_errors': syntax_result.get('errors', []),
                    'symbols': symbols,
                    'ir': ir,
                    'dependencies': dependencies,
                    'cve_matches': cve_matches
                }
        else:
            results['static_results'] = {
                'pattern_matches': [],
                'taint_flows': [],
                'cfg_structures': [],
                'syntax_valid': True,
                'symbols': {},
                'ir': []
            }
        
        # Step 3: Dynamic Analysis
        # Note: Dynamic analysis currently only supports Python
        # Go and Java dynamic analysis would require different approaches
        if enable_dynamic and language == 'python':
            print("[INFO] Performing dynamic analysis...")
            
            # Run with hook runner; isolation is optional
            sandbox_result = run_in_sandbox(
                file_path=file_path,
                args=[],
                timeout=dynamic_timeout,
                log_mode=dynamic_log_mode
            )
            
            # Analyze network activity
            network_activities = []
            log_entries = sandbox_result.get('log_entries', [])
            if log_entries:
                network_activities = analyze_network_activity(log_entries)
            elif sandbox_result.get('log_file'):
                network_activities = analyze_network_activity(sandbox_result['log_file'])

            # Analyze file activity and memory signals
            file_activities = []
            memory_findings = []
            if log_entries:
                file_activities = analyze_file_activity(log_entries)
                memory_findings = analyze_memory(log_source=log_entries)
            elif sandbox_result.get('log_file'):
                file_activities = analyze_file_activity(sandbox_result['log_file'])
                memory_findings = analyze_memory(log_source=sandbox_result['log_file'])

            # Fuzz testing
            fuzz_results = fuzz_execution(
                file_path=file_path,
                num_tests=3,
                timeout=min(dynamic_timeout, 2),
                use_sandbox=True,
                log_mode=dynamic_log_mode
            )

            # Extract syscalls from log
            syscalls = []
            if sandbox_result.get('log_entries'):
                for entry in sandbox_result['log_entries']:
                    if '[ALERT] SYSCALL:' in entry or '[ALERT] NETWORK:' in entry:
                        syscalls.append(entry.strip())

            results['dynamic_results'] = {
                'syscalls': syscalls,
                'network_activities': network_activities,
                'file_activities': file_activities,
                'memory_findings': memory_findings,
                'fuzz_results': fuzz_results,
                'execution_log': sandbox_result.get('log_file', ''),
                'sandbox_result': sandbox_result
            }
            if not enable_sandbox:
                results['dynamic_results']['note'] = 'Sandbox disabled; hooks enabled without isolation.'
        elif enable_dynamic and language != 'python':
            # Dynamic analysis not yet supported for Go/Java
            print(f"[INFO] Dynamic analysis not yet supported for {language}, skipping...")
            results['dynamic_results'] = {
                'syscalls': [],
                'network_activities': [],
                'file_activities': [],
                'memory_findings': [],
                'fuzz_results': [],
                'execution_log': '',
                'note': f'Dynamic analysis not yet implemented for {language}'
            }
        else:
            results['dynamic_results'] = {
                'syscalls': [],
                'network_activities': [],
                'file_activities': [],
                'memory_findings': [],
                'fuzz_results': [],
                'execution_log': ''
            }
        
        # Step 4: Result Analysis
        print("[INFO] Aggregating results...")
        aggregated = aggregate_results(
            results['static_results'],
            results['dynamic_results']
        )
        results['aggregated_results'] = aggregated
        
        print("[INFO] Identifying threats...")
        threats = identify_threats(aggregated)
        results['threats'] = threats
        
        print("[INFO] Assessing risk...")
        risk_assessment = assess_risk(threats)
        results['risk_assessment'] = risk_assessment
        
        # Step 5: Generate Reports
        print("[INFO] Generating reports...")
        report_data = {
            'file_path': file_path,
            'aggregated_results': aggregated,
            'threats': threats,
            'risk_assessment': risk_assessment
        }
        
        # Generate JSON report
        json_report = generate_json_report(report_data)
        report_dir = settings.get('report_path', 'data/reports/')
        os.makedirs(report_dir, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        json_path = os.path.join(report_dir, f"{base_name}_{timestamp}.json")
        json_path = save_report(json_report, json_path, 'json')
        results['reports']['json'] = json_path
        
        # Generate HTML report
        html_report = generate_html_report(report_data)
        html_path = os.path.join(report_dir, f"{base_name}_{timestamp}.html")
        html_path = save_report(html_report, html_path, 'html')
        results['reports']['html'] = html_path
        
        # Generate Markdown report
        markdown_report = generate_markdown_report(report_data)
        markdown_path = os.path.join(report_dir, f"{base_name}_{timestamp}.md")
        markdown_path = save_report(markdown_report, markdown_path, 'markdown')
        results['reports']['markdown'] = markdown_path
        
        print(f"[SUCCESS] Analysis complete. Risk score: {risk_assessment['risk_score']}/100")
        
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        results['error'] = str(e)
    
    return results


def _analyze_file_worker(payload):
    """Helper for parallel analysis."""
    file_path, config = payload
    return file_path, analyze_file(file_path, config)


def analyze_multiple_files(
    file_paths: list,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    批量分析多个 Python 文件
    
    Args:
        file_paths: Python 文件路径列表
        config: Optional configuration dictionary. If None, loads from config files.
        
    Returns:
        dict: 批量分析结果，包含：
            - 'files_analyzed': int - 分析的文件数量
            - 'file_results': List[Dict] - 每个文件的分析结果
            - 'summary': dict - 汇总统计
            - 'aggregated_threats': List[Dict] - 所有威胁汇总
            - 'overall_risk': dict - 整体风险评估
    """
    if config is None:
        config = load_config()
    
    file_results = []
    all_threats = []
    total_risk_score = 0
    settings = config.get('settings', {})
    use_parallel = settings.get('parallel_analysis', True) and len(file_paths) > 1
    max_workers = settings.get('parallel_workers') or min(4, os.cpu_count() or 2)

    results_by_path = {}
    errors_by_path = {}

    if use_parallel:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_analyze_file_worker, (file_path, config)): file_path
                for file_path in file_paths
            }
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    _, result = future.result()
                    results_by_path[file_path] = result
                except Exception as e:
                    errors_by_path[file_path] = str(e)
    else:
        for i, file_path in enumerate(file_paths, 1):
            print(f"[INFO] Analyzing file {i}/{len(file_paths)}: {file_path}")
            try:
                result = analyze_file(file_path, config)
                results_by_path[file_path] = result
            except Exception as e:
                print(f"[ERROR] Failed to analyze {file_path}: {e}")
                errors_by_path[file_path] = str(e)

    for file_path in file_paths:
        if file_path in errors_by_path:
            file_results.append({
                'file_path': file_path,
                'result': None,
                'success': False,
                'error': errors_by_path[file_path]
            })
            continue

        result = results_by_path.get(file_path)
        if result is None:
            file_results.append({
                'file_path': file_path,
                'result': None,
                'success': False,
                'error': 'missing result'
            })
            continue

        if result.get('skipped'):
            file_results.append({
                'file_path': file_path,
                'result': result,
                'success': False,
                'error': result.get('reason', 'skipped')
            })
            continue

        file_results.append({
            'file_path': file_path,
            'result': result,
            'success': True
        })

        threats = result.get('threats', [])
        for threat in threats:
            threat['source_file'] = file_path
            all_threats.append(threat)

        risk_assessment = result.get('risk_assessment', {})
        total_risk_score += risk_assessment.get('risk_score', 0)

    # 汇总统计
    successful_analyses = [r for r in file_results if r['success']]
    failed_analyses = [r for r in file_results if not r['success']]
    
    # 整体风险评估
    if successful_analyses:
        avg_risk_score = total_risk_score / len(successful_analyses)
        overall_risk = assess_risk(all_threats)
        overall_risk['average_risk_score'] = avg_risk_score
        if avg_risk_score >= 80:
            overall_risk['average_risk_level'] = 'critical'
        elif avg_risk_score >= 50:
            overall_risk['average_risk_level'] = 'high'
        elif avg_risk_score >= 20:
            overall_risk['average_risk_level'] = 'medium'
        else:
            overall_risk['average_risk_level'] = 'low'
    else:
        overall_risk = {
            'risk_score': 0,
            'risk_level': 'low',
            'threat_count': 0,
            'breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'average_risk_score': 0
        }
    
    return {
        'files_analyzed': len(file_paths),
        'files_successful': len(successful_analyses),
        'files_failed': len(failed_analyses),
        'file_results': file_results,
        'aggregated_threats': all_threats,
        'overall_risk': overall_risk,
        'summary': {
            'total_files': len(file_paths),
            'successful': len(successful_analyses),
            'failed': len(failed_analyses),
            'total_threats': len(all_threats)
        }
    }


if __name__ == '__main__':
    # Example usage
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        results = analyze_file(file_path)
        print(f"\nRisk Score: {results['risk_assessment']['risk_score']}/100")
        print(f"Threats Found: {len(results['threats'])}")
    else:
        print("Usage: python main_controller.py <file_path>")
