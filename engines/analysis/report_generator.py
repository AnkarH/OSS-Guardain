#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Report Generator
Generates JSON and HTML reports from analysis results.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any


def generate_json_report(analysis_results: Dict[str, Any]) -> str:
    """
    Generate JSON format report.
    
    Args:
        analysis_results: Complete analysis results dictionary
        
    Returns:
        str: JSON formatted report string
    """
    report_data = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'tool': 'OSS-Guardian',
            'version': '1.0'
        },
        'analysis_results': analysis_results
    }
    
    return json.dumps(report_data, indent=2, ensure_ascii=False)


def generate_html_report(analysis_results: Dict[str, Any]) -> str:
    """
    生成 HTML 格式报告（中文版）
    
    Args:
        analysis_results: 完整的分析结果字典
        
    Returns:
        str: HTML 格式的报告字符串
    """
    if analysis_results.get('analysis_type') == 'batch':
        summary = analysis_results.get('summary', {})
        overall_risk = analysis_results.get('overall_risk', {})
        file_results = analysis_results.get('file_results', [])
        threats = analysis_results.get('aggregated_threats', [])
        avg_score = overall_risk.get('average_risk_score', 0)
        avg_level = overall_risk.get('average_risk_level', overall_risk.get('risk_level', 'low'))

        level_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        avg_level_cn = level_cn.get(avg_level, avg_level)

        rows = []
        for fr in file_results:
            dyn = fr.get('dynamic_summary', {}) or {}
            rows.append(
                f"<tr><td>{fr.get('file_path','')}</td>"
                f"<td>{fr.get('risk_score', 0)}</td>"
                f"<td>{fr.get('threat_count', 0)}</td>"
                f"<td>{dyn.get('syscalls',0)}/{dyn.get('network_activities',0)}/{dyn.get('file_activities',0)}/{dyn.get('memory_findings',0)}/{dyn.get('fuzz_results',0)}</td></tr>"
            )

        severity_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        threat_rows = []
        for threat in threats:
            line_numbers = threat.get('line_numbers', [])
            line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
            threat_rows.append(
                f"<tr><td>{threat.get('source_file','')}</td>"
                f"<td>{threat.get('threat_type','未知')}</td>"
                f"<td>{severity_cn.get(threat.get('severity','medium'), threat.get('severity','medium'))}</td>"
                f"<td>{line_str}</td></tr>"
            )

        threat_table = ""
        if threat_rows:
            threat_table = (
                "<table><thead><tr><th>文件</th><th>威胁类型</th><th>严重程度</th><th>行号</th></tr></thead>"
                f"<tbody>{''.join(threat_rows)}</tbody></table>"
            )
        else:
            threat_table = "<p>未发现威胁。</p>"

        return f"""<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OSS-Guardian 批量分析报告</title>
        <style>
            body {{ font-family: "Microsoft YaHei", "SimHei", Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>OSS-Guardian 批量分析报告</h1>
        <h2>汇总</h2>
        <ul>
            <li>总文件数: {summary.get('total_files', 0)}</li>
            <li>成功: {summary.get('successful', 0)}</li>
            <li>失败: {summary.get('failed', 0)}</li>
            <li>威胁总数: {summary.get('total_threats', 0)}</li>
            <li>平均风险分数: {avg_score:.2f}/100</li>
            <li>平均风险等级: {avg_level_cn}</li>
        </ul>
        <h2>文件结果</h2>
        <table>
            <thead>
                <tr>
                    <th>文件</th>
                    <th>风险分数</th>
                    <th>威胁数</th>
                    <th>动态(sys/net/file/mem/fuzz)</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        <h2>按文件汇总的威胁</h2>
        {threat_table}
    </body>
    </html>"""
    threats = analysis_results.get('threats', [])
    risk_assessment = analysis_results.get('risk_assessment', {})
    aggregated = analysis_results.get('aggregated_results', {})
    dynamic = aggregated.get('dynamic', {})
    has_dynamic = any([
        dynamic.get('syscalls'),
        dynamic.get('network_activities'),
        dynamic.get('file_activities'),
        dynamic.get('memory_findings'),
        dynamic.get('fuzz_results')
    ])
    dynamic_html = ""
    if has_dynamic:
        dynamic_html = "<h2>动态分析结果</h2><ul>"
        dynamic_html += f"<li>系统调用: {len(dynamic.get('syscalls', []))}</li>"
        dynamic_html += f"<li>网络活动: {len(dynamic.get('network_activities', []))}</li>"
        dynamic_html += f"<li>文件活动: {len(dynamic.get('file_activities', []))}</li>"
        dynamic_html += f"<li>内存分析: {len(dynamic.get('memory_findings', []))}</li>"
        dynamic_html += f"<li>模糊测试: {len(dynamic.get('fuzz_results', []))}</li>"
        dynamic_html += "</ul>"
        if dynamic.get('network_activities'):
            dynamic_html += "<h3>网络活动详情</h3><ul>"
            for activity in dynamic['network_activities']:
                activity_type = activity.get('type', 'unknown')
                activity_type_cn = '连接' if activity_type == 'connect' else '绑定' if activity_type == 'bind' else activity_type
                dynamic_html += f"<li>{activity_type_cn}: {activity.get('target', 'N/A')}</li>"
            dynamic_html += "</ul>"

    risk_score = risk_assessment.get('risk_score', 0)
    risk_level = risk_assessment.get('risk_level', 'low')
    threat_count = risk_assessment.get('threat_count', 0)
    
    # 风险等级中文映射
    risk_level_cn = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重'
    }
    
    # 根据风险等级确定颜色（灰蓝色主题）
    risk_color = {
        'critical': '#E74C3C',  # 红色
        'high': '#E67E22',      # 橙色
        'medium': '#F39C12',    # 黄色
        'low': '#27AE60'        # 绿色
    }.get(risk_level, '#6c757d')
    
    # 严重程度中文映射
    severity_cn = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    }
    
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSS-Guardian 安全分析报告</title>
    <style>
        body {{
            font-family: "Microsoft YaHei", "SimHei", Arial, sans-serif;
            margin: 20px;
            background-color: #F0F4F8;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(74, 144, 164, 0.15);
        }}
        h1 {{
            color: #2C3E50;
            border-bottom: 3px solid #4A90A4;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495E;
            margin-top: 30px;
        }}
        .risk-score {{
            text-align: center;
            padding: 30px;
            margin: 20px 0;
            background: linear-gradient(135deg, #4A90A4 0%, #6B9BD1 100%);
            color: white;
            border-radius: 8px;
            font-size: 48px;
            font-weight: bold;
            box-shadow: 0 4px 6px rgba(74, 144, 164, 0.2);
        }}
        .risk-level {{
            font-size: 24px;
            margin-top: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background-color: #F8FBFC;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4A90A4;
            box-shadow: 0 2px 4px rgba(74, 144, 164, 0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #2C3E50;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #4A90A4;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border: 1px solid #B8D4E3;
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #B8D4E3;
        }}
        th {{
            background-color: #4A90A4;
            color: white;
        }}
        tr:hover {{
            background-color: #F0F4F8;
        }}
        .severity-critical {{
            color: #E74C3C;
            font-weight: bold;
            background-color: #FDE8E8;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-high {{
            color: #E67E22;
            font-weight: bold;
            background-color: #FDF0E8;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-medium {{
            color: #F39C12;
            background-color: #FEF5E7;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-low {{
            color: #27AE60;
            background-color: #E8F8F0;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .evidence {{
            background-color: #F8FBFC;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: "Consolas", "Monaco", monospace;
            font-size: 12px;
            border-left: 3px solid #6B9BD1;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 12px;
            margin-top: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>OSS-Guardian 安全分析报告</h1>
        
        <div class="risk-score">
            风险分数：{risk_score}/100
            <div class="risk-level">风险等级：{risk_level_cn.get(risk_level, risk_level.upper())}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>威胁总数</h3>
                <div class="value">{threat_count}</div>
            </div>
            <div class="summary-card">
                <h3>严重</h3>
                <div class="value" style="color: #E74C3C;">{risk_assessment.get('breakdown', {}).get('critical', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>高危</h3>
                <div class="value" style="color: #E67E22;">{risk_assessment.get('breakdown', {}).get('high', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>中危</h3>
                <div class="value" style="color: #F39C12;">{risk_assessment.get('breakdown', {}).get('medium', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>低危</h3>
                <div class="value" style="color: #27AE60;">{risk_assessment.get('breakdown', {}).get('low', 0)}</div>
            </div>
        </div>
        
        <h2>已识别的威胁</h2>
        <table>
            <thead>
                <tr>
                    <th>威胁类型</th>
                    <th>严重程度</th>
                    <th>描述</th>
                    <th>行号</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for threat in threats:
        threat_type = threat.get('threat_type', '未知')
        severity = threat.get('severity', 'medium')
        description = threat.get('description', '')
        line_numbers = threat.get('line_numbers', [])
        line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
        severity_text = severity_cn.get(severity, severity.upper())
        
        severity_class = f'severity-{severity}'
        
        html += f"""
                <tr>
                    <td><strong>{threat_type}</strong></td>
                    <td class="{severity_class}">{severity_text}</td>
                    <td>{description}</td>
                    <td>{line_str}</td>
                </tr>
"""
    
    html += """
            </tbody>
        </table>
"""

    if dynamic_html:
        html += dynamic_html

    html += """
        <h2>详细证据</h2>
"""
    
    for i, threat in enumerate(threats, 1):
        threat_type = threat.get('threat_type', '未知')
        evidence = threat.get('evidence', [])
        
        html += f"""
        <h3>{i}. {threat_type}</h3>
        <div class="evidence">
"""
        for ev in evidence[:5]:  # 显示前5项证据
            html += f"<div>{json.dumps(ev, indent=2, ensure_ascii=False)}</div><br>"
        html += """
        </div>
"""
    
    html += f"""
        <div class="timestamp">
            报告生成时间：{datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""
    
    return html


def generate_markdown_report(analysis_results: Dict[str, Any]) -> str:
    """
    生成 Markdown 格式报告（中文版）
    
    Args:
        analysis_results: 完整的分析结果字典
        
    Returns:
        str: Markdown 格式的报告字符串
    """
    if analysis_results.get('analysis_type') == 'batch':
        summary = analysis_results.get('summary', {})
        overall_risk = analysis_results.get('overall_risk', {})
        file_results = analysis_results.get('file_results', [])
        threats = analysis_results.get('aggregated_threats', [])
        avg_score = overall_risk.get('average_risk_score', 0)
        avg_level = overall_risk.get('average_risk_level', overall_risk.get('risk_level', 'low'))

        level_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        avg_level_cn = level_cn.get(avg_level, avg_level)

        md = "# OSS-Guardian 批量分析报告\n\n"
        md += "## 汇总\n\n"
        md += f"- 总文件数: {summary.get('total_files', 0)}\n"
        md += f"- 成功: {summary.get('successful', 0)}\n"
        md += f"- 失败: {summary.get('failed', 0)}\n"
        md += f"- 威胁总数: {summary.get('total_threats', 0)}\n"
        md += f"- 平均风险分数: {avg_score:.2f}/100\n"
        md += f"- 平均风险等级: {avg_level_cn}\n\n"
        md += "## 文件结果\n\n"
        md += "| 文件 | 风险分数 | 威胁数 | 动态(sys/net/file/mem/fuzz) |\n"
        md += "|---|---:|---:|---|\n"
        for fr in file_results:
            dyn = fr.get('dynamic_summary', {}) or {}
            md += f"| {fr.get('file_path','')} | {fr.get('risk_score', 0)} | {fr.get('threat_count', 0)} | {dyn.get('syscalls',0)}/{dyn.get('network_activities',0)}/{dyn.get('file_activities',0)}/{dyn.get('memory_findings',0)}/{dyn.get('fuzz_results',0)} |\n"
        md += "\n## 按文件汇总的威胁\n\n"
        if threats:
            by_file = {}
            for threat in threats:
                src = threat.get('source_file', 'unknown')
                by_file.setdefault(src, []).append(threat)
            for src, items in by_file.items():
                md += f"### {src}\n"
                for t in items:
                    severity = t.get('severity', 'medium')
                    severity_text = level_cn.get(severity, severity)
                    line_numbers = t.get('line_numbers', [])
                    line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
                    md += f"- {t.get('threat_type','unknown')} ({severity_text}) 行号: {line_str}\n"
                md += "\n"
        else:
            md += "未发现威胁。\n"
        return md

    file_path = analysis_results.get('file_path', '未知文件')
    threats = analysis_results.get('threats', [])
    risk_assessment = analysis_results.get('risk_assessment', {})
    aggregated = analysis_results.get('aggregated_results', {})
    risk_score = risk_assessment.get('risk_score', 0)
    risk_level = risk_assessment.get('risk_level', 'low')
    threat_count = risk_assessment.get('threat_count', 0)
    
    # 风险等级中文映射
    risk_level_cn = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重'
    }
    
    # 严重程度中文映射
    severity_cn = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    }
    
    breakdown = risk_assessment.get('breakdown', {})
    
    md = f"""# OSS-Guardian 安全分析报告

## 报告信息

- **分析文件：** {file_path}
- **生成时间：** {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}
- **工具版本：** OSS-Guardian v1.0

---

## 风险评估概览

### 风险分数

**{risk_score}/100** - 风险等级：**{risk_level_cn.get(risk_level, risk_level.upper())}**

### 威胁统计

| 严重程度 | 数量 |
|---------|------|
| 严重 | {breakdown.get('critical', 0)} |
| 高危 | {breakdown.get('high', 0)} |
| 中危 | {breakdown.get('medium', 0)} |
| 低危 | {breakdown.get('low', 0)} |
| **总计** | **{threat_count}** |

---

## 已识别的威胁

"""
    
    if threats:
        for i, threat in enumerate(threats, 1):
            threat_type = threat.get('threat_type', '未知')
            severity = threat.get('severity', 'medium')
            severity_text = severity_cn.get(severity, severity.upper())
            description = threat.get('description', '')
            line_numbers = threat.get('line_numbers', [])
            line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
            
            md += f"""### {i}. {threat_type}

- **严重程度：** {severity_text}
- **描述：** {description}
- **行号：** {line_str}

"""
            
            # 添加证据信息
            evidence = threat.get('evidence', [])
            if evidence:
                md += "**证据信息：**\n\n"
                for j, ev in enumerate(evidence[:3], 1):  # 显示前3项证据
                    md += f"{j}. ```json\n{json.dumps(ev, indent=2, ensure_ascii=False)}\n```\n\n"
    else:
        md += "**未检测到威胁！代码相对安全。**\n\n"
    
    # 静态分析结果
    static = aggregated.get('static', {})
    if static.get('pattern_matches') or static.get('taint_flows'):
        md += """---

## 静态分析结果

"""
        md += f"- **模式匹配：** {len(static.get('pattern_matches', []))} 项\n"
        md += f"- **污点流：** {len(static.get('taint_flows', []))} 条\n"
        md += f"- **CFG 结构：** {len(static.get('cfg_structures', []))} 个\n"
        md += f"- **语法检查：** {'通过' if static.get('syntax_valid', True) else '失败'}\n\n"
    
    # 动态分析结果
    dynamic = aggregated.get('dynamic', {})
    if dynamic.get('syscalls') or dynamic.get('network_activities') or dynamic.get('file_activities') or dynamic.get('memory_findings') or dynamic.get('fuzz_results'):

        md += """---

## 动态分析结果

"""
        md += f"- **系统调用：** {len(dynamic.get('syscalls', []))} 条\n"
        md += f"- **网络活动：** {len(dynamic.get('network_activities', []))} 条\n"
        md += f"- **文件活动：** {len(dynamic.get('file_activities', []))} 条\n"
        md += f"- **内存分析：** {len(dynamic.get('memory_findings', []))} 条\n"
        md += f"- **模糊测试：** {len(dynamic.get('fuzz_results', []))} 条\n"
        
        if dynamic.get('network_activities'):
            md += "### 网络活动详情\n\n"
            for activity in dynamic['network_activities']:
                activity_type = activity.get('type', 'unknown')
                activity_type_cn = '连接' if activity_type == 'connect' else '绑定' if activity_type == 'bind' else activity_type
                md += f"- **{activity_type_cn}** 到 {activity.get('target', 'N/A')}\n"
            md += "\n"
    
    md += f"""---

## 报告说明

本报告由 OSS-Guardian 安全检测系统自动生成。

**风险等级说明：**
- **0-19 分（低）**：代码相对安全，只有少量低危问题
- **20-49 分（中）**：存在中等风险，建议审查
- **50-79 分（高）**：存在高风险，需要立即处理
- **80-100 分（严重）**：存在严重安全威胁，必须修复

---

*报告生成时间：{datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}*
"""
    
    return md


def save_report(
    report_content: str,
    file_path: str,
    format: str = 'json'
) -> str:
    """
    保存报告到文件
    
    Args:
        report_content: 报告内容字符串
        file_path: 保存报告的路径（目录不存在会自动创建）
        format: 报告格式 ('json', 'html', 或 'markdown')
        
    Returns:
        str: 保存的报告文件路径
    """
    # 确保目录存在
    report_dir = os.path.dirname(file_path)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    
    # 添加扩展名（如果不存在）
    if not file_path.endswith(f'.{format}'):
        file_path = f"{file_path}.{format}"
    
    # 写入报告
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return file_path
