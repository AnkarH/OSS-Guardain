#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OSS-Guardian Streamlit Web Interface
提供用户友好的安全分析 Web 界面
"""

import streamlit as st
import os
import tempfile
import zipfile
import shutil
import uuid
from typing import List, Dict, Any
from main_controller import analyze_file, analyze_multiple_files, load_config

# Page configuration
st.set_page_config(
    page_title="OSS-Guardian 安全检测系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS - 增强的灰蓝色主题（更丰富的色彩）
st.markdown("""
    <style>
    /* 扩展的色彩方案 */
    :root {
        --primary-color: #4A90A4;
        --secondary-color: #6B9BD1;
        --accent-color: #5DADE2;
        --success-color: #27AE60;
        --warning-color: #F39C12;
        --danger-color: #E74C3C;
        --info-color: #3498DB;
        --purple-color: #9B59B6;
        --teal-color: #1ABC9C;
        --bg-color: #F0F4F8;
        --card-bg: #FFFFFF;
        --text-color: #2C3E50;
        --border-color: #B8D4E3;
    }
    
    /* 全局样式 - 渐变背景 */
    .main {
        background: linear-gradient(135deg, #F0F4F8 0%, #E8F0F5 50%, #F5F8FA 100%);
        min-height: 100vh;
    }
    
    /* 侧边栏样式 - 渐变背景 */
    .css-1d391kg {
        background: linear-gradient(180deg, #E8F0F5 0%, #D6E8F0 100%);
    }
    
    /* 卡片样式 - 增强阴影和渐变 */
    .stMetric {
        background: linear-gradient(135deg, #FFFFFF 0%, #F8FBFC 100%);
        padding: 20px;
        border-radius: 12px;
        border-left: 5px solid #4A90A4;
        box-shadow: 0 4px 12px rgba(74, 144, 164, 0.15), 
                    0 2px 4px rgba(74, 144, 164, 0.1);
        transition: all 0.3s ease;
    }
    
    .stMetric:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 20px rgba(74, 144, 164, 0.25), 
                    0 4px 8px rgba(74, 144, 164, 0.15);
    }
    
    /* 风险等级颜色 - 更丰富的渐变 */
    .risk-critical { 
        color: #E74C3C; 
        font-weight: bold; 
        background: linear-gradient(135deg, #FDE8E8 0%, #FAD5D5 100%);
        padding: 6px 12px;
        border-radius: 6px;
        border: 2px solid #E74C3C;
        box-shadow: 0 2px 4px rgba(231, 76, 60, 0.2);
    }
    .risk-high { 
        color: #E67E22; 
        font-weight: bold; 
        background: linear-gradient(135deg, #FDF0E8 0%, #FAE5D3 100%);
        padding: 6px 12px;
        border-radius: 6px;
        border: 2px solid #E67E22;
        box-shadow: 0 2px 4px rgba(230, 126, 34, 0.2);
    }
    .risk-medium { 
        color: #F39C12; 
        background: linear-gradient(135deg, #FEF5E7 0%, #FDEBD0 100%);
        padding: 6px 12px;
        border-radius: 6px;
        border: 2px solid #F39C12;
        box-shadow: 0 2px 4px rgba(243, 156, 18, 0.2);
    }
    .risk-low { 
        color: #27AE60; 
        background: linear-gradient(135deg, #E8F8F0 0%, #D5F4E6 100%);
        padding: 6px 12px;
        border-radius: 6px;
        border: 2px solid #27AE60;
        box-shadow: 0 2px 4px rgba(39, 174, 96, 0.2);
    }
    
    /* 标题样式 - 渐变文字 */
    h1 {
        color: #2C3E50;
        border-bottom: 4px solid;
        border-image: linear-gradient(90deg, #4A90A4 0%, #6B9BD1 50%, #5DADE2 100%) 1;
        padding-bottom: 12px;
        text-shadow: 0 2px 4px rgba(44, 62, 80, 0.1);
    }
    
    h2 {
        color: #34495E;
        background: linear-gradient(90deg, transparent 0%, #E8F0F5 50%, transparent 100%);
        padding: 8px 15px;
        border-radius: 6px;
        margin: 20px 0 15px 0;
    }
    
    h3 {
        color: #34495E;
        border-left: 4px solid #5DADE2;
        padding-left: 12px;
    }
    
    /* 按钮样式 - 渐变和3D效果 */
    .stButton > button {
        background: linear-gradient(135deg, #4A90A4 0%, #6B9BD1 100%);
        color: white;
        border-radius: 8px;
        border: none;
        padding: 10px 20px;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 8px rgba(74, 144, 164, 0.3),
                    inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #3A7A8A 0%, #5B8BC1 100%);
        transform: translateY(-3px);
        box-shadow: 0 6px 12px rgba(74, 144, 164, 0.4),
                    inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }
    
    .stButton > button:active {
        transform: translateY(-1px);
        box-shadow: 0 2px 4px rgba(74, 144, 164, 0.3);
    }
    
    /* 信息框样式 - 渐变背景 */
    .stInfo {
        background: linear-gradient(135deg, #E8F4F8 0%, #D6E8F0 100%);
        border-left: 5px solid #4A90A4;
        border-radius: 8px;
        box-shadow: 0 2px 6px rgba(74, 144, 164, 0.15);
    }
    
    /* 成功消息样式 */
    .stSuccess {
        background: linear-gradient(135deg, #E8F8F0 0%, #D5F4E6 100%);
        border-left: 5px solid #27AE60;
        border-radius: 8px;
        box-shadow: 0 2px 6px rgba(39, 174, 96, 0.15);
    }
    
    /* 错误消息样式 */
    .stError {
        background: linear-gradient(135deg, #FDE8E8 0%, #FAD5D5 100%);
        border-left: 5px solid #E74C3C;
        border-radius: 8px;
        box-shadow: 0 2px 6px rgba(231, 76, 60, 0.15);
    }
    
    /* 展开器样式 - 渐变背景 */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #F8FBFC 0%, #F0F4F8 100%);
        border-left: 4px solid #6B9BD1;
        border-radius: 6px;
        padding: 10px 15px;
        transition: all 0.3s ease;
    }
    
    .streamlit-expanderHeader:hover {
        background: linear-gradient(135deg, #F0F4F8 0%, #E8F0F5 100%);
        border-left-color: #5DADE2;
    }
    
    /* 表格样式 - 增强视觉效果 */
    .dataframe {
        border: 2px solid #B8D4E3;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 4px 12px rgba(74, 144, 164, 0.15);
    }
    
    .dataframe thead {
        background: linear-gradient(135deg, #4A90A4 0%, #6B9BD1 100%);
        color: white;
        font-weight: 600;
    }
    
    .dataframe tbody tr {
        transition: all 0.2s ease;
    }
    
    .dataframe tbody tr:hover {
        background: linear-gradient(90deg, #F0F4F8 0%, #E8F0F5 100%);
        transform: scale(1.01);
    }
    
    /* 下载按钮样式 */
    .stDownloadButton > button {
        background: linear-gradient(135deg, #3498DB 0%, #5DADE2 100%);
        color: white;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    
    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, #2980B9 0%, #4A90A4 100%);
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(52, 152, 219, 0.3);
    }
    
    /* 进度条样式 - 改为黄色系 */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #F4D03F 0%, #F5B041 50%, #F39C12 100%);
    }
    
    /* 代码块样式 */
    .stCodeBlock {
        border-radius: 8px;
        border: 2px solid #B8D4E3;
        box-shadow: 0 2px 8px rgba(74, 144, 164, 0.1);
    }
    
    /* 装饰元素 */
    .decorative-line {
        height: 3px;
        background: linear-gradient(90deg, transparent 0%, #4A90A4 20%, #6B9BD1 50%, #5DADE2 80%, transparent 100%);
        margin: 20px 0;
        border-radius: 2px;
    }

    /* 文档阅读器（威胁片段） */
    .doc-reader {
        background: linear-gradient(135deg, #FFFFFF 0%, #F8FBFC 100%);
        border: 1px solid rgba(184,212,227,0.85);
        border-radius: 12px;
        padding: 12px;
        margin: 10px 0 16px;
        box-shadow: 0 4px 10px rgba(44, 62, 80, 0.08);
    }
    .doc-reader-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 10px;
    }
    .doc-legend-item {
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: 600;
        color: #2C3E50;
        border: 1px solid rgba(0,0,0,0.08);
    }
    .doc-snippet {
        border: 1px solid rgba(184,212,227,0.6);
        border-radius: 8px;
        margin: 10px 0;
        overflow: hidden;
        background: #FFFFFF;
    }
    .doc-snippet-header {
        background: #E8F0F5;
        padding: 6px 10px;
        font-size: 12px;
        color: #2C3E50;
        border-bottom: 1px solid rgba(184,212,227,0.6);
    }
    .doc-code {
        font-family: Consolas, Monaco, monospace;
        font-size: 12px;
        line-height: 1.6;
        background: #F7FAFC;
        padding: 6px 0;
    }
    .doc-line {
        display: flex;
        padding: 2px 12px;
    }
    .doc-line-number {
        width: 48px;
        text-align: right;
        margin-right: 12px;
        color: #7F8C8D;
        user-select: none;
    }
    .doc-line-content {
        white-space: pre;
        color: #2C3E50;
    }
    .doc-line.threat-critical {
        background: #FFE6E6;
        border-left: 4px solid #E74C3C;
    }
    .doc-line.threat-high {
        background: #FFE8D6;
        border-left: 4px solid #E67E22;
    }
    .doc-line.threat-medium {
        background: #FFF4E6;
        border-left: 4px solid #F39C12;
    }
    .doc-line.threat-low {
        background: #E6F7E6;
        border-left: 4px solid #27AE60;
    }
    
    </style>
""", unsafe_allow_html=True)


def main():
    """主应用函数"""
    # 标题区域 - 增强的多色渐变
    st.markdown("""
    <div style="background: linear-gradient(135deg, #4A90A4 0%, #6B9BD1 30%, #5DADE2 60%, #3498DB 100%); 
                padding: 40px; 
                border-radius: 15px; 
                margin-bottom: 25px;
                box-shadow: 0 8px 16px rgba(74, 144, 164, 0.3),
                            0 4px 8px rgba(74, 144, 164, 0.2);
                border: 2px solid rgba(255, 255, 255, 0.2);">
        <h1 style="color: white; margin: 0; text-align: center; 
                   font-size: 42px; 
                   text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
                   font-weight: 700;">🛡️ OSS-Guardian</h1>
        <p style="color: #E8F0F5; text-align: center; margin: 15px 0 0 0; 
                  font-size: 20px; 
                  text-shadow: 0 1px 4px rgba(0, 0, 0, 0.2);
                  font-weight: 500;">开源软件安全检测系统</p>
        <div style="text-align: center; margin-top: 15px;">
            <span style="background: rgba(255, 255, 255, 0.2); 
                        padding: 5px 15px; 
                        border-radius: 20px; 
                        font-size: 14px; 
                        color: white;">静态分析 + 动态分析 + 威胁识别</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Load configuration
    config = load_config()
    
    # 初始化 session state
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'source_code' not in st.session_state:
        st.session_state.source_code = None
    if 'current_file_path' not in st.session_state:
        st.session_state.current_file_path = None
    if 'zip_temp_dirs' not in st.session_state:
        st.session_state.zip_temp_dirs = []
    if 'batch_results' not in st.session_state:
        st.session_state.batch_results = None
    if 'batch_extracted_files' not in st.session_state:
        st.session_state.batch_extracted_files = []
    
    # 侧边栏 - 文件上传
    st.sidebar.markdown("### 📁 文件上传")
    
    # 项目语言选择（可限制 ZIP/单文件的处理范围，避免误判）
    language_options = {
        "自动检测": None,
        "Python": "python",
        "Go": "go",
        "Java": "java"
    }
    language_choice = st.sidebar.selectbox(
        "项目语言",
        list(language_options.keys()),
        help="选择项目主要语言（ZIP 将按此过滤文件；单文件上传会限定扩展名）"
    )
    selected_language = language_options[language_choice]
    
    # 上传模式选择
    upload_mode = st.sidebar.radio(
        "上传模式",
        ["单个文件", "ZIP 压缩包"],
        help="选择上传单个源文件或包含多个文件的 ZIP 压缩包"
    )
    
    uploaded_file = None
    uploaded_zip = None
    
    if upload_mode == "单个文件":
        # 按语言限制可选扩展名，减少误选
        ext_map = {'python': ['py'], 'go': ['go'], 'java': ['java']}
        allowed_types = ['py', 'go', 'java'] if selected_language is None else ext_map.get(selected_language, ['py'])
        uploaded_file = st.sidebar.file_uploader(
            f"选择要分析的源文件",
            type=allowed_types,
            help="根据项目语言限制可选文件类型，避免误选"
        )
    else:
        uploaded_zip = st.sidebar.file_uploader(
            "选择 ZIP 压缩包",
            type=['zip'],
            help="上传包含源代码的 ZIP 压缩包（支持拖拽，按所选语言过滤）"
        )
    
    # 侧边栏 - 分析选项
    st.sidebar.markdown("### ⚙️ 分析选项")
    dynamic_default = config['settings'].get('enable_dynamic_analysis', True)
    # 批量模式默认关闭动态分析以提速，单文件沿用配置默认
    if upload_mode == "ZIP 压缩包":
        dynamic_default = False
    enable_static = st.sidebar.checkbox(
        "静态分析", 
        value=config['settings'].get('enable_static_analysis', True),
        help="启用静态代码分析（模式匹配、污点分析、CFG分析）"
    )
    enable_dynamic = st.sidebar.checkbox(
        "动态分析", 
        value=dynamic_default,
        help="启用动态行为分析（系统调用监控、网络监控、模糊测试）"
    )
    enable_sandbox = st.sidebar.checkbox(
        "启用沙箱执行",
        value=config['settings'].get('enable_sandbox', True),
        help="仅 Python 动态分析使用沙箱。关闭可跳过沙箱以提速，但缺少系统调用/网络监控。"
    )
    
    # Update config
    config['settings']['enable_static_analysis'] = enable_static
    config['settings']['enable_dynamic_analysis'] = enable_dynamic
    config['settings']['enable_sandbox'] = enable_sandbox
    
    # 分析按钮
    analyze_button = st.sidebar.button("🔍 开始分析", type="primary", use_container_width=True)
    clear_cache_clicked = st.sidebar.button("🧹 清除缓存", use_container_width=True, help="清除本地临时文件（reports/uploads/临时解压目录等）")
    if clear_cache_clicked:
        clear_local_cache(config)
        st.sidebar.success("已清除本地缓存和临时文件")
        st.rerun()

    
    # 处理 ZIP 文件上传
    extracted_files = []
    if uploaded_zip is not None:
        extracted_files = handle_zip_upload(uploaded_zip, selected_language)
    
    # 主内容区域
    if uploaded_file is not None:
        # 显示文件信息
        st.info(f"📄 **文件名称：** {uploaded_file.name} | **文件大小：** {uploaded_file.size} 字节")
        
        if analyze_button:
            # 保存上传的文件到临时位置
            with tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='w', encoding='utf-8') as tmp_file:
                tmp_file.write(uploaded_file.read().decode('utf-8'))
                tmp_file_path = tmp_file.name
            
            try:
                # 显示进度
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                status_text.info("🔄 正在启动分析...")
                progress_bar.progress(10)
                
                # 执行分析
                with st.spinner("⏳ 正在分析文件，请稍候..."):
                    results = analyze_file(tmp_file_path, config)
                
                progress_bar.progress(100)
                status_text.success("✅ 分析完成！")
                
                # 保存结果到 session state
                st.session_state.analysis_results = results
                st.session_state.current_file_path = tmp_file_path
                
                # 读取源代码
                with open(tmp_file_path, 'r', encoding='utf-8') as f:
                    st.session_state.source_code = f.read()
                
                # 显示结果
                display_results(results, tmp_file_path)
                
            except Exception as e:
                st.error(f"❌ 分析失败：{str(e)}")
                import traceback
                with st.expander("📋 错误详情"):
                    st.code(traceback.format_exc())
            finally:
                # 不立即删除，保留用于代码阅读器
                pass
        else:
            # 未重新点击分析时，继续展示已有结果
            if st.session_state.analysis_results and st.session_state.current_file_path:
                display_results(st.session_state.analysis_results, st.session_state.current_file_path)
    elif extracted_files:
        # 处理 ZIP 文件分析
        display_zip_files(extracted_files, config, analyze_button)
    # 如果没有新上传，但已有历史结果，则继续显示
    elif st.session_state.analysis_results:
        display_results(st.session_state.analysis_results, st.session_state.current_file_path)
    elif st.session_state.get('batch_results'):
        display_batch_results(st.session_state.batch_results, [], config)
    else:
        # 欢迎信息
        st.markdown("""
        <div style="background-color: #FFFFFF; padding: 30px; border-radius: 10px; border-left: 5px solid #4A90A4;">
            <h2 style="color: #2C3E50; margin-top: 0;">欢迎使用 OSS-Guardian</h2>
            <p style="color: #34495E; font-size: 16px; line-height: 1.8;">
                <strong>OSS-Guardian</strong> 是一个全面的开源软件安全分析工具，通过静态分析和动态分析相结合的方式，
                帮助您发现代码中的安全漏洞和恶意行为。
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # 功能特性卡片 - 增强的渐变和阴影
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #FFFFFF 0%, #F8FBFC 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        margin: 10px 0; 
                        border-left: 5px solid #4A90A4;
                        box-shadow: 0 4px 12px rgba(74, 144, 164, 0.15),
                                    0 2px 4px rgba(74, 144, 164, 0.1);
                        transition: all 0.3s ease;">
                <h3 style="color: #2C3E50; margin-top: 0; 
                          background: linear-gradient(90deg, #4A90A4 0%, #6B9BD1 100%);
                          -webkit-background-clip: text;
                          -webkit-text-fill-color: transparent;
                          font-size: 22px;">🔍 核心功能</h3>
                <ul style="color: #34495E; line-height: 2.2; font-size: 15px;">
                    <li style="margin: 8px 0;">✨ 静态代码分析（模式匹配、污点分析、CFG分析）</li>
                    <li style="margin: 8px 0;">🧪 动态行为分析（沙箱执行、网络监控、模糊测试）</li>
                    <li style="margin: 8px 0;">🎯 威胁识别和风险评估</li>
                    <li style="margin: 8px 0;">📊 详细的安全报告（JSON/HTML/Markdown）</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #FFFFFF 0%, #F0F8FF 100%); 
                        padding: 25px; 
                        border-radius: 12px; 
                        margin: 10px 0; 
                        border-left: 5px solid #6B9BD1;
                        box-shadow: 0 4px 12px rgba(107, 157, 209, 0.15),
                                    0 2px 4px rgba(107, 157, 209, 0.1);">
                <h3 style="color: #2C3E50; margin-top: 0;
                          background: linear-gradient(90deg, #6B9BD1 0%, #5DADE2 100%);
                          -webkit-background-clip: text;
                          -webkit-text-fill-color: transparent;
                          font-size: 22px;">🎯 检测能力</h3>
                <ul style="color: #34495E; line-height: 2.2; font-size: 15px;">
                    <li style="margin: 8px 0;">🕷️ WebShell 检测</li>
                    <li style="margin: 8px 0;">💉 SQL 注入检测</li>
                    <li style="margin: 8px 0;">⚡ RCE（远程代码执行）检测</li>
                    <li style="margin: 8px 0;">🔪 命令注入检测</li>
                    <li style="margin: 8px 0;">🚪 后门检测</li>
                    <li style="margin: 8px 0;">🌐 网络数据泄露检测</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        # 使用说明 - 增强样式
        st.markdown("""
        <div style="background: linear-gradient(135deg, #E8F4F8 0%, #D6E8F0 100%); 
                    padding: 25px; 
                    border-radius: 12px; 
                    margin: 20px 0;
                    border: 2px solid #B8D4E3;
                    box-shadow: 0 4px 12px rgba(74, 144, 164, 0.1);">
            <h3 style="color: #2C3E50; margin-top: 0; 
                      border-bottom: 2px solid #4A90A4; 
                      padding-bottom: 10px;">📖 使用说明</h3>
            <ol style="color: #34495E; line-height: 2.8; font-size: 16px;">
                <li style="margin: 10px 0; padding-left: 10px;">在左侧边栏上传 Python/Java/Go 源代码文件或 ZIP 压缩包</li>
                <li style="margin: 10px 0; padding-left: 10px;">配置分析选项（静态分析/动态分析）</li>
                <li style="margin: 10px 0; padding-left: 10px;">点击"开始分析"按钮启动分析</li>
                <li style="margin: 10px 0; padding-left: 10px;">查看分析结果、威胁位置高亮和下载报告</li>
            </ol>
        </div>
        """, unsafe_allow_html=True)
        
        # 示例文件
        with st.expander("📝 示例：使用测试文件"):
            st.code("""
# 您可以使用项目自带的测试文件进行测试
# 测试文件位置：tests/malware_demo.py
# 综合测试文件：tests/test_comprehensive.py
            """, language='python')


def handle_zip_upload(uploaded_zip, selected_language: str = None) -> List[Dict[str, str]]:
    """
    处理 ZIP 文件上传，解压并提取支持的语言文件（Python, Go, Java）
    
    Args:
        uploaded_zip: 上传的 ZIP 文件对象
        selected_language: 指定的项目语言（python/go/java）；为 None 时自动检测全量保留
        
    Returns:
        List[Dict]: 提取的文件列表，每个元素包含 'path', 'name', 'language'
    """
    extracted_files = []
    
    try:
        # 创建本地 data 上传目录
        base_upload_dir = os.path.join("data", "uploads")
        os.makedirs(base_upload_dir, exist_ok=True)
        temp_dir = os.path.join(base_upload_dir, f"zip_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        zip_path = os.path.join(temp_dir, uploaded_zip.name)
        
        # 保存 ZIP 文件
        with open(zip_path, 'wb') as f:
            f.write(uploaded_zip.getbuffer())
        
        # 解压 ZIP 文件
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # 支持的文件扩展名
        supported_extensions = ['.py', '.go', '.java']
        allowed_lang = selected_language  # None 表示保留全部支持语言
        
        # 统计各语言文件数量
        file_counts = {'python': 0, 'go': 0, 'java': 0}
        
        # 查找所有支持的文件
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_ext = os.path.splitext(file)[1].lower()
                if file_ext in supported_extensions:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, temp_dir)
                    
                    # 检测语言
                    from engines.preprocessing.language_detector import detect_language
                    language = detect_language(file_path)
                    
                    # 若用户指定了语言，则仅保留该语言文件
                    if allowed_lang and language != allowed_lang:
                        continue
                    
                    extracted_files.append({
                        'path': file_path,
                        'name': relative_path,
                        'language': language,
                        'temp_dir': temp_dir
                    })
                    
                    if language in file_counts:
                        file_counts[language] += 1
        
        # 保存临时目录到 session state
        if 'zip_temp_dirs' not in st.session_state:
            st.session_state.zip_temp_dirs = []
        st.session_state.zip_temp_dirs.append(temp_dir)
        
    except Exception as e:
        st.error(f"❌ ZIP 文件处理失败：{str(e)}")
    
    return extracted_files


def cleanup_temp_dirs(temp_dirs):
    """删除临时解压目录"""
    for d in temp_dirs:
        if d and os.path.exists(d):
            shutil.rmtree(d, ignore_errors=True)

def clear_local_cache(config: Dict):
    """清理本地缓存和临时文件（reports/uploads/解压目录）"""
    temp_file_path = st.session_state.get('current_file_path')
    if temp_file_path and os.path.exists(temp_file_path):
        try:
            os.remove(temp_file_path)
        except Exception:
            pass

    temp_dirs = set(st.session_state.get('zip_temp_dirs') or [])
    for file_info in st.session_state.get('batch_extracted_files', []) or []:
        temp_dir = file_info.get('temp_dir')
        if temp_dir:
            temp_dirs.add(temp_dir)
    cleanup_temp_dirs(temp_dirs)

    upload_dir = os.path.join("data", "uploads")
    if os.path.isdir(upload_dir):
        shutil.rmtree(upload_dir, ignore_errors=True)

    report_dir = config.get('settings', {}).get('report_path', 'data/reports/')
    if report_dir and os.path.isdir(report_dir):
        shutil.rmtree(report_dir, ignore_errors=True)

    st.session_state.analysis_results = None
    st.session_state.source_code = None
    st.session_state.current_file_path = None
    st.session_state.zip_temp_dirs = []
    st.session_state.batch_results = None
    st.session_state.batch_extracted_files = []
    st.session_state.selected_files = set()

    for key in list(st.session_state.keys()):
        if key.startswith("file_checkbox_"):
            del st.session_state[key]


def display_zip_files(extracted_files: List[Dict], config: Dict, analyze_button: bool):
    """显示 ZIP 文件中的文件列表并支持批量分析"""
    # 统计各语言文件数量
    lang_counts = {}
    for f in extracted_files:
        lang = f.get('language', 'unknown')
        lang_counts[lang] = lang_counts.get(lang, 0) + 1
    
    lang_info = ', '.join([f"{count} 个 {lang.upper()}" for lang, count in lang_counts.items()])
    st.info(f"📦 **ZIP 文件已解压，发现 {len(extracted_files)} 个文件** ({lang_info})")
    
    # 文件选择
    st.markdown("### 📋 选择要分析的文件")
    
    # 初始化选中状态
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = set()
    
    # 全选/取消全选按钮
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("全选", key="select_all_btn"):
            st.session_state.selected_files = set(range(len(extracted_files)))
            # 需要同时更新每个复选框的状态，否则 Streamlit 会保留旧值
            for i in range(len(extracted_files)):
                st.session_state[f"file_checkbox_{i}"] = True
            st.rerun()
    with col2:
        if st.button("取消全选", key="deselect_all_btn"):
            st.session_state.selected_files = set()
            for i in range(len(extracted_files)):
                st.session_state[f"file_checkbox_{i}"] = False
            st.rerun()
    
    # 文件列表
    selected_indices = []
    for i, file_info in enumerate(extracted_files):
        lang = file_info.get('language', 'unknown')
        lang_icon = {'python': '🐍', 'go': '🐹', 'java': '☕'}.get(lang, '📄')
        is_selected = st.checkbox(
            f"{lang_icon} {file_info['name']} ({lang.upper()})",
            value=i in st.session_state.selected_files,
            key=f"file_checkbox_{i}"
        )
        if is_selected:
            selected_indices.append(i)
    
    # 更新选中状态
    st.session_state.selected_files = set(selected_indices)
    
    # 执行批量分析
    if analyze_button and selected_indices:
        selected_files = [extracted_files[i]['path'] for i in selected_indices]
        
        with st.spinner(f"⏳ 正在分析 {len(selected_files)} 个文件，请稍候..."):
            batch_results = analyze_multiple_files(selected_files, config)
            st.session_state.batch_results = batch_results
            st.session_state.batch_extracted_files = extracted_files
            display_batch_results(batch_results, extracted_files, config)
            # 分析结束，清理解压目录
            temp_dirs = {f.get('temp_dir') for f in extracted_files}
            cleanup_temp_dirs(temp_dirs)
            st.session_state.zip_temp_dirs = []
    elif st.session_state.get('batch_results'):
        # 未再次点击分析，但已有历史结果，继续展示
        display_batch_results(st.session_state.batch_results, st.session_state.get('batch_extracted_files', extracted_files), config)


def display_batch_results(batch_results: Dict, extracted_files: List[Dict], config: Dict):
    """显示批量分析结果"""
    unique_suffix = str(uuid.uuid4())[:8]
    st.markdown("---")
    st.markdown("### 📊 批量分析结果汇总")
    
    summary = batch_results.get('summary', {})
    overall_risk = batch_results.get('overall_risk', {})
    
    # 汇总统计
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("总文件数", summary.get('total_files', 0))
    col2.metric("成功分析", summary.get('successful', 0))
    col3.metric("分析失败", summary.get('failed', 0))
    col4.metric("发现威胁", summary.get('total_threats', 0))
    
    # 每个文件的报告下载（为避免重复 key，使用索引+文件名）
    successful_files = [r for r in batch_results.get('file_results', []) if r.get('success') and r.get('result')]
    if False and successful_files:
        st.markdown("### 📥 报告下载（单文件）")
        for idx, file_result in enumerate(successful_files):
            result = file_result.get('result', {})
            reports = result.get('reports', {})
            file_label = os.path.basename(file_result.get('file_path', '未知'))
            with st.expander(f"{file_label} 报告"):
                cols = st.columns(3)
                if reports.get('json'):
                    with open(reports['json'], 'r', encoding='utf-8') as f:
                        json_content = f.read()
                    cols[0].download_button(
                        label="📄 JSON",
                        data=json_content,
                        file_name=os.path.basename(reports['json']),
                        mime="application/json",
                        key=f"{unique_suffix}_dl_json_{idx}_{file_label}"
                    )
                if reports.get('html'):
                    with open(reports['html'], 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    cols[1].download_button(
                        label="🌐 HTML",
                        data=html_content,
                        file_name=os.path.basename(reports['html']),
                        mime="text/html",
                        key=f"{unique_suffix}_dl_html_{idx}_{file_label}"
                    )
                if reports.get('markdown'):
                    with open(reports['markdown'], 'r', encoding='utf-8') as f:
                        markdown_content = f.read()
                    cols[2].download_button(
                        label="📝 Markdown",
                        data=markdown_content,
                        file_name=os.path.basename(reports['markdown']),
                        mime="text/markdown",
                        key=f"{unique_suffix}_dl_md_{idx}_{file_label}"
                    )
    
    # 整体风险评估
    st.markdown("### 🎯 整体风险评估")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("平均风险分数", f"{overall_risk.get('average_risk_score', 0):.1f}/100")
    with col2:
        risk_level = overall_risk.get('risk_level', 'low')
        risk_level_cn = {'low': '低', 'medium': '中', 'high': '高', 'critical': '严重'}.get(risk_level, risk_level)
        st.metric("整体风险等级", risk_level_cn)

    # 威胁分布饼图
    all_threats = batch_results.get('aggregated_threats', [])
    if all_threats:
        severity_counts = {}
        for t in all_threats:
            sev = t.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 中文映射与配色
        severity_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危',
            'unknown': '未知'
        }
        colors = {
            '严重': '#E74C3C',
            '高危': '#E67E22',
            '中危': '#F1C40F',
            '低危': '#27AE60',
            '未知': '#7F8C8D'
        }

        labels = [severity_cn.get(k, '未知') for k in severity_counts.keys()]
        values = list(severity_counts.values())

        # 清爽浅色卡片风格，与页面整体配色一致
        pie_css = """
        <style>
        .threat-pie-title {
            color: #2C3E50;
            font-weight: 700;
            margin: 0;
            font-size: 18px;
            letter-spacing: 0.2px;
        }
        /* 通过 marker 选择相邻组件，让标题 + 图表看起来是同一个面板 */
        div[data-testid="stElementContainer"]:has(#threat-pie-marker) + div[data-testid="stElementContainer"],
        div[data-testid="stElementContainer"]:has(#threat-pie-marker) + div[data-testid="stElementContainer"] + div[data-testid="stElementContainer"] {
            background: linear-gradient(135deg, #FFFFFF 0%, #F8FBFC 100%);
            border: 1px solid rgba(184,212,227,0.9);
            box-shadow: 0 6px 16px rgba(44,62,80,0.08);
        }
        div[data-testid="stElementContainer"]:has(#threat-pie-marker) + div[data-testid="stElementContainer"] {
            border-bottom: none;
            border-radius: 14px 14px 0 0;
            padding: 12px 16px 6px;
        }
        div[data-testid="stElementContainer"]:has(#threat-pie-marker) + div[data-testid="stElementContainer"] + div[data-testid="stElementContainer"] {
            border-top: none;
            border-radius: 0 0 14px 14px;
            padding: 0 10px 12px;
        }
        </style>
        """
        st.markdown(pie_css, unsafe_allow_html=True)
        st.markdown('<div id="threat-pie-marker"></div>', unsafe_allow_html=True)
        st.markdown('<div class="threat-pie-title">威胁分布</div>', unsafe_allow_html=True)

        try:
            import plotly.express as px
            fig = px.pie(
                names=labels,
                values=values,
                color=labels,
                color_discrete_map=colors,
                hole=0.2
            )
            # 轻量动感效果，避免过度装饰
            fig.update_traces(
                pull=[0.02 + 0.01*i for i in range(len(labels))],
                marker=dict(
                    line=dict(color="#FFFFFF", width=2)
                ),
                opacity=0.95,
                hovertemplate='%{label}: %{value} 个 (%{percent})'
            )
            fig.update_layout(
                legend_title="威胁等级",
                legend=dict(orientation="h", y=-0.2, x=0),
                margin=dict(t=10, b=60, l=10, r=10),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#2C3E50", size=12)
            )
            st.plotly_chart(fig, use_container_width=True, config={"displaylogo": False})
        except Exception as e:
            st.warning(f"Plotly 未安装或渲染失败，改用备用图表。错误：{e}")
            try:
                import altair as alt
                import pandas as pd
                df = pd.DataFrame({
                    "等级": labels,
                    "数量": values
                })
                chart = alt.Chart(df).mark_arc(innerRadius=30).encode(
                    theta="数量",
                    color=alt.Color("等级", scale=alt.Scale(domain=list(colors.keys()), range=list(colors.values()))),
                    tooltip=["等级", "数量"]
                ).properties(title="威胁分布")
                st.altair_chart(chart, use_container_width=True)
            except Exception:
                st.write("威胁分布：", dict(zip(labels, values)))

    
    # 所有威胁列表
    all_threats = batch_results.get('aggregated_threats', [])
    if all_threats:
        st.markdown("### 🚨 所有威胁汇总")
        
        severity_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        
        threat_data = []
        for threat in all_threats:
            severity = threat.get('severity', 'medium')
            threat_data.append({
                '文件': os.path.basename(threat.get('source_file', '未知')),
                '威胁类型': threat.get('threat_type', '未知'),
                '严重程度': severity_cn.get(severity, severity.upper()),
                '行号': ', '.join(map(str, threat.get('line_numbers', []))) or 'N/A'
            })
        
        st.dataframe(threat_data, use_container_width=True)

    # 各文件详细结果
    st.markdown("### 📄 各文件分析结果")
    file_results = batch_results.get('file_results', [])
    
    for file_result in file_results:
        file_path = file_result.get('file_path', '未知')
        file_name = os.path.basename(file_path)
        
        with st.expander(f"📄 {file_name}"):
            if file_result.get('success'):
                result = file_result.get('result', {})
                risk_assessment = result.get('risk_assessment', {})
                threats = result.get('threats', [])
                
                st.write(f"**风险分数：** {risk_assessment.get('risk_score', 0)}/100")
                st.write(f"**发现威胁：** {len(threats)} 个")
                
                if threats:
                    for threat in threats:
                        st.write(f"- **{threat.get('threat_type', '未知')}** (严重程度: {threat.get('severity', 'medium')})")
                    
                    with st.expander("📖 文档阅读器（威胁片段）"):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                source_code = f.read()
                            render_threat_snippet_reader(source_code, threats)
                        except Exception as e:
                            st.warning(f"加载源码失败，无法展示片段：{e}")
            else:
                st.error(f"分析失败：{file_result.get('error', '未知错误')}")
    
    st.markdown("---")
    st.markdown("### 📥 下载批量分析报告")
    
    # 生成汇总报告
    if batch_results:
        # 创建汇总报告数据
        summary_report_data = {
            'analysis_type': 'batch',
            'summary': batch_results.get('summary', {}),
            'overall_risk': batch_results.get('overall_risk', {}),
            'aggregated_threats': batch_results.get('aggregated_threats', []),
            'file_results': [
                {
                    'file_path': fr.get('file_path'),
                    'risk_score': fr.get('result', {}).get('risk_assessment', {}).get('risk_score', 0) if fr.get('success') else 0,
                    'threat_count': len(fr.get('result', {}).get('threats', [])) if fr.get('success') else 0
                }
                for fr in batch_results.get('file_results', [])
            ]
        }
        
        # 生成报告
        from engines.analysis.report_generator import generate_json_report, generate_html_report, generate_markdown_report
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = config.get('settings', {}).get('report_path', 'data/reports/')
        os.makedirs(report_dir, exist_ok=True)
        
        col1, col2, col3 = st.columns(3)
        
        # JSON 报告
        json_report = generate_json_report(summary_report_data)
        json_path = os.path.join(report_dir, f"batch_analysis_{timestamp}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(json_report)
        with open(json_path, 'r', encoding='utf-8') as f:
            json_content = f.read()
        col1.download_button(
            label="📄 下载 JSON 汇总报告",
            data=json_content,
            file_name=f"batch_analysis_{timestamp}.json",
            mime="application/json",
            key=f"{unique_suffix}_batch_json"
        )
        
        # HTML 报告
        html_report = generate_html_report(summary_report_data)
        html_path = os.path.join(report_dir, f"batch_analysis_{timestamp}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        col2.download_button(
            label="🌐 下载 HTML 汇总报告",
            data=html_content,
            file_name=f"batch_analysis_{timestamp}.html",
            mime="text/html",
            key=f"{unique_suffix}_batch_html"
        )
        
        # Markdown 报告
        markdown_report = generate_markdown_report(summary_report_data)
        markdown_path = os.path.join(report_dir, f"batch_analysis_{timestamp}.md")
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(markdown_report)
        with open(markdown_path, 'r', encoding='utf-8') as f:
            markdown_content = f.read()
        col3.download_button(
            label="📝 下载 Markdown 汇总报告",
            data=markdown_content,
            file_name=f"batch_analysis_{timestamp}.md",
            mime="text/markdown",
            key=f"{unique_suffix}_batch_md"
        )


def build_threat_line_map(threats: List[Dict]) -> Dict[int, List[Dict[str, str]]]:
    """构建威胁行号映射"""
    threat_lines: Dict[int, List[Dict[str, str]]] = {}
    for threat in threats:
        severity = threat.get('severity', 'medium')
        threat_type = threat.get('threat_type', '未知')
        for line_num in threat.get('line_numbers', []) or []:
            try:
                line_int = int(line_num)
            except (TypeError, ValueError):
                continue
            if line_int <= 0:
                continue
            threat_lines.setdefault(line_int, []).append({
                'type': threat_type,
                'severity': severity
            })
    return threat_lines


def merge_context_ranges(line_numbers: List[int], total_lines: int, context_lines: int) -> List[tuple]:
    """合并威胁行上下文范围"""
    ranges = []
    for ln in line_numbers:
        start = max(1, ln - context_lines)
        end = min(total_lines, ln + context_lines)
        ranges.append((start, end))
    ranges.sort(key=lambda x: x[0])
    merged = []
    for start, end in ranges:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(s, e) for s, e in merged]


def render_threat_snippet_reader(source_code: str, threats: List[Dict], context_lines: int = 4, max_snippets: int = 50):
    """显示威胁代码片段阅读器"""
    if not source_code:
        st.info("未找到可展示的源代码。")
        return
    if not threats:
        st.info("未检测到威胁，暂无片段可显示。")
        return

    lines = source_code.splitlines()
    threat_lines = build_threat_line_map(threats)
    if not threat_lines:
        st.info("未检测到有效的威胁行号。")
        return

    severity_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

    def pick_severity(items: List[Dict[str, str]]) -> str:
        best = 'low'
        best_rank = 0
        for item in items:
            sev = item.get('severity', 'low')
            rank = severity_rank.get(sev, 0)
            if rank > best_rank:
                best = sev
                best_rank = rank
        return best

    ranges = merge_context_ranges(sorted(threat_lines.keys()), len(lines), context_lines)
    if not ranges:
        st.info("未检测到可展示的片段范围。")
        return

    legend_html = """
    <div class="doc-reader-legend">
        <div class="doc-legend-item" style="background:#FFE6E6;border-color:#E74C3C;">严重</div>
        <div class="doc-legend-item" style="background:#FFE8D6;border-color:#E67E22;">高危</div>
        <div class="doc-legend-item" style="background:#FFF4E6;border-color:#F39C12;">中危</div>
        <div class="doc-legend-item" style="background:#E6F7E6;border-color:#27AE60;">低危</div>
    </div>
    """

    html_parts = ['<div class="doc-reader">', legend_html]
    for idx, (start, end) in enumerate(ranges[:max_snippets], 1):
        html_parts.append(f'<div class="doc-snippet"><div class="doc-snippet-header">片段 {idx}：第 {start} 行 - 第 {end} 行</div>')
        html_parts.append('<div class="doc-code">')
        for line_num in range(start, end + 1):
            line_content = escape_html(lines[line_num - 1]) if line_num - 1 < len(lines) else ''
            if line_num in threat_lines:
                items = threat_lines[line_num]
                severity = pick_severity(items)
                threat_types = ', '.join(sorted({t.get("type", "未知") for t in items}))
                html_parts.append(
                    f'<div class="doc-line threat-{severity}" title="威胁: {escape_html(threat_types)}">'
                    f'<span class="doc-line-number">{line_num:4d}</span>'
                    f'<span class="doc-line-content">{line_content}</span>'
                    f'</div>'
                )
            else:
                html_parts.append(
                    f'<div class="doc-line">'
                    f'<span class="doc-line-number">{line_num:4d}</span>'
                    f'<span class="doc-line-content">{line_content}</span>'
                    f'</div>'
                )
        html_parts.append('</div></div>')

    if len(ranges) > max_snippets:
        html_parts.append(f'<div style="color:#7F8C8D;font-size:12px;">仅显示前 {max_snippets} 个片段。</div>')

    html_parts.append('</div>')
    st.markdown(''.join(html_parts), unsafe_allow_html=True)


def display_results(results: dict, file_path: str = None):
    """显示分析结果"""
    risk_assessment = results.get('risk_assessment', {})
    threats = results.get('threats', [])
    aggregated = results.get('aggregated_results', {})
    
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
    
    # 风险评分显示区域
    st.markdown("---")
    st.markdown("### 📊 风险评估概览")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("风险分数", f"{risk_score}/100")
    
    with col2:
        risk_class = f"risk-{risk_level}"
        risk_level_text = risk_level_cn.get(risk_level, risk_level.upper())
        st.markdown(f"### <span class='{risk_class}'>风险等级：{risk_level_text}</span>", unsafe_allow_html=True)
    
    with col3:
        st.metric("发现威胁", threat_count)
    
    # 威胁分类统计
    breakdown = risk_assessment.get('breakdown', {})
    st.markdown("### 🎯 威胁分类统计")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("严重", breakdown.get('critical', 0))
    col2.metric("高危", breakdown.get('high', 0))
    col3.metric("中危", breakdown.get('medium', 0))
    col4.metric("低危", breakdown.get('low', 0))
    
    # 威胁列表表格
    if threats:
        st.markdown("---")
        st.markdown("### 🚨 已识别的威胁")
        
        # 严重程度中文映射
        severity_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        
        threat_data = []
        for threat in threats:
            severity = threat.get('severity', 'medium')
            threat_data.append({
                '威胁类型': threat.get('threat_type', '未知'),
                '严重程度': severity_cn.get(severity, severity.upper()),
                '描述': threat.get('description', ''),
                '行号': ', '.join(map(str, threat.get('line_numbers', []))) or 'N/A'
            })
        
        st.dataframe(threat_data, use_container_width=True)

        # 文档阅读器：仅展示威胁片段（单文件）
        source_code = None
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code = f.read()
            except Exception:
                source_code = st.session_state.source_code
        else:
            source_code = st.session_state.source_code

        with st.expander("📖 文档阅读器（威胁片段）"):
            render_threat_snippet_reader(source_code, threats)
        
        # 详细威胁信息
    else:
        st.success("✅ 未检测到威胁！代码相对安全。")
    
    # 静态分析结果
    if aggregated.get('static', {}).get('pattern_matches'):
        st.markdown("---")
        with st.expander("📊 静态分析结果"):
            static = aggregated['static']
            
            st.write(f"**模式匹配：** {len(static.get('pattern_matches', []))} 项")
            st.write(f"**污点流：** {len(static.get('taint_flows', []))} 条")
            st.write(f"**CFG 结构：** {len(static.get('cfg_structures', []))} 个")
            st.write(f"**语法检查：** {'通过' if static.get('syntax_valid', True) else '失败'}")
            
            if static.get('pattern_matches'):
                st.markdown("#### 模式匹配详情")
                for match in static['pattern_matches'][:10]:  # 显示前10项
                    st.write(f"- **{match.get('rule_name', '未知规则')}** (第 {match.get('line', 'N/A')} 行)")
    
    # 动态分析结果
    dynamic = aggregated.get('dynamic', {})
    if dynamic.get('network_activities') or dynamic.get('syscalls') or dynamic.get('fuzz_results'):
        st.markdown("---")
        with st.expander("🌐 动态分析结果"):
            syscalls = dynamic.get('syscalls', [])
            networks = dynamic.get('network_activities', [])
            fuzzes = dynamic.get('fuzz_results', [])

            col1, col2, col3 = st.columns(3)
            col1.metric("系统调用", len(syscalls))
            col2.metric("网络活动", len(networks))
            col3.metric("模糊测试", len(fuzzes))

            if networks:
                st.markdown("#### 网络活动详情")
                for activity in networks:
                    activity_type = activity.get('type', 'unknown')
                    activity_type_cn = '连接' if activity_type == 'connect' else '绑定' if activity_type == 'bind' else activity_type
                    st.write(f"- **{activity_type_cn}** 到 {activity.get('target', 'N/A')}")

            if syscalls:
                st.markdown("#### 系统调用（前20条）")
                for entry in syscalls[:20]:
                    st.code(entry)

            if fuzzes:
                st.markdown("#### 模糊测试结果（前10条）")
                for fr in fuzzes[:10]:
                    st.write(f"- 输入: `{fr.get('test_input', '')}` | 返回码: {fr.get('return_code', '')} | 超时: {fr.get('timed_out', False)} | 崩溃: {fr.get('crashed', False)}")
    
    # 报告下载
    st.markdown("---")
    st.markdown("### 📥 下载报告")
    
    reports = results.get('reports', {})
    col1, col2, col3 = st.columns(3)
    
    if reports.get('json'):
        with open(reports['json'], 'r', encoding='utf-8') as f:
            json_content = f.read()
        col1.download_button(
            label="📄 下载 JSON 报告",
            data=json_content,
            file_name=os.path.basename(reports['json']),
            mime="application/json"
        )
    
    if reports.get('html'):
        with open(reports['html'], 'r', encoding='utf-8') as f:
            html_content = f.read()
        col2.download_button(
            label="🌐 下载 HTML 报告",
            data=html_content,
            file_name=os.path.basename(reports['html']),
            mime="text/html"
        )
    
    if reports.get('markdown'):
        with open(reports['markdown'], 'r', encoding='utf-8') as f:
            markdown_content = f.read()
        col3.download_button(
            label="📝 下载 Markdown 报告",
            data=markdown_content,
            file_name=os.path.basename(reports['markdown']),
            mime="text/markdown"
        )
    
    # 代码阅读器按钮
def escape_html(text: str) -> str:
    """转义 HTML 特殊字符"""
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


if __name__ == '__main__':
    main()
