# OWASP CRS 规则知识库

## OWASP CRS 913 Scanner Detection

### 规则说明
913 系列规则用于识别扫描器、漏洞验证工具和自动化探测行为。

### 常见命中
- sqlmap User-Agent
- nikto User-Agent
- acunetix User-Agent
- nessus User-Agent

### 处置建议
- 将扫描器命中作为辅助证据，不应覆盖更具体的攻击类型。
- 回溯该 IP 是否同时触发 SQLi、XSS、路径穿越等规则。
- 对高频扫描源进行限速、封禁或加入观察名单。

## OWASP CRS 930 Path Traversal

### 规则说明
930 系列规则用于识别路径穿越和任意文件读取行为。

### 常见命中
- `../`
- `/etc/passwd`
- Windows 系统文件名

### 处置建议
- 关注下载、导出、图片预览等文件访问接口。
- 检查服务端是否将用户输入直接映射到文件系统路径。

## OWASP CRS 941 XSS

### 规则说明
941 系列规则用于识别跨站脚本攻击。

### 常见命中
- `<script>`
- 事件处理器属性
- JavaScript URL

### 处置建议
- 检查响应中是否反射了恶意输入。
- 对 HTML、属性、URL、JavaScript 上下文分别编码。

## OWASP CRS 942 SQL Injection

### 规则说明
942 系列规则用于识别 SQL 注入攻击。

### 常见命中
- 布尔注入
- UNION 查询
- 时间盲注
- 数据库元数据探测

### 处置建议
- 检查数据库访问层是否使用参数化查询。
- 对登录、搜索、筛选等接口优先复核。

## OWASP CRS 932 Command Injection

### 规则说明
932 系列规则用于识别远程命令执行和命令注入攻击。

### 常见命中
- shell 元字符
- 系统命令关键字
- 反引号执行
- `$()` 命令替换

### 处置建议
- 检查服务是否调用系统命令。
- 避免用户输入进入 shell 解释器。
