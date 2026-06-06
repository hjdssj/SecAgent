# MITRE ATT&CK 映射知识库

## T1190 Exploit Public-Facing Application

### 技术说明
攻击者利用暴露在公网的 Web 应用、API、网关或中间件漏洞获取未授权访问能力。

### 相关攻击
- SQL Injection
- Path Traversal
- 文件上传漏洞
- 远程代码执行

### 研判要点
- 请求是否访问公网接口。
- Payload 是否命中 Web 攻击特征。
- WAF 是否命中应用攻击规则。
- 是否存在同源 IP 对多个入口的持续探测。

### 修复建议
- 修复受影响接口的输入校验和权限控制。
- 优先处理公网暴露入口。
- 开启 WAF 阻断并保留命中证据。

## T1189 Drive-by Compromise

### 技术说明
攻击者通过诱导用户访问被植入恶意内容的页面，使浏览器执行脚本或加载恶意资源。

### 相关攻击
- XSS
- 恶意重定向
- 前端脚本注入

### 修复建议
- 对输出内容做 HTML/JavaScript 上下文编码。
- 使用 Content-Security-Policy 降低脚本执行风险。
- 检查页面是否反射用户输入。

## T1059 Command and Scripting Interpreter

### 技术说明
攻击者通过命令解释器执行系统命令或脚本，常见于命令注入、WebShell 和自动化后渗透。

### 相关攻击
- Command Injection
- WebShell 命令执行
- 反弹 shell

### 修复建议
- 禁止把用户输入拼接到 shell 命令。
- 使用白名单参数和最小权限运行服务。
- 对高危命令执行行为进行审计。
