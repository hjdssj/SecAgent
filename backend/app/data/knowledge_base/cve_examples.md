# CVE 示例知识库

## CVE 类别：SQL 注入漏洞

### 漏洞说明
SQL 注入类 CVE 通常源于应用将用户输入直接拼接进数据库查询语句，导致攻击者可以改变查询逻辑。

### 关联攻击
- SQL Injection
- Authentication Bypass
- Data Exfiltration

### 修复建议
- 升级受影响组件。
- 使用参数化查询。
- 检查数据库账号权限。

## CVE 类别：路径穿越漏洞

### 漏洞说明
路径穿越类 CVE 通常源于文件路径拼接或目录边界控制不严，攻击者可以读取预期目录之外的敏感文件。

### 关联攻击
- Path Traversal
- Arbitrary File Read

### 修复建议
- 修复文件路径规范化逻辑。
- 限制访问根目录。
- 使用文件白名单。

## CVE 类别：命令注入漏洞

### 漏洞说明
命令注入类 CVE 通常源于应用将用户输入传递给 shell 或系统命令解释器。

### 关联攻击
- Command Injection
- Remote Code Execution

### 修复建议
- 升级受影响组件。
- 移除不必要的命令执行入口。
- 使用安全 API 替代 shell 命令。
