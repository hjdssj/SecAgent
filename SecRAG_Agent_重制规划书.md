# SecRAG Agent 企业级 WAF 联动版重制规划书

## 一、项目背景

当前 SecRAG Agent 已经具备基于 RAG 和多 Agent 的安全知识检索、日志分析与响应建议生成能力，但整体更偏向离线问答式系统，缺少真实安全运营场景中的持续数据输入与自动检测闭环。

为了提升项目的工程落地感与企业 SOC 场景适配能力，本次重制计划将系统与 WAF / Nginx / 防火墙日志结合，使 SecRAG Agent 从“用户主动提问的安全知识库”升级为“实时消费安全日志并自动研判的智能安全分析与响应系统”。

重制后的系统将支持 WAF 源源不断地输入日志，SecRAG Agent 自动完成日志解析、攻击识别、知识库检索、威胁情报查询、攻击链推理和响应建议生成。

## 二、重制目标

在两天内将 SecRAG Agent 重制为一个面向企业安全运营 SOC 的实时安全分析系统。

核心目标如下：

1. 接入 WAF / Nginx / 防火墙日志，实现持续日志输入。
2. 自动解析日志中的攻击行为、攻击源、目标路径、Payload 和规则命中信息。
3. 结合 RAG 安全知识库、ATT&CK、CVE 和威胁情报进行攻击判定。
4. 输出 Markdown 分析报告、风险等级、证据引用和处置建议。
5. 支持完整演示闭环：攻击请求 -> WAF 记录 -> SecRAG 分析 -> 告警卡片 / 响应建议。

## 三、总体架构

推荐采用一个准真实的安全运营演示环境，而不是直接接入真实企业 WAF。

技术选型如下：

| 模块 | 技术方案 |
| --- | --- |
| WAF | Nginx + ModSecurity + OWASP CRS |
| 靶场 | DVWA 或 OWASP Juice Shop |
| 日志采集 | tail / Filebeat / Vector |
| 消息缓冲 | Redis Stream |
| 后端服务 | FastAPI |
| Agent 编排 | ReAct + Reflection + Memory |
| RAG 知识库 | LlamaIndex + Milvus + BGE |
| 检索策略 | BM25 + 向量检索混合召回 |
| 威胁情报 | 本地 mock 库 + 可插拔真实 API |
| 结果展示 | Web 控制台 / Markdown 报告 / API 返回 |

数据流如下：

```text
攻击请求
  ↓
Nginx + ModSecurity WAF
  ↓
WAF Audit Log / Access Log
  ↓
Log Collector
  ↓
Redis Stream
  ↓
SecRAG Agent Pipeline
  ↓
攻击识别 + RAG 检索 + 威胁情报 + 决策
  ↓
告警卡片 / Markdown 报告 / 响应建议
```

## 四、核心模块设计

### 1. WAF 日志接入模块

职责：

- 监听 WAF audit log 或 Nginx access log。
- 将原始日志标准化为安全事件。
- 持续推送到 Redis Stream 或直接调用后端 API。

标准事件格式示例：

```json
{
  "timestamp": "2026-03-10T12:30:21Z",
  "source_ip": "45.67.89.10",
  "method": "GET",
  "url": "/login?id=1' OR '1'='1",
  "status": 403,
  "user_agent": "sqlmap/1.7",
  "waf_rule_id": "942100",
  "waf_message": "SQL Injection Attack Detected",
  "payload": "id=1' OR '1'='1",
  "raw_log": "..."
}
```

### 2. Log 解析 Agent

职责：

- 解析 WAF / Nginx / 防火墙日志。
- 抽取源 IP、请求方法、URL、Payload、User-Agent、状态码、命中规则等字段。
- 提取攻击特征，例如 SQL 注入关键字、XSS 标签、路径穿越符号、命令执行特征等。
- 初步判断攻击类型，包括 SQL 注入、XSS、路径穿越、命令执行、爆破、扫描等。

### 3. RAG 检索 Agent

职责：

- 根据攻击特征检索本地安全知识库。
- 匹配 OWASP CRS 规则、ATT&CK 技术、CVE 漏洞、攻击行为描述和修复建议。
- 使用 Query Rewrite 将原始日志转换为更适合检索的安全语义查询。
- 使用 BM25 + 向量检索混合召回，提升安全术语和攻击特征匹配能力。

Query Rewrite 示例：

```text
原始日志：
GET /login?id=1' OR '1'='1

改写查询：
SQL injection authentication bypass WAF rule 942100 OWASP CRS
```

### 4. 威胁情报 Agent

职责：

- 查询源 IP 是否为扫描器、代理、僵尸网络或黑产资产。
- 查询域名、URL、Hash 等 IOC 信息。
- 给出威胁可信度和风险评分。
- 辅助判断攻击来源和攻击活动背景。

两天内优先实现：

- 本地 mock 威胁情报库。
- 预留真实 API 适配器。

可选真实情报源：

- AbuseIPDB
- VirusTotal
- 微步在线
- 奇安信威胁情报

### 5. 决策 Agent

职责：

- 融合日志证据、RAG 结果、威胁情报和历史记忆。
- 输出攻击结论、风险等级、攻击链推理和响应建议。
- 生成 Markdown 格式安全事件报告。
- 对最终答案进行逻辑审校和提纲式归纳。

输出示例：

```markdown
## 安全事件分析

**结论**：疑似 SQL 注入攻击，风险等级：高危。

**关键证据**

- WAF 命中规则：942100，SQL Injection Attack Detected
- 请求参数包含典型布尔注入 Payload：`' OR '1'='1`
- User-Agent 显示为 sqlmap 自动化扫描工具
- 源 IP 在威胁情报中标记为扫描节点

**ATT&CK 映射**

- T1190: Exploit Public-Facing Application

**建议处置**

1. 临时封禁源 IP。
2. 检查 `/login` 接口参数化查询实现。
3. 对同源 IP 过去 24 小时访问行为进行回溯。
4. 提升相关 WAF 规则拦截等级。
```

## 五、两天实施计划

### Day 1：打通实时日志接入与攻击检测闭环

上午任务：

1. 搭建 Docker 演示环境：
   - Nginx + ModSecurity + OWASP CRS
   - DVWA 或 OWASP Juice Shop
   - Redis
   - SecRAG 后端服务

2. 生成真实 WAF 日志：
   - SQL 注入请求
   - XSS 请求
   - 路径穿越请求
   - sqlmap 扫描请求

下午任务：

1. 实现日志采集器：
   - 监听 WAF audit log。
   - 解析 ModSecurity 日志。
   - 将日志写入 Redis Stream。

2. 实现实时消费服务：
   - FastAPI 启动 consumer。
   - 从 Redis Stream 消费安全事件。
   - 调用 Log 解析 Agent。
   - 输出基础攻击类型和风险等级。

Day 1 交付物：

- WAF 能持续产生日志。
- SecRAG 能实时消费日志。
- 系统能识别 SQL 注入 / XSS / 扫描类攻击。
- 可以在控制台或 API 中看到结构化告警。

### Day 2：接入 RAG、威胁情报与报告生成

上午任务：

1. 接入 RAG 检索：
   - CVE 知识库。
   - ATT&CK 知识库。
   - OWASP CRS 规则解释。
   - 修复建议库。

2. 增加 Query Rewrite：
   - 从日志中抽取攻击特征。
   - 自动生成检索查询。
   - 使用 BM25 + 向量检索混合召回。

下午任务：

1. 接入威胁情报模块：
   - 本地 mock 情报库。
   - 可选真实 API。
   - IP 风险评分。

2. 完成决策 Agent：
   - 汇总日志证据。
   - 汇总 RAG 证据。
   - 汇总威胁情报。
   - 生成 Markdown 报告和告警卡片。

3. 准备演示脚本：
   - 发起 SQL 注入攻击。
   - WAF 拦截并记录日志。
   - SecRAG 实时分析。
   - 输出攻击结论、证据、ATT&CK 映射、处置建议。

Day 2 交付物：

- 一个完整实时安全分析 Demo。
- 一份 Markdown 安全事件报告。
- 一个 API 或 Web 页面展示告警卡片。
- README 中写清楚架构、启动方式和演示流程。

## 六、MVP 范围控制

两天内必须完成：

1. WAF 日志实时接入。
2. Redis Stream 或轻量消息队列。
3. 日志标准化。
4. 攻击类型识别。
5. RAG 检索安全知识。
6. Markdown 安全报告生成。
7. 至少 3 类攻击演示：SQL 注入、XSS、路径穿越。

两天内不建议投入：

1. 复杂前端大屏。
2. 真正自动封禁生产流量。
3. 多租户权限系统。
4. 完整 SIEM 替代能力。
5. 过度复杂的多 Agent 可视化编排。

可以作为加分项：

1. 自动生成 Nginx / WAF 封禁建议。
2. 支持手动确认后一键封禁 IP。
3. 事件历史记忆，识别同一 IP 的连续攻击行为。
4. 风险评分公式。

## 七、演示方案

推荐演示流程：

```text
1. 启动 docker-compose
2. 打开靶场站点
3. 发送攻击请求：
   /login?id=1' OR '1'='1
4. WAF 拦截并写入 audit log
5. SecRAG 自动消费日志
6. 系统生成告警：
   - 攻击类型：SQL 注入
   - 风险等级：高危
   - 源 IP 信誉：可疑
   - ATT&CK：T1190
   - 证据：Payload、WAF Rule、User-Agent
   - 建议：封禁 IP、检查接口、回溯日志
```

推荐演示攻击类型：

| 攻击类型 | 示例 Payload / 行为 | 预期识别结果 |
| --- | --- | --- |
| SQL 注入 | `/login?id=1' OR '1'='1` | SQL 注入，高危 |
| XSS | `/search?q=<script>alert(1)</script>` | XSS，中高危 |
| 路径穿越 | `/download?file=../../etc/passwd` | 路径穿越，高危 |
| 自动化扫描 | User-Agent: sqlmap | 扫描行为，中危 |
| 爆破登录 | 短时间多次登录失败 | 暴力破解，中高危 |

## 八、项目亮点包装

重制后项目可以描述为：

> 本项目不是传统离线安全问答系统，而是一个可与 WAF 联动的实时安全分析 Agent。系统通过接入 ModSecurity / Nginx WAF 日志流，持续消费企业边界安全事件，并结合 RAG 知识库、ATT&CK 攻击链、CVE 漏洞信息和威胁情报，对攻击行为进行自动研判、归因和响应建议生成，实现从“日志产生”到“安全结论输出”的自动化闭环。

核心亮点：

1. 从离线问答升级为实时安全事件分析。
2. 从单纯 RAG 升级为 RAG + 多 Agent + 威胁情报融合。
3. 从“用户问什么答什么”升级为“系统主动发现攻击”。
4. 可通过 WAF 真实日志证明系统具备工程落地价值。
5. 能够输出结构化告警、Markdown 安全报告和可执行响应建议。

## 九、最终项目定位

一句话总结：

> SecRAG Agent 企业级 WAF 联动版，是一个面向 SOC 场景的实时安全分析与响应系统，能够持续消费 WAF 日志，并结合 RAG 知识库、多 Agent 推理和威胁情报，对安全事件进行自动研判、归因和处置建议生成。

重制方向：

```text
安全知识库问答项目
  ↓
WAF 驱动的实时安全分析与响应系统
```
