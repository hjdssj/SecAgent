# SecRAG Agent 项目架构设计

## 一、项目定位

SecRAG Agent 是一个面向企业 SOC 场景的实时安全分析与响应系统。系统通过接入 WAF / Nginx / 防火墙日志流，持续消费安全事件，并结合 RAG 安全知识库、多 Agent 分析流程和威胁情报，对攻击行为进行自动识别、归因、风险评级和响应建议生成。

项目核心目标不是做一个离线安全问答机器人，而是实现一条可演示、可扩展的安全事件处理链路：

```text
日志输入 -> 攻击识别 -> 知识检索 -> 情报查询 -> 综合研判 -> 响应建议
```

## 二、总体架构

```text
┌────────────────────────────────────────────────────────────┐
│                    Attack / Normal Traffic                 │
│       SQLi / XSS / Path Traversal / Brute Force / Scan      │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│                 WAF Layer                                  │
│        Nginx + ModSecurity + OWASP CRS                     │
│        Access Log / Audit Log / Rule Match                 │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│                 Log Collector                              │
│        Tail Log / Parse Raw Log / Normalize Event           │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│                 Event Queue                                │
│        Redis Stream / Event Buffer / Retry                 │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│                 SecRAG Agent Backend                       │
│                                                            │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
│  │ Log Parser   │ ->│ RAG Agent    │ ->│ TI Agent     │    │
│  │ Agent        │   │ LlamaIndex   │   │ Threat Intel │    │
│  └──────────────┘   └──────────────┘   └──────────────┘    │
│          │                  │                  │            │
│          └──────────────────┴──────────────────┘            │
│                              │                              │
│                              ▼                              │
│                    ┌──────────────────┐                    │
│                    │ Decision Agent   │                    │
│                    │ Risk + Reasoning │                    │
│                    └──────────────────┘                    │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│                 Output Layer                               │
│        Alert Card / Markdown Report / API Response          │
└────────────────────────────────────────────────────────────┘
```

## 三、技术栈选型

| 层级 | 技术方案 | 作用 |
| --- | --- | --- |
| WAF 层 | Nginx + ModSecurity + OWASP CRS | 产生接近真实场景的安全日志 |
| 靶场层 | DVWA / OWASP Juice Shop | 用于构造 SQL 注入、XSS、路径穿越等攻击流量 |
| 日志采集层 | Python Tail Collector / Filebeat / Vector | 持续读取 WAF 日志并标准化 |
| 消息队列层 | Redis Stream | 缓冲安全事件，解耦日志采集和分析服务 |
| 后端服务层 | FastAPI | 提供 API、消费日志事件、触发分析流程 |
| RAG 层 | LlamaIndex + Milvus + BGE | 构建 CVE、ATT&CK、OWASP CRS、安全修复知识库 |
| 检索层 | BM25 + Vector Hybrid Search | 同时提升关键词匹配和语义召回能力 |
| Agent 层 | 自定义 Agent Orchestrator | 编排日志解析、RAG 检索、情报查询、综合决策 |
| 情报层 | Mock Threat Intel + 可插拔真实 API | 判断 IP / 域名 / IOC 风险 |
| 输出层 | Markdown + JSON Alert | 输出安全报告和结构化告警 |

## 四、核心数据流

### 1. 实时日志输入

攻击者访问靶场应用后，请求先经过 WAF。WAF 根据 OWASP CRS 规则进行检测，并将命中结果写入 audit log。

示例攻击请求：

```text
GET /login?id=1' OR '1'='1 HTTP/1.1
User-Agent: sqlmap/1.7
```

WAF 日志中可能包含：

- 源 IP
- 请求方法
- 请求路径
- 请求参数
- User-Agent
- HTTP 状态码
- 命中的 WAF 规则 ID
- WAF 规则描述
- 原始 Payload

### 2. 日志标准化

Log Collector 将原始日志转换为统一事件格式。

```json
{
  "event_id": "evt-20260310-000001",
  "timestamp": "2026-03-10T12:30:21Z",
  "source_ip": "45.67.89.10",
  "method": "GET",
  "url": "/login?id=1' OR '1'='1",
  "path": "/login",
  "query": "id=1' OR '1'='1",
  "status": 403,
  "user_agent": "sqlmap/1.7",
  "waf_rule_id": "942100",
  "waf_message": "SQL Injection Attack Detected",
  "raw_log": "..."
}
```

### 3. Agent 分析流程

```text
标准化安全事件
  ↓
Log Parser Agent
  - 字段解析
  - Payload 抽取
  - 初步攻击分类
  ↓
RAG Agent
  - Query Rewrite
  - 检索 CVE / ATT&CK / OWASP CRS / 修复建议
  - 返回相关证据
  ↓
Threat Intelligence Agent
  - 查询源 IP 信誉
  - 查询 IOC 风险
  - 判断是否为扫描器 / 僵尸网络 / 黑产资产
  ↓
Decision Agent
  - 融合日志证据、知识库证据、威胁情报
  - 给出攻击类型、风险等级、攻击链映射
  - 生成响应建议
```

## 五、模块设计

### 1. Log Collector

负责从 WAF 日志文件中持续读取新增内容。

输入：

- ModSecurity audit log
- Nginx access log
- 防火墙日志，后续扩展

输出：

- 标准化安全事件
- 写入 Redis Stream

核心能力：

- 实时 tail 日志
- 解析多段式 ModSecurity audit log
- 提取规则命中信息
- 过滤普通访问日志
- 对异常日志进行降级处理

### 2. Event Queue

负责解耦日志采集和后端分析服务。

推荐使用 Redis Stream：

- `security:events`：待分析安全事件
- `security:alerts`：分析后的告警结果
- `security:deadletter`：解析失败或分析失败事件

使用 Redis Stream 的好处：

- 实现实时消费。
- 支持事件积压。
- 支持失败重试。
- 方便演示“日志源源不断进入系统”。

### 3. FastAPI Backend

负责承载系统 API 和 Agent 分析入口。

主要接口：

| 接口 | 方法 | 作用 |
| --- | --- | --- |
| `/api/events` | POST | 手动提交安全事件，用于测试 |
| `/api/events/recent` | GET | 查看最近事件 |
| `/api/alerts/recent` | GET | 查看最近告警 |
| `/api/analyze` | POST | 对单条日志立即分析 |
| `/api/reports/{alert_id}` | GET | 获取 Markdown 分析报告 |

后台任务：

- Redis Stream Consumer
- Agent Pipeline 调度
- 告警结果落库

### 4. RAG Knowledge Base

RAG 层使用 LlamaIndex 构建，重点服务于安全知识检索。

知识库内容：

- CVE 漏洞库
- MITRE ATT&CK 技术库
- OWASP CRS 规则说明
- 常见攻击 Payload 特征
- 安全修复建议
- 企业内部安全规范，后续扩展

检索策略：

```text
原始日志
  ↓
攻击特征抽取
  ↓
Query Rewrite
  ↓
BM25 关键词召回
  +
BGE 向量召回
  ↓
Rerank
  ↓
返回证据片段
```

LlamaIndex 在项目中的定位：

- 负责文档加载、切分、索引、向量库连接和检索。
- 不承担全部 Agent 编排。
- 专注做安全知识库的高质量召回。

### 5. Agent Orchestrator

两天 MVP 中建议先使用自定义轻量编排器，而不是重度引入 LangChain / LangGraph。

推荐流程：

```text
LogParserAgent -> RAGAgent -> ThreatIntelAgent -> DecisionAgent -> ReportGenerator
```

各 Agent 职责：

| Agent | 职责 |
| --- | --- |
| LogParserAgent | 解析日志字段，提取攻击特征，初步分类 |
| RAGAgent | 根据攻击特征检索安全知识库 |
| ThreatIntelAgent | 查询 IP / 域名 / IOC 威胁情报 |
| DecisionAgent | 综合研判攻击类型、风险等级和处置优先级 |
| ReportGenerator | 生成 Markdown 报告和卡片式要点 |

后续如果需要复杂状态机、人工审批、一键封禁等能力，可以再引入 LangGraph。

## 六、风险评分设计

风险分数建议采用 0-100 分。

评分因素：

| 因素 | 权重 | 示例 |
| --- | --- | --- |
| WAF 命中规则严重度 | 30 | SQL 注入、RCE 高分 |
| Payload 危险程度 | 25 | 命令执行、认证绕过高分 |
| 威胁情报结果 | 20 | 恶意 IP、扫描器、僵尸网络 |
| 访问行为频率 | 15 | 短时间大量请求、爆破 |
| 资产敏感度 | 10 | 登录接口、管理后台、上传接口 |

风险等级：

| 分数 | 等级 | 含义 |
| --- | --- | --- |
| 0-39 | 低危 | 可记录观察 |
| 40-69 | 中危 | 需要关注和回溯 |
| 70-89 | 高危 | 需要及时处置 |
| 90-100 | 严重 | 建议立即响应 |

## 七、推荐目录结构

```text
secagent/
├── app/
│   ├── main.py
│   ├── api/
│   │   ├── events.py
│   │   ├── alerts.py
│   │   └── reports.py
│   ├── agents/
│   │   ├── log_parser_agent.py
│   │   ├── rag_agent.py
│   │   ├── threat_intel_agent.py
│   │   ├── decision_agent.py
│   │   └── report_generator.py
│   ├── collector/
│   │   ├── waf_log_collector.py
│   │   └── modsecurity_parser.py
│   ├── rag/
│   │   ├── index_builder.py
│   │   ├── retriever.py
│   │   └── query_rewriter.py
│   ├── intelligence/
│   │   ├── mock_intel.py
│   │   └── providers.py
│   ├── models/
│   │   ├── event.py
│   │   └── alert.py
│   ├── storage/
│   │   ├── redis_client.py
│   │   └── alert_store.py
│   └── config.py
├── data/
│   ├── knowledge_base/
│   │   ├── cve/
│   │   ├── attack/
│   │   ├── owasp_crs/
│   │   └── remediation/
│   └── threat_intel/
├── docker/
│   ├── nginx/
│   ├── modsecurity/
│   └── waf/
├── scripts/
│   ├── build_index.py
│   ├── run_collector.py
│   └── simulate_attack.py
├── reports/
├── docker-compose.yml
├── README.md
└── requirements.txt
```

## 八、MVP 架构范围

两天内建议优先实现以下架构：

```text
Nginx + ModSecurity
  ↓
WAF Audit Log
  ↓
Python Log Collector
  ↓
Redis Stream
  ↓
FastAPI Consumer
  ↓
LogParserAgent
  ↓
LlamaIndex RAGAgent
  ↓
Mock ThreatIntelAgent
  ↓
DecisionAgent
  ↓
Markdown Report / JSON Alert
```

暂缓内容：

- 复杂前端大屏。
- 生产级自动封禁。
- 多租户权限。
- 完整 SIEM 能力。
- 复杂 LangGraph 编排。

## 九、最终输出格式

### 1. JSON 告警

```json
{
  "alert_id": "alert-20260310-000001",
  "event_id": "evt-20260310-000001",
  "attack_type": "SQL Injection",
  "risk_score": 86,
  "risk_level": "high",
  "source_ip": "45.67.89.10",
  "target": "/login",
  "confidence": 0.91,
  "evidence": [
    "WAF rule 942100 matched SQL injection pattern",
    "Payload contains boolean-based injection",
    "User-Agent indicates sqlmap scanner"
  ],
  "mitre_attack": [
    {
      "technique_id": "T1190",
      "name": "Exploit Public-Facing Application"
    }
  ],
  "recommendations": [
    "Temporarily block the source IP",
    "Review parameterized query implementation of /login",
    "Trace historical requests from the same source IP"
  ]
}
```

### 2. Markdown 报告

```markdown
## 安全事件分析报告

**结论**：检测到疑似 SQL 注入攻击，风险等级：高危。

**关键证据**

- WAF 命中规则 942100，规则描述为 SQL Injection Attack Detected。
- 请求参数包含典型布尔注入 Payload：`' OR '1'='1`。
- User-Agent 显示为 sqlmap 自动化扫描工具。

**ATT&CK 映射**

- T1190: Exploit Public-Facing Application

**处置建议**

1. 临时封禁源 IP。
2. 检查 `/login` 接口是否使用参数化查询。
3. 回溯同一 IP 在过去 24 小时内的访问行为。
4. 提高相关 WAF 规则的拦截级别。
```

## 十、架构亮点

1. 通过 WAF 日志接入真实安全事件来源，避免项目停留在离线问答层面。
2. 使用 Redis Stream 构建实时日志消费链路，体现工程化事件处理能力。
3. 使用 LlamaIndex 专注构建安全知识库检索层，强化 RAG 项目核心优势。
4. 使用轻量自定义 Agent 编排，避免两天内陷入复杂框架集成。
5. 结合威胁情报和 ATT&CK 映射，让输出结果更接近 SOC 分析报告。
6. 支持 JSON 告警和 Markdown 报告两种输出，便于 API 调用和项目展示。

