# SecRAG Agent 前后端分离文件结构规划

## 一、整体工程结构

前后端分离后，项目建议拆成 `backend/`、`frontend/`、`infra/`、`data/`、`docs/` 五个核心部分。

```text
secagent/
├── backend/
├── frontend/
├── infra/
├── data/
├── docs/
├── reports/
├── scripts/
├── docker-compose.yml
├── README.md
└── .env.example
```

整体职责：

| 目录 | 职责 |
| --- | --- |
| `backend/` | FastAPI 后端、WAF 日志消费、RAG、多 Agent、威胁情报、报告生成 |
| `frontend/` | Web 控制台，展示事件、告警、报告、攻击链和系统状态 |
| `infra/` | Nginx、ModSecurity、Redis、Milvus 等基础设施配置 |
| `data/` | 知识库、样例日志、mock 威胁情报数据 |
| `reports/` | 自动生成的 Markdown 安全分析报告 |
| `scripts/` | 构建索引、日志回放、模拟攻击、启动辅助脚本 |
| `docs/` | 架构文档、演示文档、API 文档 |

## 二、推荐完整目录结构

```text
secagent/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   │
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   ├── events.py
│   │   │   ├── alerts.py
│   │   │   ├── reports.py
│   │   │   ├── intelligence.py
│   │   │   └── health.py
│   │   │
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py
│   │   │   ├── log_parser_agent.py
│   │   │   ├── rag_agent.py
│   │   │   ├── threat_intel_agent.py
│   │   │   ├── decision_agent.py
│   │   │   └── report_generator.py
│   │   │
│   │   ├── collector/
│   │   │   ├── __init__.py
│   │   │   ├── waf_log_collector.py
│   │   │   ├── modsecurity_parser.py
│   │   │   └── nginx_parser.py
│   │   │
│   │   ├── rag/
│   │   │   ├── __init__.py
│   │   │   ├── index_builder.py
│   │   │   ├── retriever.py
│   │   │   ├── query_rewriter.py
│   │   │   └── schemas.py
│   │   │
│   │   ├── intelligence/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── mock_intel.py
│   │   │   └── providers.py
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── event.py
│   │   │   ├── alert.py
│   │   │   ├── report.py
│   │   │   └── intelligence.py
│   │   │
│   │   ├── storage/
│   │   │   ├── __init__.py
│   │   │   ├── redis_client.py
│   │   │   ├── event_store.py
│   │   │   └── alert_store.py
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── event_consumer.py
│   │   │   ├── risk_scorer.py
│   │   │   └── markdown_renderer.py
│   │   │
│   │   └── utils/
│   │       ├── __init__.py
│   │       ├── logger.py
│   │       ├── time.py
│   │       └── text.py
│   │
│   ├── tests/
│   │   ├── test_log_parser.py
│   │   ├── test_risk_scorer.py
│   │   └── test_orchestrator.py
│   │
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   │
│   │   ├── api/
│   │   │   ├── client.ts
│   │   │   ├── events.ts
│   │   │   ├── alerts.ts
│   │   │   ├── reports.ts
│   │   │   └── health.ts
│   │   │
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── EventsPage.tsx
│   │   │   ├── AlertsPage.tsx
│   │   │   ├── AlertDetailPage.tsx
│   │   │   ├── ReportsPage.tsx
│   │   │   └── SettingsPage.tsx
│   │   │
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── AppShell.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── Topbar.tsx
│   │   │   │
│   │   │   ├── alerts/
│   │   │   │   ├── AlertTable.tsx
│   │   │   │   ├── AlertCard.tsx
│   │   │   │   ├── RiskBadge.tsx
│   │   │   │   └── EvidenceList.tsx
│   │   │   │
│   │   │   ├── events/
│   │   │   │   ├── EventTable.tsx
│   │   │   │   ├── EventTimeline.tsx
│   │   │   │   └── RawLogViewer.tsx
│   │   │   │
│   │   │   ├── reports/
│   │   │   │   ├── MarkdownReport.tsx
│   │   │   │   └── RecommendationList.tsx
│   │   │   │
│   │   │   └── common/
│   │   │       ├── StatusDot.tsx
│   │   │       ├── EmptyState.tsx
│   │   │       ├── LoadingState.tsx
│   │   │       └── PageHeader.tsx
│   │   │
│   │   ├── hooks/
│   │   │   ├── useAlerts.ts
│   │   │   ├── useEvents.ts
│   │   │   └── useReport.ts
│   │   │
│   │   ├── types/
│   │   │   ├── event.ts
│   │   │   ├── alert.ts
│   │   │   └── report.ts
│   │   │
│   │   ├── styles/
│   │   │   ├── globals.css
│   │   │   └── theme.css
│   │   │
│   │   └── utils/
│   │       ├── format.ts
│   │       └── risk.ts
│   │
│   ├── public/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── Dockerfile
│
├── infra/
│   ├── nginx/
│   │   ├── nginx.conf
│   │   └── default.conf
│   │
│   ├── modsecurity/
│   │   ├── modsecurity.conf
│   │   └── crs-setup.conf
│   │
│   ├── redis/
│   │   └── redis.conf
│   │
│   ├── milvus/
│   │   └── milvus.env
│   │
│   └── waf/
│       └── Dockerfile
│
├── data/
│   ├── knowledge_base/
│   │   ├── cve/
│   │   ├── attack/
│   │   ├── owasp_crs/
│   │   └── remediation/
│   │
│   ├── threat_intel/
│   │   └── mock_ioc.json
│   │
│   └── sample_logs/
│       ├── modsecurity_sqli.log
│       ├── modsecurity_xss.log
│       └── nginx_access.log
│
├── scripts/
│   ├── build_index.py
│   ├── run_collector.py
│   ├── simulate_attack.py
│   └── replay_sample_logs.py
│
├── reports/
│   └── .gitkeep
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── demo.md
│   └── deployment.md
│
├── docker-compose.yml
├── README.md
└── .env.example
```

## 三、后端结构说明

后端建议使用 FastAPI，职责是承接安全事件、执行 Agent 分析流程、调用 RAG 检索和生成告警报告。

### 1. backend/app/main.py

后端入口。

职责：

- 创建 FastAPI 应用。
- 注册 API 路由。
- 启动 Redis Stream 消费任务。
- 暴露健康检查接口。

### 2. backend/app/api/

后端 API 层，只负责 HTTP 入参、出参和路由转发，不写复杂业务逻辑。

| 文件 | 职责 |
| --- | --- |
| `events.py` | 安全事件提交、事件列表查询 |
| `alerts.py` | 告警列表、告警详情查询 |
| `reports.py` | Markdown 报告查询 |
| `intelligence.py` | IP / IOC 情报查询 |
| `health.py` | 后端、Redis、Milvus 状态检查 |

推荐接口：

```text
GET  /api/health
POST /api/events
GET  /api/events/recent
GET  /api/alerts/recent
GET  /api/alerts/{alert_id}
GET  /api/reports/{alert_id}
POST /api/analyze
```

### 3. backend/app/agents/

后端核心分析层。

```text
orchestrator.py
  -> log_parser_agent.py
  -> rag_agent.py
  -> threat_intel_agent.py
  -> decision_agent.py
  -> report_generator.py
```

职责划分：

| 文件 | 职责 |
| --- | --- |
| `orchestrator.py` | 串联完整分析工作流 |
| `log_parser_agent.py` | 从日志中抽取攻击特征 |
| `rag_agent.py` | 调用 LlamaIndex 检索安全知识 |
| `threat_intel_agent.py` | 查询威胁情报 |
| `decision_agent.py` | 综合研判风险等级、攻击类型、响应建议 |
| `report_generator.py` | 生成 Markdown 报告 |

### 4. backend/app/rag/

RAG 检索层。

LlamaIndex 建议集中放在这一层，不要散落到其他模块。

| 文件 | 职责 |
| --- | --- |
| `index_builder.py` | 构建 CVE / ATT&CK / CRS 知识库索引 |
| `retriever.py` | 封装 LlamaIndex 检索逻辑 |
| `query_rewriter.py` | 将日志特征改写为安全检索 Query |
| `schemas.py` | 定义检索证据结构 |

### 5. backend/app/collector/

日志采集层。

| 文件 | 职责 |
| --- | --- |
| `waf_log_collector.py` | 持续监听 WAF 日志 |
| `modsecurity_parser.py` | 解析 ModSecurity audit log |
| `nginx_parser.py` | 解析 Nginx access log |

### 6. backend/app/storage/

存储与消息队列层。

MVP 阶段推荐只使用 Redis。

| 文件 | 职责 |
| --- | --- |
| `redis_client.py` | Redis 连接、Stream 读写 |
| `event_store.py` | 安全事件缓存与查询 |
| `alert_store.py` | 告警缓存与查询 |

Redis Stream 建议：

```text
security:events       待分析安全事件
security:alerts       已生成告警
security:deadletter   失败事件
```

## 四、前端结构说明

前端建议使用 React + TypeScript + Vite。

前端不是营销页，而是 SOC 风格的安全分析控制台。第一屏应该直接展示告警、事件流、风险统计和系统状态。

### 1. frontend/src/pages/

页面级组件。

| 页面 | 职责 |
| --- | --- |
| `DashboardPage.tsx` | 总览：风险统计、最新告警、事件流、系统状态 |
| `EventsPage.tsx` | 安全事件列表，展示 WAF 输入日志 |
| `AlertsPage.tsx` | 告警列表，支持按风险等级、攻击类型筛选 |
| `AlertDetailPage.tsx` | 告警详情，展示证据、ATT&CK、威胁情报、处置建议 |
| `ReportsPage.tsx` | Markdown 报告列表与预览 |
| `SettingsPage.tsx` | API 地址、刷新频率、模拟攻击开关等配置 |

### 2. frontend/src/api/

后端 API 封装。

| 文件 | 职责 |
| --- | --- |
| `client.ts` | Axios / fetch 基础客户端 |
| `events.ts` | 事件接口 |
| `alerts.ts` | 告警接口 |
| `reports.ts` | 报告接口 |
| `health.ts` | 系统状态接口 |

### 3. frontend/src/components/

组件按业务拆分。

```text
components/
├── layout/
├── alerts/
├── events/
├── reports/
└── common/
```

重点组件：

| 组件 | 职责 |
| --- | --- |
| `AlertTable.tsx` | 告警表格 |
| `RiskBadge.tsx` | 风险等级标签 |
| `EvidenceList.tsx` | 证据列表 |
| `EventTimeline.tsx` | 实时事件流 |
| `RawLogViewer.tsx` | 原始日志查看 |
| `MarkdownReport.tsx` | Markdown 报告渲染 |
| `StatusDot.tsx` | 系统状态指示 |

### 4. frontend/src/types/

前端类型定义要和后端 Pydantic 模型对齐。

```text
types/
├── event.ts
├── alert.ts
└── report.ts
```

示例：

```ts
export interface SecurityAlert {
  alert_id: string;
  event_id: string;
  attack_type: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  source_ip: string;
  target: string;
  confidence: number;
  evidence: string[];
  recommendations: string[];
}
```

## 五、前后端接口契约

前后端分离最重要的是先定接口契约。

### 1. 安全事件

```json
{
  "event_id": "evt-20260310-000001",
  "timestamp": "2026-03-10T12:30:21Z",
  "source_ip": "45.67.89.10",
  "method": "GET",
  "url": "/login?id=1' OR '1'='1",
  "path": "/login",
  "status": 403,
  "user_agent": "sqlmap/1.7",
  "waf_rule_id": "942100",
  "waf_message": "SQL Injection Attack Detected",
  "raw_log": "..."
}
```

### 2. 告警结果

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

## 六、MVP 阶段建议先实现的文件

两天内不需要把所有目录都写满。建议优先实现下面这些文件。

```text
backend/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── api/
│   │   ├── events.py
│   │   ├── alerts.py
│   │   └── reports.py
│   ├── models/
│   │   ├── event.py
│   │   └── alert.py
│   ├── agents/
│   │   ├── orchestrator.py
│   │   ├── log_parser_agent.py
│   │   ├── rag_agent.py
│   │   ├── threat_intel_agent.py
│   │   └── decision_agent.py
│   ├── collector/
│   │   └── modsecurity_parser.py
│   ├── rag/
│   │   ├── index_builder.py
│   │   └── retriever.py
│   └── storage/
│       └── redis_client.py
│
frontend/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── api/
│   │   ├── client.ts
│   │   ├── alerts.ts
│   │   └── events.ts
│   ├── pages/
│   │   ├── DashboardPage.tsx
│   │   ├── AlertsPage.tsx
│   │   └── AlertDetailPage.tsx
│   ├── components/
│   │   ├── alerts/
│   │   │   ├── AlertTable.tsx
│   │   │   └── RiskBadge.tsx
│   │   └── events/
│   │       └── EventTimeline.tsx
│   └── types/
│       ├── alert.ts
│       └── event.ts
```

## 七、开发顺序建议

### Day 1

1. 后端先定义 `SecurityEvent` 和 `SecurityAlert`。
2. 实现 `/api/events` 和 `/api/analyze`，支持手动提交日志分析。
3. 实现 `LogParserAgent` 和 `DecisionAgent`，先用规则识别 SQLi / XSS / 路径穿越。
4. 前端实现 `DashboardPage` 和 `AlertsPage`，能看到告警列表。
5. 接入 Redis Stream，让日志可以持续进入后端。

### Day 2

1. 后端接入 LlamaIndex RAG 检索。
2. 接入 mock 威胁情报。
3. 生成 Markdown 报告接口。
4. 前端实现 `AlertDetailPage`，展示证据、ATT&CK、情报和处置建议。
5. 接入 WAF / 样例日志回放，完成演示闭环。

## 八、推荐启动方式

### 后端

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

### 前端

```bash
cd frontend
npm install
npm run dev
```

### Docker Compose

```bash
docker compose up -d
```

推荐端口：

| 服务 | 端口 |
| --- | --- |
| Frontend | `5173` |
| Backend API | `8000` |
| Redis | `6379` |
| Milvus | `19530` |
| WAF / Nginx | `8080` |

## 九、结论

前后端分离后，项目的表达会更工程化：

```text
frontend/
  负责 SOC 控制台和告警展示

backend/
  负责 WAF 日志接入、RAG、多 Agent 和分析报告

infra/
  负责 WAF、Redis、Milvus 等运行环境

data/
  负责知识库、样例日志和 mock 威胁情报
```

两天 MVP 的关键不是把页面做复杂，而是让前端能清楚展示后端分析链路：

```text
事件进入 -> 识别攻击 -> 检索证据 -> 生成告警 -> 展示报告
```
