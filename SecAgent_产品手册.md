# SecAgent 产品手册

## 1. 产品定位

SecAgent 是一个面向企业安全运营中心（SOC）的智能安全分析与响应系统。

它的核心目标不是做一个单纯的日志解析 Demo，而是把真实 WAF 日志、Redis 实时事件流、规则检测、RAG 知识库、企业上下文、自动分诊、告警状态流转、可选 LLM 报告和前端 SOC 控制台串成一条可运行的安全运营闭环。

当前产品更适合用于：

```text
WAF 安全告警分析演示
SOC 告警研判流程原型
企业安全知识库增强分析
LLM 在安全运营中的低成本辅助场景验证
本机或单服务器 WAF 链路演示
```

当前产品不等同于完整 SIEM / SOAR 平台，也不默认执行真实封禁、工单派发或生产处置动作。

## 2. 核心业务闭环

当前已经实现的主链路如下：

```text
攻击请求 / 正常请求
  -> Nginx + ModSecurity + OWASP CRS WAF
  -> business-demo 或真实业务 upstream
  -> ModSecurity audit.log
  -> WafLogCollector
  -> Redis Stream: security:events
  -> EventConsumer
  -> SecurityAnalysisOrchestrator
  -> SecurityAlert
  -> Redis Stream: security:alerts
  -> SQLite alerts 表
  -> FastAPI 查询接口
  -> React SOC Console
```

分析链路如下：

```text
SecurityEvent
  -> LogParserAgent 规则解析
  -> LLMUnknownAttackClassifier 可选 Unknown 补识别
  -> DecisionAgent 风险评分和 ATT&CK 映射
  -> AnalysisPolicy 选择 fast / enriched / deep
  -> RAGAgent 可选知识库增强
  -> ThreatIntelAgent 可选威胁情报增强
  -> EventMemory 源 IP 历史行为记忆
  -> ContextAgent 企业上下文检索
  -> AutoTriagePolicy 自动分诊
  -> LongTermMemorySearch 可选相似历史事件回流
  -> LLMReportEnhancer 可选 LLM 分析师报告
  -> SessionMemory 保存追问上下文
  -> LongTermMemoryStore 可选长期分析记忆写入
```

## 3. 已实现功能

### 3.1 WAF 接入

系统支持通过 Docker Compose 启动本地 WAF：

```text
Nginx + ModSecurity + OWASP CRS
```

WAF 会把请求代理到：

```text
WAF_PROXY_PASS
```

默认上游是项目内置的 `business-demo`：

```text
http://business-demo:3000
```

本地访问链路：

```text
http://127.0.0.1:8080 -> WAF -> business-demo
```

当前支持过滤健康检查路径：

```text
WAF_COLLECTOR_IGNORED_PATHS=/__waf_health
```

### 3.2 日志采集与实时事件流

`WafLogCollector` 会读取 ModSecurity audit log，将日志转换为标准化安全事件：

```text
SecurityEvent
```

并写入 Redis Stream：

```text
security:events
```

`event_consumer` 从 `security:events` 读取事件，调用分析编排器生成告警，并写入：

```text
security:alerts
```

异常事件会进入预留死信流：

```text
security:deadletter
```

### 3.3 攻击识别

当前规则检测支持：

```text
SQL Injection
XSS
Path Traversal
Command Injection
SSRF
Brute Force
File Upload
Authentication Bypass
Automated Scanner
Unknown
```

检测依据包括：

```text
URL / path / query / raw_log
User-Agent
HTTP status
WAF rule_id
WAF message
OWASP CRS 规则编号
```

典型 OWASP CRS 映射：

```text
942xxx -> SQL Injection
941xxx -> XSS
930xxx -> Path Traversal
932xxx -> Command Injection
913xxx -> Automated Scanner
```

### 3.4 风险评分

系统会生成：

```text
risk_score
risk_level
score_breakdown
analysis_metadata
```

风险等级：

```text
0-39   -> low
40-69  -> medium
70-89  -> high
90-100 -> critical
```

评分来源包括：

```text
攻击类型基准分
WAF 是否拦截
WAF 规则命中
自动化扫描特征
RAG 知识库命中
威胁情报
历史行为记忆
```

### 3.5 RAG 安全知识库

当前知识库位于：

```text
backend/app/data/knowledge_base/
```

包含：

```text
attack_patterns.md
mitre_attack.md
owasp_crs.md
remediation.md
cve_examples.md
```

RAG 检索能力：

```text
Query Rewrite
BM25 检索
HybridRetriever
可选 Milvus 向量检索
引用、分数和命中原因输出
```

默认情况下，即使 Milvus 不可用，系统也会使用 BM25 正常分析。

当前已支持通过接口和前端页面维护 RAG 知识库：

```text
GET  /api/knowledge/documents
GET  /api/knowledge/documents/{source}
POST /api/knowledge/documents
POST /api/knowledge/documents/upload
前端 Knowledge 页面
```

上传的 Markdown 会保存到：

```text
backend/app/data/knowledge_base/
```

说明：

```text
JSON 上传适合在页面中直接粘贴或编辑 Markdown
文件上传适合导入已有 .md 安全文档
上传后当前 API 进程会刷新 RAG 缓存，BM25 检索可立即使用
如果启用了 Milvus 向量检索，仍需要执行 scripts/rebuild_knowledge_vectors.py --recreate 重建向量索引
已在运行的独立 consumer 进程不会自动加载新文档，需要重启 consumer
```

### 3.6 企业上下文检索

企业上下文位于：

```text
backend/app/data/context/
```

包含：

```text
asset_inventory.md
service_owners.md
scanner_whitelist.md
waf_policy.md
incident_playbook.md
change_calendar.md
```

当前会检索并提取：

```text
业务负责人
资产名称
资产重要性
扫描器白名单
WAF 策略
变更窗口
处置 playbook
```

### 3.7 自动分诊

`AutoTriagePolicy` 会根据风险、上下文和资产信息生成：

```text
status
automation_decision
triage_reason
requires_human_review
context_references
```

典型效果：

```text
低风险内部扫描器 -> 自动关闭或观察
高风险关键资产告警 -> 需要人工复核
业务 owner 明确的告警 -> 可通知对应负责人
```

当前不会自动执行真实封禁或工单动作，只给出分诊结论和建议。

### 3.8 告警持久化与状态流转

告警会写入 SQLite：

```text
data/secagent.db
```

当前支持：

```text
查询最近告警
按风险等级过滤
按状态过滤
按是否需要人工复核过滤
更新告警状态
填写 analyst_note
填写 handled_by
记录 handled_at
```

当前状态包括：

```text
auto_triaged
needs_review
investigating
resolved
false_positive
```

### 3.9 短期会话记忆与追问

每次分析会生成：

```text
AnalysisState
```

并保存到 Redis：

```text
security:result:{session_id}
security:session:{session_id}:*
```

当前支持通过接口读取分析上下文，也支持基于该上下文进行追问：

```text
GET  /api/analysis/{session_id}/result
POST /api/analysis/{session_id}/ask
```

追问只读取保存的分析状态，不会重新跑检测，也不会修改风险评分或告警状态。
当前前端告警详情页已提供 Follow-up 对话框，可以围绕某个告警进行多轮追问。
前端会把当前对话的最近若干轮消息随 `history` 一起提交给后端，便于 LLM 理解“那为什么不是误报？”这类依赖上一轮的问题。

### 3.10 长期分析记忆

当前已经实现可选 Milvus 长期分析记忆：

```text
secagent_analysis_memory
```

写入内容来自：

```text
SecurityAlert + AnalysisState
```

长期记忆会保存：

```text
alert_id
session_id
source_ip
target
attack_type
risk_level
business_owner
asset_criticality
status
automation_decision
summary
evidence_text
recommendation_text
analyst_note
handled_by
handled_at
```

当前支持：

```text
高价值告警写入长期记忆
相似历史事件检索
在 enriched / deep 分析中回流相似历史事件
将相似事件追加到 evidence
将相似事件追加到 Markdown 报告
```

默认关闭：

```text
LONG_TERM_MEMORY_ENABLED=false
LONG_TERM_MEMORY_SEARCH_ENABLED=false
```

### 3.11 LLM 能力

当前 LLM 是可选模块，默认关闭：

```text
LLM_ENABLED=false
```

已实现两类能力：

```text
Unknown 攻击类型补识别
高价值告警 Markdown 分析师报告增强
```

LLM 不负责：

```text
替代规则引擎
直接修改风险评分
自动执行封禁
自动修改告警状态
```

支持 OpenAI-compatible 接口，当前配置兼容 DashScope：

```text
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
LLM_MODEL=qwen3-max
```

### 3.12 前端 SOC 控制台

前端使用 React + TypeScript + Vite。

入口：

```text
http://127.0.0.1:5173
```

当前页面支持：

```text
告警列表
风险等级展示
状态展示
源 IP / 目标 / 置信度展示
按风险等级过滤
按状态过滤
只看需要人工复核
告警详情展示
评分拆解展示
启用 / 跳过模块展示
AutoTriage 展示
LLM Report 元数据展示
Evidence 展示
Recommendations 展示
MITRE ATT&CK 展示
Markdown 报告展示
告警状态更新
分析员备注填写
处理人填写
告警详情内多轮 Follow-up 追问
Knowledge 页面查看知识库文档
Knowledge 页面上传或粘贴 Markdown 安全文档
```

## 4. 主要接口

### 4.1 健康检查

```text
GET /api/health
```

返回：

```json
{
  "status": "ok",
  "message": "SecRAG-agent-backend"
}
```

### 4.2 单条事件分析

```text
POST /api/analyze
```

输入：

```json
{
  "source_ip": "45.67.89.10",
  "method": "GET",
  "url": "/login?id=1' OR '1'='1",
  "path": "/login",
  "query": "id=1' OR '1'='1",
  "status": 403,
  "user_agent": "sqlmap/1.7",
  "waf_rule_id": "942100",
  "waf_message": "SQL Injection Attack Detected",
  "raw_log": "demo"
}
```

输出：

```text
SecurityAlert
```

### 4.3 查询告警

```text
GET /api/alerts/recent
```

支持参数：

```text
count
risk_level
status
requires_human_review
```

示例：

```text
GET /api/alerts/recent?count=20
GET /api/alerts/recent?risk_level=critical
GET /api/alerts/recent?status=needs_review
GET /api/alerts/recent?risk_level=high&requires_human_review=true
```

### 4.4 更新告警状态

```text
PATCH /api/alerts/{alert_id}/status
```

示例：

```json
{
  "status": "resolved",
  "analyst_note": "WAF 已拦截，业务负责人确认无影响。",
  "handled_by": "analyst"
}
```

### 4.5 查询分析上下文

```text
GET /api/analysis/{session_id}/result
```

返回：

```text
AnalysisState
```

### 4.6 分析结果追问

```text
POST /api/analysis/{session_id}/ask
```

示例：

```json
{
  "question": "为什么这个告警是 critical？",
  "history": []
}
```

### 4.7 知识库文档管理

```text
GET  /api/knowledge/documents
GET  /api/knowledge/documents/{source}
POST /api/knowledge/documents
POST /api/knowledge/documents/upload
```

JSON 上传示例：

```json
{
  "filename": "custom_playbook.md",
  "content": "# Custom Playbook\n\n## SQL Injection\n\nUse parameterized queries.",
  "overwrite": false
}
```

文件上传说明：

```text
仅支持 UTF-8 Markdown .md 文件
同名文件默认返回 409，需要 overwrite=true 才会覆盖
BM25 检索在 API 进程刷新缓存后可用
Milvus 向量索引需要手动重建
```

## 5. 运行方式

### 5.1 快速样例日志演示

适合不启动 WAF，只验证后端分析链路。

第一个终端：

```powershell
docker compose up -d redis
python scripts\clear_redis.py
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

第二个终端：

```powershell
cd frontend
npm install
npm run dev
```

打开：

```text
http://127.0.0.1:5173
```

### 5.2 WAF 链路演示

适合验证真实 WAF 日志进入系统。

```powershell
docker compose up -d redis waf
python scripts\clear_redis.py
python scripts\simulate_attack.py all
cd backend
python -m app.collector.waf_log_collector --from-start
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
```

前端：

```powershell
cd frontend
npm run dev
```

### 5.3 持续运行模式

Collector 持续采集：

```powershell
cd backend
python -m app.collector.waf_log_collector --follow
```

Consumer 持续消费：

```powershell
cd backend
python -m app.services.event_consumer --follow
```

注意：持续消费依赖 Redis。若出现：

```text
consumer redis error: Error 10061 connecting to localhost:6379
```

说明 Redis 没有启动或 Docker Desktop 没有运行。

## 6. 关键配置

### 6.1 Redis

```text
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_EVENT_STREAM=security:events
REDIS_ALERT_STREAM=security:alerts
REDIS_DEADLETTER_STREAM=security:deadletter
```

### 6.2 WAF

```text
WAF_PORT=8080
WAF_BASE_URL=http://127.0.0.1:8080
WAF_PROXY_PASS=http://business-demo:3000
MODSEC_RULE_ENGINE=on
WAF_AUDIT_LOG_PATH=data/waf_logs/modsecurity/audit/audit.log
WAF_COLLECTOR_IGNORED_PATHS=/__waf_health
```

### 6.3 数据库

```text
SECAGENT_DB_PATH=data/secagent.db
DATABASE_URL=
```

默认使用 SQLite。代码层面支持通过 `DATABASE_URL` 切换到其他 SQLAlchemy 支持的数据库。

### 6.4 LLM

```text
LLM_ENABLED=false
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
LLM_API_KEY=
LLM_MODEL=qwen3-max
LLM_ONLY_FOR_REVIEW=true
LLM_MIN_RISK_LEVEL=high
LLM_UNKNOWN_CLASSIFIER_ENABLED=false
```

### 6.5 Embedding 与 Milvus

```text
EMBEDDING_ENABLED=false
EMBEDDING_MODEL=text-embedding-v4
EMBEDDING_API_KEY=
EMBEDDING_DIMENSION=1024
MILVUS_ENABLED=false
MILVUS_HOST=localhost
MILVUS_PORT=19530
MILVUS_KNOWLEDGE_COLLECTION=secagent_knowledge_chunks
MILVUS_MEMORY_COLLECTION=secagent_analysis_memory
```

重建知识库向量：

```powershell
python scripts\rebuild_knowledge_vectors.py --recreate
```

### 6.6 长期记忆

```text
LONG_TERM_MEMORY_ENABLED=false
LONG_TERM_MEMORY_SEARCH_ENABLED=false
LONG_TERM_MEMORY_MIN_RISK_LEVEL=high
LONG_TERM_MEMORY_WRITE_AUTO_CLOSED=false
LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE=false
```

## 7. 演示攻击样例

脚本：

```powershell
python scripts\simulate_attack.py all
```

当前包含：

```text
normal
sqli
xss
path_traversal
order_json
```

典型结果：

```text
normal -> HTTP 200
sqli -> HTTP 403
xss -> HTTP 403
path_traversal -> HTTP 403
order_json -> HTTP 403
```

## 8. 常见问题

### 8.1 前端打不开 127.0.0.1:5173

通常原因：

```text
frontend dev server 没启动
端口 5173 没有监听
```

启动：

```powershell
cd frontend
npm run dev
```

### 8.2 consumer 连接 Redis 失败

报错：

```text
Error 10061 connecting to localhost:6379
```

通常原因：

```text
Redis 没启动
Docker Desktop 没启动
6379 端口没有监听
```

解决：

```powershell
docker compose up -d redis
```

如果 Docker 报错连接不到 Docker API，需要先启动 Docker Desktop。

### 8.3 前端没有告警

可能原因：

```text
Redis 没有事件
consumer 没跑
告警没有写入数据库
前端过滤条件过窄
backend API 没启动
```

检查顺序：

```powershell
docker compose up -d redis
python scripts\publish_sample_logs.py
cd backend
python -m app.services.event_consumer
uvicorn app.main:app --reload --port 8000
cd ..\frontend
npm run dev
```

### 8.4 WAF 没有日志

可能原因：

```text
WAF 容器没启动
没有请求经过 WAF
audit.log 尚未生成
MODSEC_AUDIT_ENGINE 配置影响日志输出
```

可以先运行：

```powershell
python scripts\simulate_attack.py all
```

## 9. 当前能力边界

已经实现：

```text
WAF 日志接入
Redis 实时事件流
规则攻击识别
可选 LLM Unknown 补识别
风险评分和评分拆解
RAG 知识库增强
可选 Milvus 知识库向量检索
企业上下文检索
AutoTriage 自动分诊
SQLite 告警持久化
告警状态更新
短期 AnalysisState 记忆
基于 AnalysisState 的追问
可选 LLM 报告增强
可选 Milvus 长期分析记忆写入
可选相似历史事件回流
React SOC 控制台
本地 business-demo WAF 演示上游
```

尚未实现：

```text
/api/memories 长期记忆管理接口
前端 Memories 页面
长期记忆 enable / disable 管理
真实外部威胁情报 API 接入
真实自动封禁动作
工单系统集成
用户登录和权限控制
生产级多租户
生产级审计日志
```

## 10. 推荐演示话术

可以这样介绍项目：

```text
SecAgent 是一个面向 SOC 的 WAF 告警智能分析系统。
它从真实 WAF audit log 开始，把日志转换成标准事件，通过 Redis Stream 进入分析流水线。
系统先用规则和 WAF 命中信息识别攻击类型，再结合本地安全知识库、企业资产上下文、历史行为记忆和可选 LLM 生成可解释告警。
告警会进入数据库，前端 SOC 控制台可以按风险和状态过滤，并支持人工更新处置状态。
对于高价值事件，系统还可以把分析摘要沉淀到 Milvus 长期记忆中，后续类似事件会自动引用历史处置经验。
```
