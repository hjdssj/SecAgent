# SecRAG Agent 后续开发规划

## 一、项目完整场景

SecRAG Agent 是一个面向企业 SOC 的 RAG 增强安全告警分析与响应系统。

系统目标不是替代 WAF，也不是把所有日志都交给大模型，而是在企业已有 WAF、日志、知识库、资产文档和威胁情报基础上，构建一条成本可控、可解释、可闭环的安全事件研判链路。

完整业务链路：

```text
WAF / Nginx 日志
  -> Redis Stream 实时事件流
  -> LogParser 解析标准化事件
  -> DecisionAgent 识别攻击类型和基础风险
  -> AnalysisPolicy 选择 fast / enriched / deep 分析模式
  -> RAG 检索安全知识和企业上下文
  -> ThreatIntel 查询或缓存 IP 信誉
  -> Redis Memory 分析短期历史行为
  -> AutoTriage 自动分流
  -> LLM 生成解释性报告
  -> Redis 推送实时告警
  -> 数据库存储告警状态和处置闭环
  -> 前端 SOC 控制台展示
```

核心价值：

```text
把 WAF 产生的大量原始安全告警，转化为带有攻击识别、企业上下文、风险解释、自动分流和处置闭环的 SOC 可执行告警。
```

## 二、当前已经具备的能力

目前项目已经完成或正在本地完成：

```text
1. 标准化 SecurityEvent / ParsedSecurityEvent / SecurityAlert
2. WAF / Nginx / 简化 ModSecurity 日志解析
3. LogParserAgent 攻击类型识别
4. DecisionAgent 基础风险评分
5. Redis Stream: security:events / security:alerts
6. event_consumer 消费事件并生成告警
7. 本地安全知识库
8. Query Rewrite
9. BM25Retriever
10. HybridRetriever 框架
11. VectorRetriever 预留接口
12. RAG 引用、score、reason 输出
13. 本地威胁情报 mock
14. Redis-backed EventMemory
15. fast / enriched / deep 成本控制分析模式
16. RiskScoreBreakdown
17. AnalysisMetadata
18. React SOC 告警展示
19. README、架构文档、演示文档、测试用例
```

说明：

```text
第九阶段和第十阶段当前已经在本地实现，但尚未提交到 GitHub。
```

## 三、当前还缺的核心能力

按照完整产品场景，后续还缺这些能力：

```text
1. 企业上下文 RAG
2. AutoTriage 自动分流
3. 告警状态与持久化数据库
4. LLM 报告生成器
5. 威胁情报真实 API 接入与缓存
6. 长短期记忆管理增强
7. 前端 SOC 闭环操作
8. 部署、CI、演示材料
```

其中最影响产品完整性的不是 LLM，而是：

```text
企业上下文 RAG
自动分流
告警持久化
```

## 四、存储分工

### Redis

Redis 用于：

```text
实时事件流
短期记忆
缓存
去重
```

建议保存：

```text
security:events
security:alerts
memory:ip:{source_ip}
intel:ip:{source_ip}
rag:cache:{query_hash}
dedup:alert:{fingerprint}
```

典型 TTL：

```text
IP 短期行为：1 小时 / 24 小时
威胁情报缓存：6 小时 / 24 小时
RAG 查询缓存：1 小时
去重 key：1 分钟 / 5 分钟
```

### 数据库

数据库用于：

```text
告警最终状态
自动分流结果
人工复核记录
处置备注
复盘历史
统计查询
```

建议默认：

```text
SQLite
```

生产预留：

```text
MySQL / PostgreSQL
```

### RAG 知识库

RAG 用于：

```text
安全知识
企业上下文
资产信息
负责人信息
白名单
WAF 策略
应急预案
变更窗口
```

一句话分工：

```text
Redis = 现在正在发生什么
数据库 = 这件事最终怎么处理
RAG = 公司知道些什么
```

## 五、后续阶段安排

## 第十一阶段：企业上下文 RAG 与自动分流设计

### 目标

把普通安全知识 RAG 扩展为：

```text
安全知识 RAG + 企业上下文 RAG
```

让系统可以自动回答：

```text
这个接口属于哪个业务？
负责人是谁？
目标资产是否高危？
源 IP 是否内部扫描器？
当前 WAF 规则是 block 还是 detect？
是否处于变更窗口？
是否需要人工复核？
```

### 需要新增的数据

建议新增：

```text
backend/app/data/context/
  asset_inventory.md
  service_owners.md
  scanner_whitelist.md
  waf_policy.md
  incident_playbook.md
  change_calendar.md
```

示例内容：

```text
/login 属于账号中心
业务负责人 account-team
资产等级 critical
10.10.3.8 是内部安全扫描器
OWASP CRS 942100 当前策略为 block
SQLi 告警应急预案要求回溯认证日志和数据库错误日志
```

### 需要新增的模块

建议新增：

```text
backend/app/context/
  __init__.py
  schemas.py
  context_loader.py
  context_retriever.py
  context_agent.py
```

建议新增：

```text
backend/app/triage/
  __init__.py
  schemas.py
  auto_triage_policy.py
```

### AutoTriage 输出

建议输出字段：

```text
status
automation_decision
triage_reason
requires_human_review
business_owner
asset_name
asset_criticality
context_references
```

建议状态：

```text
auto_triaged
needs_review
investigating
resolved
false_positive
```

建议自动化决策：

```text
observe_only
auto_close
notify_owner
block_ip_recommended
human_review_required
```

### 示例规则

```text
内部扫描器 + 低风险 + 白名单命中 -> auto_triaged / auto_close
外部 IP + SQLi + WAF 已阻断 + 中等级资产 -> auto_triaged / observe_only
高价值资产 + SQLi + 恶意 IP -> needs_review / human_review_required
低置信度 + 上下文不足 -> needs_review
涉及封禁建议 -> needs_review
```

### 需要的 API

本阶段最少需要：

```text
无新增外部 API
```

原因：

```text
第十一阶段主要在分析链路内部补企业上下文和自动分流结果。
现有 /api/analyze 和 /api/alerts/recent 返回的 SecurityAlert 增加字段即可。
```

如果前端需要查看上下文引用详情，后续可再增加：

```text
GET /api/alerts/{alert_id}
```

但不建议当前阶段为了“看起来完整”强行新增。

## 第十二阶段：告警持久化与闭环状态

### 目标

引入数据库保存告警最终状态和复核信息。

### 数据库建议

默认：

```text
SQLite
```

通过环境变量预留：

```text
DATABASE_URL
```

### 需要新增的模块

```text
backend/app/db/
  __init__.py
  session.py
  models.py
  init_db.py

backend/app/repositories/
  __init__.py
  alert_repository.py
```

### alerts 表建议字段

```text
alert_id
event_id
attack_type
risk_score
risk_level
source_ip
target
confidence
evidence_json
mitre_attack_json
recommendations_json
report_markdown
analysis_mode
score_breakdown_json
analysis_metadata_json
status
automation_decision
triage_reason
requires_human_review
business_owner
asset_name
asset_criticality
context_references_json
analyst_note
handled_by
handled_at
created_at
updated_at
```

### 数据写入链路

```text
event_consumer
  -> SecurityAnalysisOrchestrator.analyze()
  -> SecurityAlert
  -> Redis security:alerts
  -> DB alerts 表
```

同时：

```text
/api/analyze
  -> SecurityAlert
  -> DB alerts 表
```

### 需要的 API

本阶段需要的 API：

```text
GET /api/alerts/recent
PATCH /api/alerts/{alert_id}/status
```

其中：

```text
GET /api/alerts/recent
```

需要支持：

```text
count
status
requires_human_review
```

用于前端列表筛选。

```text
PATCH /api/alerts/{alert_id}/status
```

用于：

```text
接受系统自动研判
进入人工复核
标记已解决
标记误报
填写备注
记录处理人
```

请求体建议：

```json
{
  "status": "resolved",
  "analyst_note": "WAF 已阻断，未发现后端异常，已通知账号中心负责人复核。",
  "handled_by": "analyst"
}
```

可选 API：

```text
GET /api/alerts/{alert_id}
```

如果前端详情完全依赖列表选中项，可以先不做。

## 第十三阶段：LLM 报告生成与解释增强

### 目标

让 LLM 负责解释和归纳，而不是直接负责攻击判定。

LLM 输入：

```text
攻击类型
WAF 证据
RAG 安全知识
企业上下文
威胁情报
Memory 历史行为
RiskScoreBreakdown
AutoTriage 结果
```

LLM 输出：

```text
Markdown 安全分析报告
自动分流理由
业务可执行处置建议
复核要点
```

### 需要新增的模块

```text
backend/app/llm/
  __init__.py
  schemas.py
  prompt_builder.py
  report_generator.py
  fallback_report.py
```

### 触发策略

不要每条日志都调用 LLM。

建议触发：

```text
analysis_mode = deep
requires_human_review = true
上下文较复杂
证据冲突
需要生成正式报告
```

不建议触发：

```text
低风险 fast 模式
重复告警
已知内部扫描器
自动关闭事件
```

### 需要的 API

本阶段可以不新增 API。

原因：

```text
LLM 报告生成是分析链路内部能力，最终结果仍然写入 SecurityAlert.report_markdown。
```

如果后续需要人工重新生成报告，再新增：

```text
POST /api/alerts/{alert_id}/regenerate-report
```

但当前不建议先做。

## 第十四阶段：真实威胁情报与缓存

### 目标

把本地 mock 情报升级为真实情报接入，同时保持可演示和可降级。

候选来源：

```text
AbuseIPDB
VirusTotal
AlienVault OTX
GreyNoise
```

### 关键设计

```text
本地 mock 优先保证演示稳定
外部 API 可选开启
Redis 缓存查询结果
API 失败时降级到 local_mock
不把 API key 写进代码
```

### 需要新增

```text
.env.example
backend/app/intel/providers/
backend/app/intel/cache.py
```

### 需要的 API

本阶段不一定需要对外新增 API。

原因：

```text
威胁情报查询仍然是分析链路内部能力。
```

如果前端需要单独查询 IP，可后续新增：

```text
GET /api/intel/ip/{source_ip}
```

当前阶段不建议强行做。

## 第十五阶段：长期记忆与统计复盘

### 目标

基于数据库中的历史告警，形成长期复盘能力。

短期记忆：

```text
Redis memory:ip:*
```

长期历史：

```text
DB alerts 表
```

可以统计：

```text
某 IP 历史攻击次数
某接口被攻击次数
某规则误报率
某业务线高危告警数量
平均处理时长
未处理告警数量
```

### 需要新增的模块

```text
backend/app/analytics/
  __init__.py
  alert_stats.py
  ip_profile.py
  asset_profile.py
```

### 需要的 API

本阶段如果要做前端统计面板，需要：

```text
GET /api/analytics/summary
GET /api/analytics/top-sources
GET /api/analytics/top-targets
GET /api/analytics/status-counts
```

如果暂时不做统计前端，则这些 API 可以后置。

## 第十六阶段：前端 SOC 闭环体验

### 目标

让前端从“告警展示台”升级为“SOC 操作台”。

建议展示：

```text
自动分流状态
是否需要人工复核
自动化决策
业务负责人
资产等级
上下文引用
评分拆解
处理备注
处理人
处理时间
```

建议操作：

```text
接受自动研判
进入人工复核
标记已解决
标记误报
填写备注
按状态筛选
按是否需要复核筛选
```

### 需要的 API

依赖第十二阶段：

```text
GET /api/alerts/recent
PATCH /api/alerts/{alert_id}/status
```

如果前端需要详情页独立刷新，再增加：

```text
GET /api/alerts/{alert_id}
```

## 第十七阶段：部署、CI 与演示材料

### 目标

让项目可以稳定演示和交付。

建议补充：

```text
docker-compose backend / frontend
.env.example
GitHub Actions
演示脚本
架构图
前端截图
答辩讲稿
最终 README polish
```

### 需要的 API

不新增业务 API。

本阶段主要是工程交付。

## 六、推荐开发顺序

建议后续顺序：

```text
1. 先提交当前第九、十阶段代码
2. 第十一阶段：企业上下文 RAG + AutoTriage
3. 第十二阶段：告警持久化 + 状态更新
4. 第十三阶段：LLM 报告生成
5. 第十四阶段：真实威胁情报 + Redis 缓存
6. 第十五阶段：长期记忆与统计复盘
7. 第十六阶段：前端 SOC 闭环体验
8. 第十七阶段：部署、CI、演示材料
```

如果时间紧，最小闭环版本建议只做：

```text
第十一阶段
第十二阶段
第十三阶段的 fallback LLM 报告生成或模板报告增强
```

## 七、当前最需要的 API 清单

按照真实需要，而不是风味功能，当前明确需要的 API 只有这些：

### 已有并需要保留

```text
GET /api/health
POST /api/analyze
GET /api/alerts/recent
```

### 第十二阶段需要新增或增强

```text
GET /api/alerts/recent?count=20&status=needs_review&requires_human_review=true
PATCH /api/alerts/{alert_id}/status
```

### 可能需要，但可以后置

```text
GET /api/alerts/{alert_id}
POST /api/alerts/{alert_id}/regenerate-report
GET /api/intel/ip/{source_ip}
GET /api/analytics/summary
GET /api/analytics/top-sources
GET /api/analytics/top-targets
GET /api/analytics/status-counts
```

不建议当前就做的 API：

```text
复杂工单 API
用户权限 API
通知 API
规则管理 API
知识库管理 API
```

原因：

```text
这些功能会显著拉长开发周期，而且当前项目还没有到需要它们支撑核心演示的阶段。
```

## 八、最终项目表达

完成上述阶段后，项目可以这样表达：

```text
SecRAG Agent 是一个面向企业 SOC 的 RAG 增强安全告警分析与响应系统。
系统接入 WAF 日志并通过 Redis Stream 构建实时事件流，基于规则和 WAF 命中信息完成快速攻击识别，
再根据风险等级动态选择 fast / enriched / deep 分析模式。
系统结合安全知识 RAG、企业上下文 RAG、威胁情报、短期行为记忆和风险评分拆解，对告警进行自动分流，
并在需要人工复核的高风险场景中生成 LLM 辅助分析报告。
最终告警会写入关系型数据库，支持状态流转、处理备注、复盘统计和前端 SOC 工作台闭环。
```

