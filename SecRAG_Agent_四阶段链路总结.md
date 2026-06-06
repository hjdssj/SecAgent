# SecRAG Agent 前四阶段链路总结

## 一、当前阶段位置

当前项目已经推进到第四阶段。

```text
第一阶段：单条日志分析，已完成
第二阶段：样例日志回放，已完成
第三阶段：Redis Stream 实时事件流，已完成
第四阶段：真实 WAF 接入与日志采集，已完成基础闭环
```

前四阶段完成后，项目已经从“手动输入 JSON 的 toy demo”升级为“可以接入 WAF 日志并自动生成安全告警的实时分析系统雏形”。

## 二、第一阶段链路：单条日志分析

第一阶段目标是打通最小 Agent 分析链路。

核心链路：

```text
POST /api/analyze
  -> SecurityEvent
  -> LogParserAgent
  -> ParsedSecurityEvent
  -> DecisionAgent
  -> SecurityAlert
```

主要文件：

```text
backend/app/models/event.py
backend/app/models/alert.py
backend/app/agents/log_parser_agent.py
backend/app/agents/decision_agent.py
backend/app/agents/orchestrator.py
backend/app/api/analyze.py
backend/app/main.py
```

实现能力：

```text
接收单条安全事件
识别 SQL Injection / XSS / Path Traversal / Command Injection / Scanner
生成风险分数和风险等级
生成 MITRE ATT&CK 映射
生成 evidence、recommendations 和 Markdown 报告
```

## 三、第二阶段链路：样例日志回放

第二阶段目标是从手动 JSON 输入升级为批量读取样例日志。

核心链路：

```text
data/sample_logs/*.log
  -> scripts/replay_sample_logs.py
  -> ModSecurityParser
  -> SecurityEvent
  -> SecurityAnalysisOrchestrator
  -> SecurityAlert
  -> reports/*.md
```

主要文件：

```text
backend/app/collector/modsecurity_parser.py
scripts/replay_sample_logs.py
data/sample_logs/*.log
reports/
```

实现能力：

```text
从 key=value 格式样例日志中提取 source_ip、method、url、status、user_agent、rule_id、message
将日志标准化为 SecurityEvent
批量生成安全告警
为真实 WAF 日志采集做了解析层准备
```

## 四、第三阶段链路：Redis Stream 实时事件流

第三阶段目标是从一次性脚本回放升级为事件流处理。

核心链路：

```text
scripts/publish_sample_logs.py
  -> Redis Stream: security:events
  -> backend/app/services/event_consumer.py
  -> SecurityAnalysisOrchestrator
  -> Redis Stream: security:alerts
  -> GET /api/alerts/recent
```

主要文件：

```text
docker-compose.yml
backend/app/storage/redis_client.py
backend/app/services/event_consumer.py
backend/app/api/alerts.py
scripts/publish_sample_logs.py
```

Redis Stream：

```text
security:events
security:alerts
security:deadletter
```

实现能力：

```text
将 SecurityEvent 写入 Redis Stream
从 Redis Stream 消费事件并生成告警
将 SecurityAlert 写入 Redis Stream
通过 API 查询最近告警
形成实时分析系统的消息流雏形
```

## 五、第四阶段链路：真实 WAF 接入

第四阶段目标是接入 Nginx + ModSecurity + OWASP CRS，让真实 HTTP 攻击请求产生 WAF 日志，再进入 SecRAG 分析链路。

核心链路：

```text
curl / simulate_attack.py
  -> Nginx + ModSecurity + OWASP CRS
  -> data/waf_logs/modsecurity/audit/audit.log
  -> WafLogCollector
  -> SecurityEvent
  -> Redis Stream: security:events
  -> event_consumer.py
  -> Redis Stream: security:alerts
  -> GET /api/alerts/recent
```

主要文件：

```text
infra/waf/Dockerfile
infra/waf/default.conf
docker-compose.yml
backend/app/collector/waf_log_collector.py
scripts/simulate_attack.py
data/waf_logs/
```

实现能力：

```text
通过 docker compose 启动 Redis 和 WAF
将 WAF 的 Nginx 日志和 ModSecurity audit 日志挂载到本地
从真实 ModSecurity JSON audit log 中提取请求、响应和规则命中信息
将 WAF 日志转换为 SecurityEvent
复用第三阶段 Redis Stream 分析链路生成告警
```

## 六、前四阶段整体闭环

完整链路如下：

```text
攻击请求
  -> WAF
  -> WAF audit log
  -> waf_log_collector.py
  -> SecurityEvent
  -> Redis security:events
  -> event_consumer.py
  -> LogParserAgent
  -> DecisionAgent
  -> SecurityAlert
  -> Redis security:alerts
  -> /api/alerts/recent
```

这条链路体现了项目目前的核心价值：

```text
不是用户手动提交日志让系统分析
而是 WAF 持续产生安全日志
SecRAG Agent 自动采集、标准化、分析并生成告警
```

## 七、第四阶段验证命令

启动基础服务：

```powershell
docker compose up -d --build redis waf
```

发送攻击流量：

```powershell
python scripts\simulate_attack.py all
```

采集 WAF 日志：

```powershell
cd backend
python -m app.collector.waf_log_collector --from-start
```

消费安全事件：

```powershell
python -m app.services.event_consumer
```

启动 API：

```powershell
uvicorn app.main:app --reload --port 8000
```

查询告警：

```text
http://127.0.0.1:8000/docs
GET /api/alerts/recent
```

## 八、后续阶段衔接

前四阶段解决的是“真实日志进来并自动生成基础告警”。

后续阶段继续增强：

```text
第五阶段：RAG 安全知识库，补充 CVE / ATT&CK / CRS / 修复建议引用
第六阶段：ThreatIntel + Memory，补充 IP 信誉、历史行为和上下文研判
第七阶段：前端 SOC 控制台，展示告警列表、详情、证据和报告
第八阶段：测试、README、演示脚本和工程化收尾
```
