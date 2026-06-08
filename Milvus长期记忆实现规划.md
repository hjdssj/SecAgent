# Milvus 长期记忆实现规划

## 目标

把当前项目中的长期记忆从“规划占位”升级为真实可用的 Milvus 向量检索能力。

Milvus 在本项目中承担两类职责：

```text
1. 安全知识库向量检索
   将本地 Markdown 知识库 chunks 写入 Milvus，增强 RAG 的语义召回。

2. 跨会话长期分析记忆
   将高质量历史告警、分析摘要、人工处置结论写入 Milvus，支持相似事件检索和经验复用。
```

Milvus 不作为事实数据库，不替代 SQLite / MySQL。告警状态、人工备注、处理人、处理时间仍以关系数据库为准。

## 当前代码基础

当前已经具备：

```text
backend/app/rag/knowledge_loader.py
  读取 backend/app/data/knowledge_base/*.md
  按 ## 二级标题切分为 KnowledgeChunk

backend/app/rag/hybrid_retriever.py
  已经支持 BM25 + VectorRetriever 混合召回

backend/app/rag/vector_retriever.py
  当前是空实现，后续可替换为 Milvus 检索

backend/app/analysis/state.py
  保存一次分析的 AnalysisState

backend/app/memory/session_memory.py
  保存 Redis session 上下文

backend/app/repositories/alert_repository.py
  持久化告警、状态和人工备注
```

当前还没有：

```text
pymilvus 依赖
embedding client
Milvus collection 初始化
知识库向量写入脚本
长期记忆写入逻辑
相似历史事件检索逻辑
/api/memories 管理接口
前端 memories 页面
```

## 总体架构

```text
知识库 Markdown
  -> KnowledgeLoader
  -> KnowledgeChunk
  -> EmbeddingClient
  -> Milvus: secagent_knowledge_chunks
  -> MilvusVectorRetriever
  -> HybridRetriever
  -> RAGAgent

SecurityAlert + AnalysisState + analyst_note
  -> LongTermMemoryBuilder
  -> EmbeddingClient
  -> Milvus: secagent_analysis_memory
  -> LongTermMemoryRetriever
  -> Orchestrator enriched/deep 模式
  -> Alert evidence / report / follow-up answer context
```

## Collection 设计

### 1. 知识库 collection

名称：

```text
secagent_knowledge_chunks
```

用途：

```text
保存知识库 Markdown 切分后的 chunk 向量
用于 RAG 的语义召回
```

字段：

```text
chunk_id           varchar primary key
doc_id             varchar
source             varchar
title              varchar
category           varchar
tags_json          varchar/text
content            varchar/text
content_hash       varchar
created_at         varchar
embedding          float_vector
```

索引建议：

```text
embedding: COSINE / HNSW 或 AUTOINDEX
doc_id: scalar index
category: scalar index
source: scalar index
```

### 2. 长期分析记忆 collection

名称：

```text
secagent_analysis_memory
```

用途：

```text
保存跨会话安全分析经验
支持相似事件检索
支持历史处置经验复用
```

字段：

```text
memory_id           varchar primary key
alert_id            varchar
session_id          varchar
source_ip           varchar
target              varchar
attack_type         varchar
risk_level          varchar
business_owner      varchar
asset_criticality   varchar
status              varchar
automation_decision varchar
summary             varchar/text
evidence_text       varchar/text
recommendation_text varchar/text
analyst_note        varchar/text
handled_by          varchar
handled_at          varchar
created_at          varchar
enabled             bool
embedding           float_vector
```

索引建议：

```text
embedding: COSINE / HNSW 或 AUTOINDEX
attack_type: scalar index
risk_level: scalar index
source_ip: scalar index
target: scalar index
enabled: scalar index
```

## Embedding 设计

建议先做抽象层，避免绑定某一家 API。

新增目录：

```text
backend/app/embedding/
```

建议文件：

```text
schemas.py
config.py
client.py
dashscope_client.py
fallback.py
```

统一接口：

```text
EmbeddingClient.embed_text(text: str) -> list[float]
EmbeddingClient.embed_texts(texts: list[str]) -> list[list[float]]
```

配置：

```text
EMBEDDING_PROVIDER=dashscope
EMBEDDING_MODEL=text-embedding-v4
EMBEDDING_API_KEY=
EMBEDDING_BASE_URL=
EMBEDDING_DIMENSION=1024
EMBEDDING_TIMEOUT_SECONDS=30
```

说明：

```text
如果使用 DashScope embedding，可以复用 DASHSCOPE_API_KEY
如果没有 embedding API，则 Milvus 写入和向量检索降级关闭
BM25 仍可工作
```

## Milvus 配置

`.env.example` 建议新增：

```text
MILVUS_ENABLED=false
MILVUS_HOST=localhost
MILVUS_PORT=19530
MILVUS_USER=
MILVUS_PASSWORD=
MILVUS_DATABASE=default
MILVUS_KNOWLEDGE_COLLECTION=secagent_knowledge_chunks
MILVUS_MEMORY_COLLECTION=secagent_analysis_memory
MILVUS_INDEX_TYPE=AUTOINDEX
MILVUS_METRIC_TYPE=COSINE
MILVUS_TOP_K=5
```

Docker Compose 建议新增可选服务：

```text
milvus
etcd
minio
```

为了两天内可控，也可以先用 Milvus standalone 镜像或 Zilliz Cloud，避免本机 compose 过重。

## 开发阶段

### 第一阶段：Embedding 抽象层

目标：

```text
新增 embedding 配置
新增 EmbeddingClient 接口
新增 DashScopeEmbeddingClient
新增 disabled/fallback 行为
```

验收：

```text
无 API key 时不会影响系统启动
有 API key 时可以生成固定维度向量
单元测试使用 fake embedding client，不访问外网
```

测试：

```text
tests/test_embedding_client.py
```

## 第二阶段：Milvus 基础客户端

目标：

```text
新增 backend/app/milvus/
实现连接管理
实现 collection exists / create / load
实现 insert / search / delete / upsert 风格封装
```

建议文件：

```text
backend/app/milvus/config.py
backend/app/milvus/client.py
backend/app/milvus/schemas.py
```

验收：

```text
MILVUS_ENABLED=false 时所有 Milvus 调用安全降级
Milvus 不可达时主分析链路不中断
测试使用 fake Milvus client
```

测试：

```text
tests/test_milvus_client.py
```

## 第三阶段：知识库向量化

目标：

```text
将 KnowledgeChunk 写入 secagent_knowledge_chunks
实现知识库重建脚本
实现 MilvusVectorRetriever 替换空 VectorRetriever
HybridRetriever 继续保留 BM25 + Vector 混合召回
```

建议新增：

```text
backend/app/rag/milvus_vector_retriever.py
scripts/rebuild_knowledge_vectors.py
tests/test_milvus_vector_retriever.py
```

重建脚本：

```powershell
python scripts\rebuild_knowledge_vectors.py
```

脚本行为：

```text
读取 backend/app/data/knowledge_base/*.md
切分 chunks
计算 content_hash
只写入新增或变更 chunk
支持 --recreate 清空重建 collection
```

验收：

```text
HybridRetriever 在 Milvus 可用时返回 vector/hybrid 结果
Milvus 不可用时自动退回 BM25
RAG 报告仍包含引用、score 和 reason
```

## 第四阶段：长期分析记忆写入

目标：

```text
新增 LongTermMemoryBuilder
新增 LongTermMemoryStore
分析结束或告警处理完成后写入 secagent_analysis_memory
```

建议文件：

```text
backend/app/memory/long_term_schemas.py
backend/app/memory/long_term_builder.py
backend/app/memory/milvus_memory_store.py
```

写入策略建议：

```text
默认不把所有 low 噪声写入长期记忆
high / critical 默认可写入候选长期记忆
resolved / false_positive / 带 analyst_note 的告警优先写入高质量长期记忆
auto_close 的低危扫描器默认不写入
```

配置：

```text
LONG_TERM_MEMORY_ENABLED=false
LONG_TERM_MEMORY_MIN_RISK_LEVEL=high
LONG_TERM_MEMORY_WRITE_AUTO_CLOSED=false
LONG_TERM_MEMORY_REQUIRE_ANALYST_NOTE=false
```

验收：

```text
告警生成后可生成长期记忆摘要
符合策略的告警可写入 Milvus
Milvus 写失败不影响告警生成和状态更新
```

## 第五阶段：相似历史事件检索

目标：

```text
分析 enriched / deep 模式时检索 secagent_analysis_memory
将相似历史事件加入 evidence / report_markdown
追问接口可引用相似历史事件作为上下文
```

建议新增：

```text
LongTermMemoryRetriever.search_similar(alert/state)
```

报告展示：

```text
## 长期记忆相似事件

- alert_id: ...
- attack_type: ...
- risk_level: ...
- similarity: ...
- analyst_note: ...
- handled_at: ...
```

验收：

```text
相似事件能被检索回来
禁用的 memory 不参与检索
检索结果有来源和相似度
```

## 第六阶段：/memories 管理接口

目标：

```text
让前端和用户可以管理长期记忆
避免错误经验长期污染检索
```

API：

```text
GET /api/memories
GET /api/memories/{memory_id}
POST /api/memories/search
PATCH /api/memories/{memory_id}
DELETE /api/memories/{memory_id}
POST /api/memories/{memory_id}/disable
POST /api/memories/{memory_id}/enable
```

第一版可以只做后端 API，不急着做前端页面。

## 第七阶段：前端 Memories 页面

目标：

```text
新增长期记忆管理页面
展示 memory 列表、详情、来源告警、相似检索结果
支持 enable / disable
支持按攻击类型、风险等级、IP、资产过滤
```

建议文件：

```text
frontend/src/api/memories.ts
frontend/src/types/memory.ts
frontend/src/components/MemoryTable.tsx
frontend/src/components/MemoryDetail.tsx
```

## 与现有链路的关系

### RAG 知识库

```text
当前：BM25 + 空 VectorRetriever
目标：BM25 + MilvusVectorRetriever
```

Milvus 不可用时：

```text
HybridRetriever 自动只使用 BM25
系统仍可正常分析
```

### Redis 记忆

```text
Redis 继续负责短期 session、追问上下文、IP 行为记忆
Milvus 只负责长期语义检索
```

### 数据库

```text
数据库仍是告警事实源
Milvus memory_id 应引用 alert_id / session_id
人工处理状态仍以 DB 为准
```

## 推荐实施顺序

为了降低风险，建议不要一口气做完所有阶段。

优先做：

```text
1. Embedding 抽象层
2. Milvus 基础客户端
3. 知识库向量化
```

这三步完成后，RAG 就能从“BM25 为主”升级为“BM25 + Milvus 语义召回”。

然后再做：

```text
4. 长期分析记忆写入（已完成）
5. 相似历史事件检索（已完成）
6. /memories 管理接口
7. 前端 Memories 页面
```

## 当前落地状态

截至 2026-06-07，已经完成：

```text
Embedding 抽象层
Milvus 基础客户端
知识库向量化脚本
HybridRetriever 使用可选 Milvus vector results
长期分析记忆写入
相似历史事件检索并回流到 evidence / report_markdown
```

长期记忆当前已具备：

```text
LongTermMemoryPolicy
LongTermMemoryBuilder
LongTermMemoryStore
secagent_analysis_memory collection 创建、写入和底层检索封装
Orchestrator 分析结束后的 long_term_memory workflow step
Orchestrator enriched / deep 分析中的 long_term_memory_search workflow step
相似历史事件命中后追加到告警 evidence 和 Markdown 报告
```

仍未完成：

```text
/api/memories 管理接口
前端 Memories 页面
长期记忆清理和治理策略
```

## 需要确认的问题

开发前需要确认：

```text
1. Milvus 使用本地 Docker，还是 Zilliz Cloud？
2. Embedding 使用 DashScope text-embedding-v4，还是本地 BGE？
3. 长期记忆是否默认写入 high/critical，还是必须人工处理后写入？
4. 是否允许把 analyst_note 写入 Milvus？
5. Milvus 数据是否需要清理策略，例如只保留最近 90 天？
```

## 最小可交付版本

如果时间有限，建议最小版本做到：

```text
Milvus 可启动
知识库 chunks 可写入 Milvus
HybridRetriever 能使用 Milvus vector results
Milvus 不可用时自动 fallback 到 BM25
pytest 通过
README / docs 说明如何重建向量索引
```

暂缓：

```text
长期分析记忆写入
/memories 管理接口
前端 Memories 页面
```

这样最短路径可以先增强当前 RAG 效果，而不是一次性引入过多业务状态。
