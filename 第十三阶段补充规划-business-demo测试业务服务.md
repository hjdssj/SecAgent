# 第十三阶段补充规划：business-demo 测试业务服务

## 一、补充背景

第十三阶段已经完成了单服务器部署形态：

```text
redis
waf
backend
frontend
collector
consumer
```

其中 WAF 已经支持：

```text
WAF_PROXY_PASS
```

也就是说，WAF 可以作为反向代理，把请求转发到真实业务服务。

但目前还缺一个稳定、可控、可演示的 upstream 服务。

如果直接接真实业务，会有几个问题：

```text
误报可能影响真实业务
接口不可控，攻击样例不一定稳定
演示环境不容易复现
不方便测试 SQL Injection / XSS / Path Traversal
```

因此建议新增一个轻量的 `business-demo` 测试业务服务，专门用于验证：

```text
WAF 反向代理是否可用
ModSecurity 是否能生成 audit.log
collector 是否能采集真实 WAF 日志
consumer 是否能生成告警
前端 SOC 控制台是否能看到告警
```

## 二、目标定位

`business-demo` 不是安全分析系统的一部分，也不是风味功能。

它的定位是：

```text
被 WAF 保护的测试业务 upstream
```

它模拟一个普通 Web 业务，让 WAF 有真实请求可以转发。

目标链路：

```text
用户 / 攻击请求
  -> WAF: http://127.0.0.1:8080
  -> WAF_PROXY_PASS=http://business-demo:3000
  -> business-demo
  -> ModSecurity audit.log
  -> collector
  -> Redis security:events
  -> consumer
  -> DB alerts 表
  -> frontend SOC console
```

## 三、为什么需要这个服务

### 1. 验证 WAF 真实代理能力

当前 WAF 有健康检查：

```text
/__waf_health
```

但健康检查只能证明 WAF 容器活着，不能证明：

```text
WAF 能否代理业务
代理请求头是否正确
请求 path / query / body 是否经过 WAF
ModSecurity 是否真的观察到业务请求
```

`business-demo` 可以补齐这个验证。

### 2. 稳定触发攻击样例

需要稳定接口：

```text
/login?id=...
/search?q=...
/download?file=...
/api/order
```

这些接口可以让攻击样例稳定命中 WAF 规则。

### 3. 避免误伤真实业务

初期 WAF 建议使用：

```text
MODSEC_RULE_ENGINE=DetectionOnly
```

但即使是 DetectionOnly，也不建议一开始就接真实业务。

先用 `business-demo` 观察：

```text
日志格式
告警链路
误报情况
前端展示
```

确认无误后再接真实业务。

### 4. 方便答辩和演示

演示时可以直接说明：

```text
这是一个模拟业务服务
WAF 位于业务服务前面
攻击请求先经过 WAF
WAF 生成审计日志
SecAgent 对日志进行实时分析
SOC 控制台展示告警
```

这比只用样例日志更像真实部署场景。

## 四、建议目录结构

新增：

```text
infra/business-demo/
  Dockerfile
  main.py
  requirements.txt
```

可选新增：

```text
tests/test_business_demo.py
```

后续修改：

```text
docker-compose.prod.yml
docs/deployment.md
docs/demo_guide.md
README.md
.env.example
.env
scripts/simulate_attack.py
scripts/deploy_check.py
```

## 五、技术选型

建议使用：

```text
FastAPI
uvicorn
```

原因：

```text
项目后端本身已经使用 FastAPI
实现简单
启动快
接口清晰
便于 Docker 化
便于后续写测试
```

`business-demo` 不需要数据库，不需要 Redis，不需要复杂业务逻辑。

## 六、接口设计

### 1. 健康检查

```text
GET /
```

返回：

```json
{
  "service": "business-demo",
  "status": "ok"
}
```

用途：

```text
验证 WAF 能否成功代理 upstream
```

### 2. 登录接口

```text
GET /login?id=1
```

返回：

```json
{
  "page": "login",
  "id": "1"
}
```

攻击样例：

```text
/login?id=1' OR '1'='1
```

目标：

```text
触发 SQL Injection 规则
```

### 3. 搜索接口

```text
GET /search?q=test
```

返回：

```json
{
  "page": "search",
  "q": "test"
}
```

攻击样例：

```text
/search?q=<script>alert(1)</script>
```

目标：

```text
触发 XSS 规则
```

### 4. 下载接口

```text
GET /download?file=readme.txt
```

返回：

```json
{
  "page": "download",
  "file": "readme.txt"
}
```

攻击样例：

```text
/download?file=../../etc/passwd
```

目标：

```text
触发 Path Traversal 规则
```

### 5. 订单接口

```text
POST /api/order
```

请求体：

```json
{
  "sku": "demo",
  "quantity": 1,
  "comment": "normal"
}
```

攻击样例：

```json
{
  "sku": "demo",
  "quantity": 1,
  "comment": "<script>alert(1)</script>"
}
```

目标：

```text
验证 JSON body 是否经过 WAF
```

## 七、Docker Compose 规划

在 `docker-compose.prod.yml` 中新增：

```yaml
business-demo:
  build:
    context: .
    dockerfile: infra/business-demo/Dockerfile
  container_name: secagent-business-demo
  restart: unless-stopped
  ports:
    - "${BUSINESS_DEMO_PORT:-3000}:3000"
```

然后将 WAF 默认 upstream 改为：

```text
WAF_PROXY_PASS=http://business-demo:3000
```

服务依赖关系：

```text
waf depends_on business-demo
```

部署链路：

```text
business-demo
  <- waf
  <- user traffic
```

## 八、环境变量规划

新增：

```text
BUSINESS_DEMO_ENABLED=true
BUSINESS_DEMO_HOST=0.0.0.0
BUSINESS_DEMO_PORT=3000
WAF_PROXY_PASS=http://business-demo:3000
```

说明：

```text
BUSINESS_DEMO_PORT - 暴露给宿主机的端口
WAF_PROXY_PASS - WAF 容器访问 upstream 的地址
```

如果后续接真实业务：

```text
WAF_PROXY_PASS=http://真实业务服务地址
```

即可替换掉 demo 服务。

## 九、攻击模拟脚本调整

当前：

```text
scripts/simulate_attack.py
```

已经能向：

```text
WAF_BASE_URL
```

发送攻击请求。

建议新增：

```text
order_json
```

用于 POST JSON body 测试。

攻击样例：

```text
normal
sqli
xss
path_traversal
order_json
all
```

## 十、部署检查脚本调整

当前：

```text
scripts/deploy_check.py
```

建议新增检查：

```text
business-demo direct health
WAF proxy to business-demo
```

检查 URL：

```text
http://127.0.0.1:3000/
http://127.0.0.1:8080/
```

通过条件：

```text
business-demo 返回 service=business-demo
WAF 代理访问也返回 service=business-demo
```

这样可以明确证明：

```text
WAF -> upstream 代理链路可用
```

## 十一、测试规划

### 单元测试

如果将 business-demo 放在 repo 中，可以新增：

```text
tests/test_business_demo.py
```

测试：

```text
GET /
GET /login
GET /search
GET /download
POST /api/order
```

### Compose 配置测试

继续验证：

```powershell
docker compose -f docker-compose.prod.yml config
```

### 端到端手动验证

启动：

```powershell
docker compose -f docker-compose.prod.yml up -d --build
```

检查：

```powershell
python scripts\deploy_check.py
```

发送攻击：

```powershell
python scripts\simulate_attack.py all
```

查看：

```text
http://127.0.0.1:5173
```

预期：

```text
SOC 控制台出现 SQL Injection / XSS / Path Traversal 告警
```

## 十二、验收标准

满足以下条件即可认为补充阶段完成：

```text
business-demo 可以独立启动
WAF 可以代理 business-demo
/__waf_health 仍然可用
访问 WAF / 可以返回 business-demo 响应
攻击请求可以经过 WAF
ModSecurity 可以生成 audit.log
collector 可以采集 audit.log
consumer 可以生成告警并入库
前端 SOC 控制台可以看到告警
docker compose -f docker-compose.prod.yml config 通过
pytest 通过
frontend build 通过
部署文档更新完成
```

## 十三、暂不做

本补充阶段暂不做：

```text
真实用户登录
真实数据库业务
复杂业务页面
真实漏洞实现
故意写不安全 SQL 查询
文件真实读取
支付 / 订单完整业务
HTTPS
生产级业务服务
```

说明：

```text
business-demo 只是模拟被保护业务，不应该真的包含可利用漏洞。
攻击检测由 WAF 对请求特征完成，而不是依赖业务服务真的存在漏洞。
```

## 十四、风险与注意事项

### 1. 不要写真实漏洞

接口只回显参数即可。

不要实现：

```text
真实 SQL 拼接
真实文件读取
真实命令执行
```

### 2. 保持接口稳定

攻击样例要长期稳定。

这样：

```text
演示可靠
测试可靠
WAF 告警可复现
```

### 3. WAF 模式建议

本阶段仍建议：

```text
MODSEC_RULE_ENGINE=DetectionOnly
```

如果要展示阻断效果，再切换：

```text
MODSEC_RULE_ENGINE=on
```

## 十五、开发顺序规划

### Step 1：新增 business-demo 文件

新增：

```text
infra/business-demo/main.py
infra/business-demo/requirements.txt
infra/business-demo/Dockerfile
```

### Step 2：实现接口

实现：

```text
GET /
GET /login
GET /search
GET /download
POST /api/order
```

### Step 3：接入 docker-compose.prod.yml

新增：

```text
business-demo service
```

调整：

```text
WAF_PROXY_PASS=http://business-demo:3000
waf depends_on business-demo
```

### Step 4：调整 simulate_attack.py

新增：

```text
order_json
```

### Step 5：调整 deploy_check.py

新增：

```text
business-demo direct check
WAF proxy check
```

### Step 6：更新文档

更新：

```text
docs/deployment.md
docs/demo_guide.md
README.md
工作日志.md
```

### Step 7：验证

执行：

```powershell
D:\anaconda\envs\machinelearning\python.exe -m compileall backend\app scripts tests
D:\anaconda\envs\machinelearning\python.exe -m pytest
cd frontend
npm run build
docker compose -f docker-compose.prod.yml config
```

可选端到端：

```powershell
docker compose -f docker-compose.prod.yml up -d --build
python scripts\deploy_check.py
python scripts\simulate_attack.py all
```

## 十六、简历描述方向

完成后可以这样描述：

```text
为 SecRAG Agent 单服务器部署链路设计并实现可控测试业务 upstream，使用 FastAPI 构建 business-demo 服务模拟登录、搜索、文件下载和订单等典型业务接口。
通过 WAF_PROXY_PASS 将 Nginx + ModSecurity WAF 接入业务服务前置，实现攻击请求经过 WAF、生成 audit log、实时采集入 Redis、自动分析入库并在 SOC 控制台展示的端到端验证链路。
```

## 十七、完成记录

### 完成时间

2026-06-07

### 已完成内容

```text
已新增 infra/business-demo FastAPI 测试业务服务
已提供 GET /、GET /login、GET /search、GET /download、POST /api/order
已将 business-demo 接入 docker-compose.yml 和 docker-compose.prod.yml
已将 WAF 默认 upstream 调整为 http://business-demo:3000
已扩展 simulate_attack.py，支持 order_json JSON body 攻击样例
已扩展 deploy_check.py，检查 business-demo 直连和 WAF 代理链路
已新增 tests/test_business_demo.py
已修复 WAF 容器 healthcheck，使其检查 /__waf_health
```

### 验证结果

```text
D:\anaconda\envs\machinelearning\python.exe -m compileall backend\app scripts tests infra\business-demo
结果：通过

D:\anaconda\envs\machinelearning\python.exe -m pytest
结果：27 passed

docker compose -f docker-compose.prod.yml config
结果：通过

docker compose -f docker-compose.prod.yml up -d --build
结果：business-demo、waf、redis、backend、frontend、collector、consumer 均可启动

python scripts\deploy_check.py
结果：Redis、Backend、Frontend、WAF、WAF audit log、Business demo、WAF proxy 均通过

python scripts\simulate_attack.py all
结果：normal 返回 200，sqli / xss / path_traversal / order_json 返回 403
```

### 当前结论

```text
本机已经可以不依赖外部服务器完整跑通 WAF 演示链路：

攻击请求
  -> http://127.0.0.1:8080
  -> WAF
  -> business-demo
  -> ModSecurity audit.log
  -> collector
  -> Redis security:events
  -> consumer
  -> Redis security:alerts
  -> DB alerts
  -> 前端 SOC 控制台
```
