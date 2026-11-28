# geodata5-sso 开发计划（修订版，对齐架构 revision 28 + 2026-11-27 生产证据）

两档：**2 周紧凑档（10 工作日）**、**3 周稳妥档（15 工作日）**。差异只有两处：第 11–15 天的
「存量回归 + 缓冲」是否包含，以及并行期灰度是否完整跑一轮。两档的前 10 天完全一致。
单人全职假设；如两人并行（一人 CAS 兼容层、一人 OAuth/OIDC 侧），紧凑档可压到 8 天。

## 状态基线（2026-11-28）

代码骨架已可编译、可启动、冒烟通过（见 verification.md），即下表 D1–D4 的「骨架」部分
已完成；计划中的天数按**剩余工作**折算标注。

## 2 周紧凑档

| 日 | 主题 | 前置 | 交付物 | 验收 |
|---|---|---|---|---|
| D1 | 环境与契约固化 | 无 | PG16+Redis7 compose 起本地栈；golden sample 入库为回归基线 | compose up 全绿；7 属性基线测试跑通 |
| D2 | CAS 兼容层精修 | D1 | 对齐 T-16/T-18 定案：enabled=0 登录步拒绝、真实 DDL 映射、旧摘要双校验联调（连真 PG） | 用种子旧密码登录→升级 BCrypt→二次登录走 BCrypt 全链路点通 |
| D3 | 服务注册表 + ST/TGT 语义 | D2 | cas_service_registry 落库 CRUD；ST 消费一次即失效、TTL 10s 实测；TGT idle 2h/max 8h | STRICT 模式拒绝未注册 service；重复用 ST 得 INVALID_TICKET |
| D4 | 授权码 + PKCE 全流程 | D1 | demo-web（机密客户端）+ demo-spa（public 强制 PKCE）浏览器端点通；token/jwks/introspection | 手工浏览器流程 + curl token 交换 + 错误路径（错 code、过期 code） |
| D5 | OIDC claims + userinfo | D4 | token customizer 下发 userId 等 claims；/userinfo；scope→claim 映射 | OIDC 客户端按 scope 拿到对应 claim |
| D6 | 旧库真连 + 迁移演练 | D1、D2 | 只读账号连 MySQL t_customer（S1）；38 万行只读查询压测 | 登录 P95 < 500ms（含 BCrypt 升级路径首登） |
| D7 | 管理面最小集 | D5 | 客户端注册/密钥轮换 CLI 或简单管理页；JWK 持久化 | 重启后 token 仍有效（JWK 不换） |
| D8 | 部署与上线准备 | D7 | Dockerfile/compose 定稿；生产 application-prod.yml；反向代理（根路径挂载）配置 | staging 环境全流程冒烟 |
| D9 | 存量应用试点接入 | D8 | 挑 1 个 CAS 客户端应用切到新地址（双前缀均验证） | 试点应用登录/校验/登出全通，属性 7 项逐字一致 |
| D10 | 验收与文档 | D9 | verification.md 补全真实结果；接入手册；回滚预案（DNS 切回旧 CasServer） | 一期验收单逐项打勾 |

## 3 周稳妥档（D1–D10 同上，追加）

| 日 | 主题 | 交付物 | 验收 |
|---|---|---|---|
| D11 | 存量应用批量接入（≤10 个） | 逐应用接入清单与 diff 复核 | 每个应用至少 1 次真实登录+校验 |
| D12 | 并行期灰度 | 旧 CasServer 与新系统并行；日志对比抽样 | 双系统 ST 语义一致；无重定向死循环 |
| D13 | 性能与故障演练 | 压测报告；Redis 降级路径（票据注册表回退） | 峰值 QPS 下的错误率达标 |
| D14 | 安全复核 | 密钥/secret 管理核验；审计留存检查 | 等保相关清单过一遍 |
| D15 | 缓冲 | 计划外问题 | — |

## 风险与降级路径

- **双前缀**：任何一天发现存量方依赖未覆盖的路径形态，扩 `mount-paths` 即可，端点注册是循环生成的，不改代码。
- **属性方言**：golden sample 测试在，任何人改渲染器都会被真实客户端解析器挡下；新增属性（T-17）只动 `cas_attribute_mapping` 表 + 白名单灰度，不发版。
- **STRICT 服务注册**：若存量 service 清单拿不全，保持 LENIENT 上线，事后逐条补注册再切 STRICT。
- **性能兜底**：票据注册表可平替为 Redis 实现（接口已抽离）；单机内存版本即旧系统 DefaultTicketRegistry 等价物，并行期单实例可接受。
- **回滚**：DNS/反代把 auth.geodata5.cn 指回旧 CasServer 即回滚；旧库未被写过（S1 只读），零数据回滚成本。

## 明确不做（一期与二期都不做，摘自架构 10.3）

`/cas/p3/*`、`/cas/proxy`、`/cas/samlValidate`（生产零调用已证）、`/cas/v1/tickets`、`/cas/openid/*`、
`/cas/oauth10login`、`/cas/services/*`、`/cas/status`；不新增 CAS 响应属性；不复刻旧系统安全缺陷。
