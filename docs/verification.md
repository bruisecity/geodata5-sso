# 验证记录（真实命令与结果）

本文件只记录**实际运行过**的命令与输出。凡未验证的项，显式标注「未验证」与原因。
构建环境：沙箱（2C/4G），Temurin JDK 21.0.13.1，Maven 3.9.16，依赖经 Aliyun central 镜像拉取。

## 1. 单元测试（2026-11-28 实测）

```
rm -rf target && mvn -B test
```

结果（`/tmp/test.log`）：

```
Tests run: 5, Failures: 0, Errors: 0, Skipped: 0 -- ApplicationContextTest
Tests run: 9, Failures: 0, Errors: 0, Skipped: 0 -- CasResponseDialectTest
Tests run: 14, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

覆盖要点：
- **属性方言**：渲染出的 serviceValidate XML 喂给**真实的** cas-client-core 3.2.1 解析器（反射调用 `Cas20ServiceTicketValidator.extractCustomAttributes`），断言 7 个属性全部恢复；`golden/legacy-serviceValidate-success.xml`（2026-11-27 生产抓包原文）同样过真实解析器并与装配器输出做名字集合相等断言。
- **登录页字段名**：username / password / yzm / lt / execution / _eventId 逐字对齐（模板断言）。
- **enabled=0 登录步拒绝**（T-16 关闭后的复刻行为）：provider 抛 BadCredentialsException。
- **服务身份客户端**：无 redirectUri 的 client_credentials 客户端不得注册 authorization_code（RegisteredClient 不变量）。
- **映射表驱动**：cas_attribute_mapping 中 emitted=false 的行（isEnabled/roleId/roleName）不出现在响应。

## 2. 运行时冒烟（2026-11-28 实测）

打包（注意：沙箱文件系统 bug，见 §4）：

```
mvn -B -q jar:jar spring-boot:repackage
```

`java -jar target/geodata5-sso.jar` 启动（`Started Geodata5SsoApplication in 5.402 seconds`），随后逐端点探测（完整结果 `/tmp/smoke.json`）：

| 探测 | 结果 | 说明 |
|---|---|---|
| GET `/.well-known/openid-configuration` | **200** | issuer/authorization_endpoint 等元数据完整（本轮修复：需 `.oidc(withDefaults())`） |
| GET `/oauth2/jwks` | **200** | RSA JWKS 正常 |
| GET `/actuator/health` | 503 | 预期：沙箱无 Redis，聚合健康检查 DOWN；非缺陷（本地验证清单见 §5） |
| GET `/login`、`/cas/login` | **200** | 双前缀登录页均渲染，六个字段名逐字存在 |
| POST `/login`（legacy MD5 口令） | **302** `service?ticket=ST-…` | **本轮修复**：此前 405（原因见 §3） |
| POST `/cas/login` | **302** `service?ticket=ST-…` | 双前缀均可签发 ST（T-14） |
| POST `/login`（错误口令） | **302** `/login?error=…&service=…` | 错误回到原前缀并保留 service |
| GET `/cas/serviceValidate?service=…&ticket=<真实ST>` | **200** | 返回体与生产抓包完全同构，7 属性逐字对齐（见下） |
| GET `/cas/validate`、`/serviceValidate`（根前缀） | 200（协议失败响应） | CAS 1.0 `no\n\n` 与 CAS 2.0 INVALID_REQUEST 均按方言返回 |
| GET `/api/me`（无 token） | 401 | Bearer 入口正确 |
| GET `/cas/p3/serviceValidate`、`/cas/proxy`、`/cas/samlValidate` | **401**（无登录→未授权） | 端点不存在（无映射），落在安全链 401，不是 404 冒充——符合「不存在即正确」 |
| Set-Cookie（登录 302） | `CASTGC=…; Max-Age=28800; Path=/; HttpOnly` | TGT max 8h、cookie path 根路径（T-14/T-16 定案） |

真实 ST 校验响应体（与 2026-11-27 生产抓包同构，属性名为元素名、每属性一行）：

```xml
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'><cas:authenticationSuccess><cas:user>legacy_user</cas:user><cas:attributes>
<cas:username>legacy_user</cas:username>
<cas:userId>2002</cas:userId>
<cas:realName>李四</cas:realName>
<cas:workFor>地质调查院</cas:workFor>
<cas:email>lisi@geodata.cn</cas:email>
<cas:mobile>13800000002</cas:mobile>
<cas:createdFrom>LOCAL</cas:createdFrom>
</cas:attributes></cas:authenticationSuccess></cas:serviceResponse>
```

## 3. 本轮发现并修复的两个真实缺陷（均有失败先证）

1. **双前缀登录 POST 失效（T-14）**：冒烟探测发现 POST `/login` 返回 405，而 POST `/cas/login` 正常。根因：Spring Security 7 的 `PathPatternRequestMatcher` 命中路径时优先读 `ServletRequestPathUtils.PATH_ATTRIBUTE`（在安全链之前由原始 URI 解析缓存），`PrefixRewrittenRequest` 只覆写 `getRequestURI/getServletPath` 对所有路径匹配器不可见。修复：wrapper 的 `getAttribute` 对该属性返回按规范 URI 重新解析的 `RequestPath`。修复后双前缀均 302 签发 ST。
2. **OIDC discovery 404**：`authorizationServerChain` 从未 `.oidc(withDefaults())`，`OidcProviderConfigurationEndpointFilter` 未注册。修复后 discovery 200。

## 4. 构建环境已知问题（非项目缺陷，交付时如实说明）

- 沙箱 hpvs_fs 上 maven-resources-plugin 的「内容未变则跳过复制」比较路径抛 `FileDescriptor.close0 EINVAL`。项目资源本无 Maven 占位符，pom 中已将资源 filtering 显式关闭；**全新构建（`rm -rf target && mvn -B test`）不受影响**，仅 target/classes 已存在时的二次 package 会触发。打包用 `mvn -B -q jar:jar spring-boot:repackage` 绕过。
- 沙箱无 Redis：运行时票据注册表为进程内实现（架构 5.3 允许的 DefaultTicketRegistry 等价物），聚合健康检查 503 属预期。

## 5. 未验证项（诚实边界）

- **PostgreSQL / Redis 真实连接**：未验证。沙箱无 PG/Redis；`application-prod.yml`、docker-compose 仅供部署侧联调，schema 均为标准 PostgreSQL DDL（SAS 官方脚本 + 兼容层脚本）。
- **授权码 + PKCE 全流程**（浏览器端）：未在运行时点完。单测覆盖了客户端注册（含 public client 强制 PKCE 配置项）；建议部署后按 README「接入示例」用 demo-web 走一次。
- **验证码**：`captcha-required` 默认关闭（与生产抓包行为一致——生产登录流程未出现 yzm 必填）；CaptchaService 为占位实现，端点 `/captcha.jpg` 已注册。**未在运行时验证码开启态下测试**。
- **第三方登录联邦**：仅建表（user_identity_binding），无 Provider 接入——一期范围外。
- T-15（user/CASold 第二张表）：文档标记仍开放，按「两表并存、CASold 首次登录强制绑定」设计，未实现绑定流程（一期范围外，等业务确认）。
