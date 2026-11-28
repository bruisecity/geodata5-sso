# geodata5-sso

Geodata5 统一身份认证中心：**OAuth 2.1 / OIDC 授权服务器 + yelu-cas（Jasig CAS 3.5.2）协议兼容层**。

实现依据：架构文档 revision 28（2026-11-27 修订 1）及当日生产证据关闭的 T-11/T-12/T-14/T-16/T-18。核心契约事实：

- CAS 响应**属性名即元素名**（`<cas:userId>`），每属性一行——用真实 cas-client-core 3.2.1 解析器验证过，非标准 CAS XML；
- 生产实发 **7 个属性**（username/userId/realName/workFor/email/mobile/createdFrom，无 isEnabled）——2026-11-27 生产抓包 golden sample 已固化为测试基线；
- 双挂载前缀（`/login` 与 `/cas/login`）均可认证（T-14：生产挂载在根路径，双前缀保留防存量写死 `/cas`）；`CASTGC` cookie path=`/`；TGT max 8h / idle 2h；ST 一次使用 + 10 秒；
- 一期端点集（其余端点**不存在**是正确性属性，不是遗漏）：`login / logout / validate / serviceValidate / proxyValidate / CentralAuthenticationService（+captcha.jpg）`；
- 旧密码 `hex_md5(pw+"{"+username+"}")` 原值只读比对 + 同事务 BCrypt 升级（旧列 varchar(50) 装不下 BCrypt 60 字符，BCrypt 只存新系统自有表 `sso_user_credential`）；
- enabled=0 在**登录步**即拒绝（与生产实测一致，响应不下发 isEnabled）。

## 快速开始

```bash
# 本地（H2 内存库，开箱即用）
mvn -B test && mvn -B -q jar:jar spring-boot:repackage
java -jar target/geodata5-sso.jar          # http://localhost:9000/login

# 生产形态（PG16 + Redis7）
cd deploy && docker compose up -d          # 见 deploy/README.md
```

种子账号：`zhangsan / Passw0rd!`、`legacy_user / legacy123`（后者走旧摘要双校验路径）。

## 三类接入示例

### 1. 存量 Java Web 应用（CAS 客户端，零改造继续跑）

```java
// web.xml 保持不变（cas-client-core 3.x filter 配置原样）
// serverName 指向新地址即可，例如：
//   http://auth.geodata5.cn/login        （生产实际挂载形态，根路径）
//   http://auth.geodata5.cn/cas/login    （若存量方写死了 /cas 前缀，同样可用）
```

登录后客户端回调 `serviceValidate` 校验 ST，按属性名取用户信息：`assertion.getAttributes().get("userId")` 等 7 个名字与旧系统逐字一致。

### 2. 新应用（Spring Security 5+/6+ OAuth2 客户端，OIDC 授权码）

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          geodata5:
            provider: geodata5
            client-id: demo-web            # 向管理员注册换取
            client-secret: demo-web-secret
            authorization-grant-type: authorization_code
            redirect-uri: "{loginBaseUrl}/login/oauth2/code/{registrationId}"
            scope: openid,profile,email
        provider:
          geodata5:
            issuer-uri: http://localhost:9000   # discovery 自动生效
```

### 3. 服务间调用（client credentials，纯后端）

```bash
curl -u demo-service:demo-service-secret \
     -d "grant_type=client_credentials&scope=api.read" \
     http://localhost:9000/oauth2/token
# -> {"access_token":"…","token_type":"Bearer","expires_in":600}
curl -H "Authorization: Bearer …" http://localhost:9000/api/me
```

## 配置速查

| 键 | 默认 | 说明 |
|---|---|---|
| `sso.cas.mount-paths` | `[/cas, ""]` | 双前缀；生产按根路径挂载，保留 `/cas` 兜底 |
| `sso.cas.ticket-cookie-path` | `/` | T-14 定案 |
| `sso.cas.service-registry-mode` | `LENIENT` | 宽松=service 非空即放行；改 `STRICT` 强制注册表 |
| `sso.cas.service-ticket-ttl` | `10s` | ST 一次使用 + 10 秒（源码真实值） |
| `sso.cas.ticket-granting-ticket-max-lifetime` | `8h` | TGT 上限 |
| `sso.cas.ticket-granting-ticket-idle-timeout` | `2h` | TGT 空闲超时 |
| `sso.legacy.upgrade-password-on-login` | `true` | 登录成功同事务写 BCrypt + 升级标记 |
| `sso.legacy.enabled-literal` | `TRUE_FALSE` | 仅历史兼容开关；生产不下发 isEnabled，此处无效果 |

属性回传由 `cas_attribute_mapping` 表驱动（名字/顺序/是否下发均为数据，改表即生效，不改代码）。

## 目录

```
src/main/java/cn/geodata/sso/
  cas/        CAS 兼容层：protocol（渲染器/失败码）、attr（表驱动装配）、ticket（TGT/ST 注册表）、
              service（落库服务注册）、web（端点 + 前缀重写过滤器）、captcha
  config/     SecurityConfig（双安全链）、AuthorizationServerConfig、BootstrapSeeder
  user/       旧库只读仓储 + 双密码认证 Provider
  oauth/      token customizer
deploy/       Dockerfile、docker-compose.yml（app+PG16+Redis7）、application-prod.yml、.env.example
docs/         plan.md（2/3 周两档开发计划）、verification.md（真实验证记录）
sql/          生产 PostgreSQL DDL
```

## 已知边界（详见 docs/verification.md「未验证项」）

- PostgreSQL/Redis 真实连接、授权码+PKCE 浏览器全流程：部署侧联调项，沙箱未验证；
- 二期及以后：CAS 代理链、第三方联邦 Provider 接入、T-15（user/CASold 表）绑定流程；
- JWK 为启动时生成——**生产必须换持久化密钥**，否则重启令牌全部失效。
