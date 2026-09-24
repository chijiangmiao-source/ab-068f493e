# 海洋观测浮标 · 离线受限委托链验签系统

浮标失联时，岸站值班员在页面粘贴 **根公钥** 与 **按顺序排列的委托链和末端应急采样命令**。
系统对每份对象按同一套 **规范 JSON 字节（JCS / RFC 8785 风格）** 用 **P-256 ECDSA-SHA256**
逐跳验签，并强制约束只能逐级收紧，最终给出准许/拒绝结论。

纯 Node.js 20 实现，**无任何第三方依赖**（内置 WebCrypto、`node:test`、`node:http`）。

## 对象与信封字段

每份委托/命令是一个 JSON 对象：

| 字段 | 含义 |
| --- | --- |
| `issuer` / `subject` | 签发者 / 主体 P-256 公钥 JWK（`kty=EC, crv=P-256, x, y`） |
| `notBefore` / `notAfter` | 有效期（unix 秒，安全整数，`notBefore < notAfter`） |
| `allowedBuoys` | 允许浮标集合（非空、唯一字符串数组） |
| `sampleLimit` | 采样上限（整数 ≥ 1） |
| `kind` | `delegation` 或 `command`（命令只允许在链末端） |
| `command` | 仅末端命令：`{amount, buoy}` |
| `signature` | 对“去掉 `signature` 字段后的信封”做规范序列化，再以 issuer 私钥做 P-256 ECDSA-SHA256，base64url(r‖s) |

## 验签规则（按检查顺序，失败即定位首个违规点）

1. **链首签发者必须等于粘贴的根公钥**，否则 `ROOT_MISMATCH`（hop 0 / `issuer`）。
2. **每跳签名按同一套规范 JSON 字节验证**；改写已签名委托或命令内容 → `BAD_SIGNATURE`，定位失败跳与 `signature`，并给出规范载荷 SHA-256 摘要。
3. **后一跳签发者必须等于前一跳主体**，否则 `CHAIN_LINK`。
4. **只允许收紧**：`notBefore` 不减、`notAfter` 不增、`allowedBuoys` 为子集、`sampleLimit` 不增；违反 → `POLICY_RELAXED`，定位首个限制字段。
5. **末端准许**：当前时间必须落在每跳窗口内；末端浮标必须获得 **全部上游** 允许；采样量不得超过 **任一** 上游上限。违反 → `POLICY_DENIED`，定位首个上游跳与字段。

可定位的输入错误：重复键、非有限数（NaN/Infinity/1e999）、不安全整数（>2^53−1）、
对象键序不规范、越界整数、链首签发者不等于根公钥，均返回对象下标/跳号/字段/行列。

**证据隔离**：拒绝与错误草稿只写入 `data/denied/`；仅 `allow` 写入 `data/evidence/`，
绝不会覆盖上一份有效证据。页面端同样只在全部通过时更新本地留存。

## 目录结构

```
src/core/canonical.js  规范 JSON 序列化 + 严格解析（重复键/键序/安全整数/非有限数）
src/core/jwk.js        P-256 JWK 校验/导入/指纹/签名验签
src/core/verify.js     委托链逐跳验签引擎（服务端与页面共用）
src/core/issue.js      离线签发与演示链夹具（岸站页面不持私钥）
src/server.js          静态页面 + /healthz + POST /api/verify
public/                值班页面（直接以 ES Module 复用 src/core）
bin/verify.js          一次性验收可执行程序
scripts/build-check.js 页面构建检查
test/                  node:test 测试
```

## 本地运行

```bash
npm start                 # 默认 0.0.0.0:8080
PORT=9090 npm start       # 自定义宿主机端口
```

- 页面： http://localhost:8080/
- 健康： http://localhost:8080/healthz
- 验签 API：`POST /api/verify`，体为 `{"root": <JWK 文本或对象>, "chain": <数组文本或数组>}`

## Docker Compose

```bash
docker compose up --build shore         # 启动岸站（可配置宿主机端口）
HOST_PORT=9090 docker compose up shore  # 宿主机端口 9090 -> 容器 8080
docker compose run --rm verify          # 一次性验收（跑完即退，退出码即验收结果）
```

`docker-compose.yml` 提供两个服务：

- `shore`：静态页面 + 健康响应 + 验签 API，端口 `${HOST_PORT:-8080}:${PORT:-8080}`，证据持久化到 `shore-data` 卷。
- `verify`：名为 `verify` 的一次性验收服务，复核合法链逐跳证据、越权链拒绝、篡改签名拒绝、
  代码测试、页面构建检查以及健康地址 API/HTTP 冒烟，执行完毕即退出并以退出码报告结果。

## 一次性验收 verify

```bash
node bin/verify.js        # 或 npm run verify；容器内可直接执行 verify
echo $?                   # 0 = 全部通过
```

验收内容：

1. 合法链 ALLOW：每跳签名、签发者—主体链接、规范载荷摘要、收紧后约束交集；
2. 越权链：采样超限、上限放宽、根公钥不匹配的拒绝定位；
3. 篡改已签名内容：`BAD_SIGNATURE` 定位失败跳；
4. 证据隔离：deny 不覆盖 evidence；
5. `node --test test/` 全部测试；
6. 页面构建检查（语法/静态资源/模块导入）；
7. 启动真实 HTTP 服务做 `/healthz`、`/`、`/api/verify` 的 API/HTTP 冒烟。

## 测试

```bash
npm test      # node --test test/
npm run build # 页面构建检查
```
