# 隔离维护站 · 设备指令委托链裁决服务（MDMS Decision）

外部签发的设备指令**委托包**进入隔离维护站后，值班员在提交前需要确认：每一级
权限只会**收窄**、每一级都是父主体对子主体的真实签名、末级凭据**一次性**使用、
被**撤销/过期/越权/篡改**的请求不得驱动设备。本服务提供真实接口完成逐级裁决，
并将每一次裁决**持久化**：相同叶项的并发提交、响应丢失后的重传，都在一次
裁决中收敛为**一次执行**与**同一回执**，重启后仍可复核。

值班员完成逐级核验后，可先取得一份**可复核的执行凭据**：核验通过才签发，凭据
与当时**规范化后的裁决身份**（根公钥 / 链摘要 / 叶项标识 / 规范载荷 → request_digest）
持久化绑定。值班员核对凭据上绑定的链与载荷摘要后，从核验结果直接**确认执行**；
确认时服务对页面当前提交的委托包与请求**重新完整裁决**并与凭据绑定逐项复核，
任何设备、命令、签名字段或请求载荷变化都明确拒绝且不驱动设备。两个页面并发使用
同一凭据确认同一请求，仍只收敛为既有的一次执行与同一稳定回执；重启后相同确认
复核原结果。凭据未使用期间链项过期、被撤销或原执行裁决不再允许时，旧凭据无法
绕过既有安全检查。

## 安全模型

- 输入只接受**规范 UTF-8 JSON**（严格 UTF-8、禁止重复键、JCS 风格规范化），
  签名对象一律是规范化后的字节。
- 委托链为 **Ed25519**：根项由 `root_pubkey` 自签（`parent_digest` 为 64 个 0），
  其后每一项由父项主体（`subject_pubkey`）签发。
- 每个子项的 `parent_digest` 必须等于父项 `header` 规范字节的 SHA-256；
  `devices` 与 `commands` 都必须相对父项为**真子集（严格收窄）**。
- 任一项 `expires_at <= now` 即拒；请求载荷须由**叶项主体**签名，且
  `device` / `command` 落在叶项范围内。
- 撤销采用包级、根公钥签署的 CRL（`revocations`），避免在链内引用下游摘要产生
  依赖环。撤销目标一旦验签通过即写入**站内全局持久名册**：之后即使提交方剥离
  撤销声明重传，命中名册的项仍被拒绝。
- 裁决身份由四要素共同决定：`root_pubkey`、`chain_digest`、`leaf_id`、
  规范载荷字节 → `request_digest`。
- 持久层用 SQLite 单写事务（`BEGIN IMMEDIATE`）串行化临界区：同 `request_digest`
  永远返回同一历史回执；同 `leaf_id` 只可能执行一次（再次驱动 → `LEAF_CONSUMED`）。
  篡改签名、越权命令、过期、撤销等只产生 `REJECTED` 记录，**绝不留下执行记录**。
- **执行凭据**持久化于 `confirm_tokens` 表：核验通过才签发，绑定规范化裁决身份
  四要素；确认执行时先对当前输入重新完整裁决，再在同一写事务内逐项比对凭据
  绑定，任一不一致即 `CONFIRM_TOKEN_MISMATCH`（不写裁决、不驱动设备）。凭据与
  直接执行接口共用同一执行临界区，因此两入口、并发页面与重启重放都收敛为同一
  条裁决；凭据未使用期间的撤销/过期/一次性检查在确认时重新生效，旧凭据无法
  绕过。

拒因（按检查顺序，界面展示“首个拒因”）：
`MALFORMED_JSON` → `PACKET_STRUCTURE` → `ROOT_KEY_INVALID` → `CHAIN_EMPTY` →
`ITEM_STRUCTURE` → `PARENT_DIGEST_MISMATCH` → `SIGNATURE_INVALID` →
`SCOPE_NOT_NARROWED` → `EXPIRED` → `REVOCATION_INVALID` → `REVOKED` →
`PAYLOAD_STRUCTURE` → `PAYLOAD_SIGNATURE_INVALID` → `DEVICE_OUT_OF_SCOPE` →
`COMMAND_OUT_OF_SCOPE`；运行期：`LEAF_CONSUMED`；
执行凭据确认：`CONFIRM_TOKEN_NOT_FOUND`（凭据不存在/标识非法）、
`CONFIRM_TOKEN_MISMATCH`（确认输入与凭据绑定的裁决身份不一致）。

## 目录

```
app/canonical.py   规范 JSON / Ed25519 验签
app/chain.py       委托链纯裁决逻辑（逐级校验、首个拒因、视图）
app/store.py       SQLite 持久化裁决（幂等、一次性凭据、撤销名册、执行凭据、回执）
app/device.py      受控设备模拟执行器（确定性 command_id）
app/drill.py       两套内置演练包（确定性种子密钥，跨重启稳定）
app/main.py        FastAPI：核验 / 执行凭据签发/确认 / 执行 / 回执 / 台账 / 健康 / 值班界面
app/static/        无外部依赖的值班页面
tests/             63 个单元 / 并发 / HTTP / 重启复核测试
verify/            verify 验收容器入口（HTTP 场景 + pytest）
```

## 本地运行（不使用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
MDMS_DB_PATH=./data/mdms.db uvicorn app.main:app --host 0.0.0.0 --port 8000
# 打开 http://localhost:8000 ：“加载内置演练包” → “逐级核验并签发执行凭据”
#   → 核对凭据绑定摘要 → “凭执行凭据确认执行”（也可直接发起一次执行）
pytest -q
```

## Docker / Compose

宿主端口可通过 `MDMS_HOST_PORT` 配置（默认 8080），数据在命名卷 `mdms-data`
中持久化，`app` 自带容器健康检查并暴露 `GET /healthz`：

```bash
MDMS_HOST_PORT=18080 docker compose up -d --build app
curl -s http://localhost:18080/healthz
```

### verify 验收容器

`verify` 服务等待 `app` 健康后运行：有效执行、并发重传收敛、篡改/越权/过期/
撤销拒绝、执行凭据（签发/复核/确认/篡改与撤销阻断/并发收敛）、API/HTTP 冒烟，
并运行全部 pytest；**以退出状态码报告结果后退出**：

```bash
docker compose build
docker compose run --rm verify            # 只跑验收（app 可在线或由 compose 管理）
docker compose up --build --abort-on-container-exit verify   # 一键：起 app + 验收
docker inspect -f '{{.State.ExitCode}}' mdms-verify         # 0=通过 非0=失败
```

## HTTP 接口

| 方法 路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康响应（含执行记录数） |
| `GET  /` | 值班界面（粘贴委托包与请求、逐级展示、执行、台账） |
| `GET  /api/drill` | 内置有效/撤销两套演练包的可粘贴文本 |
| `POST /api/inspect` | 只核验不落盘：逐级签名、父子主体、范围、失效、首个拒因 |
| `POST /api/credential/issue` | 核验通过才签发**执行凭据**（失败不产生凭据）；凭据与规范化裁决身份持久绑定 |
| `GET  /api/credential/{token_id}` | 复核凭据：标识、绑定的链与载荷摘要、`ISSUED`/`USED` 状态 |
| `POST /api/credential/confirm` | 重新裁决当前输入并与凭据绑定逐项复核后执行；变化即拒，不驱动设备 |
| `POST /api/execute` | 持久化裁决并执行（幂等；兼容旧流程，返回信封 + 稳定回执） |
| `GET  /api/receipt/{request_digest}` | 按裁决标识复核回执（重启后逐字一致） |
| `GET  /api/decisions?limit=` | 持久化裁决台账 |

执行/核验请求体：

```json
{
  "packet_text": "{\"root_pubkey\":\"…\",\"chain\":[{\"header\":{…},\"signature\":\"…\"}]}",
  "request_text": "{\"payload\":{\"device\":\"dev-alpha\",\"command\":\"status\",\"nonce\":\"…\"},\"payload_signature\":\"…\"}"
}
```

凭据确认请求体在上述两字段外增加 `"token_id"`（32 位十六进制）。典型流程：
`POST /api/credential/issue` 通过核验取得 `credential.token_id` 与绑定摘要 →
值班员核对 → `POST /api/credential/confirm` 携带页面当前的委托包/请求文本与
`token_id`；并发或重启后的相同确认返回 `duplicate: true` 与同一回执，不重复驱动。
`CONFIRM_TOKEN_MISMATCH` / `CONFIRM_TOKEN_NOT_FOUND` 不写任何裁决记录。
