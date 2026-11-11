# agentmd-guard

扫 **Agent 会自动当指令读进来的那些文件**：`AGENTS.md`、`CLAUDE.md`、`AGENTS.local.md`、`CLAUDE.local.md`，
以及指挥 Agent 的配置：`.claude/settings.json`、`~/.codex/config.toml`、DSH 的 `cordis.patch.yml` /
`app-layer.patch.yml`、MCP 的 `.mcp.json`。

纯 Node（>=20）、零依赖、**全程只读**：只读文件，只写自己的基线与自测样本，不执行被扫内容里的任何东西。

## 安装

```sh
# 最省事
npx agentmd-guard scan

# 或全局装
npm i -g agentmd-guard

# 或者不装，直接跑（把仓库或 tarball 解开即可）
node bin/agentmd-guard.mjs scan

# 或者用 Releases 里的 tarball 本地装
npm i ./agentmd-guard-0.3.0.tgz
```

注意：**不要用 `npm i https://github.com/.../x.tgz` 这种远程 URL**——npm 12 起默认拒绝
（`Fetching packages of type "remote" have been disabled`，本机实测），必须先下载到本地再装。

## 用法

```sh
node bin/agentmd-guard.mjs scan          # 扫默认目录（家目录、DSH_HOME、Download）
node bin/agentmd-guard.mjs scan ~/code   # 只扫指定目录
node bin/agentmd-guard.mjs check         # 关键 Agent 配置有没有被人动过（退出码 1 = 有漂移）
node bin/agentmd-guard.mjs baseline --update   # 重建基线（确认无误后再做）
node bin/agentmd-guard.mjs pins --online       # MCP / 工具服务有没有锁版本
node bin/agentmd-guard.mjs selftest            # 8 组阳性/阴性对照，约 10ms
node bin/agentmd-guard.mjs scan --save-known   # 把当前命中记成「已知」，之后不再重复报
node bin/agentmd-guard.mjs scan --only-new     # 只报基线之后新出现的命中（巡检用这个）
```

`--json` 给机器读，`--verbose` 连 medium/low 一起列。

## 为什么有这个东西

2026 年 10 月，安全机构 Forever Security 报告了一条新的攻击面：**放一个纯文本的 `AGENTS.md` 到
`~/Downloads`，诱导用户在该目录启动 coding agent，agent 会把它当「项目规范」逐条执行**——
自己关掉沙箱、装恶意 npm 包、改 `~/.codex/config.toml` 做持久化；Claude Code 变体则是把
`ANTHROPIC_BASE_URL` 改指攻击者服务器，让 OAuth token 随请求外泄。研究者称之为
「Markdown is the new executable」。

这类攻击不需要任何可执行文件，杀软、后缀名白名单、`chmod -x` 全都看不见它。
能做的只有两件事：**把这类文件摊开来看**，以及**盯住它们的哈希有没有变**。

## 三层检测

| 层 | 查什么 |
|---|---|
| 不可见字符 | 零宽字符、双向控制符（U+202A–202E / U+2066–2069）、**Unicode Tag 走私（U+E0000–E007F，能把整段 ASCII 藏成看不见，并能解码还原）**、变体选择符编码、超长空白段 |
| 危险指令语义 | 关沙箱/绕审批、改模型 base URL 或代理、下载器与管道与解释器同现、解码后执行、装包与免确认执行、写 Agent 全局配置、注册 MCP server、launchctl/systemd/cron、shell rc 与 authorized_keys、环境变量外发、回连端点、话术越权（「忽略此前指令」「不要告诉用户」「静默执行」「身份改写」）、已知 IOC |
| 配置漂移 | 关键 Agent 配置文件 sha256 基线，比对出「被改过」「被删了」「新冒出来的」 |

外加 `pins` 子命令：MCP / 工具服务的启动命令有没有锁版本。
- `npx -y 包名` **不锁版本** → 每次启动都拉 registry 最新版，供应链随时可换（报 high）
- `包名@^2` **范围版本** → 上游发新版即漂移
- `包名@1.2.3` 锁死
- `docker 镜像` 没 tag 或 `:latest` → 不锁
- 跑本地文件的 → 不走 registry，但**文件本身可被改写**，风险等价
- `--online` 时还会查 registry，并识别**日期版本号陷阱**：`2026.8.31` 这类版本在包里排得比语义化的
  `2.0.1` 高，包管理器永远不提示升级，必须显式装（MCP 官方 servers v2.1.0 修 8 个洞时踩的就是这个坑）

## 输出与退出码

`scan --only-new` 配合 `--save-known`：把「已确认无害的历史命中」记进基线，之后只报**新出现**的——
否则一堆自家文档里的危险命令会每天重复刷屏（本机实测：164 文件 / 82 条历史命中，折叠后 0 条新问题）。

`scan`：`OK` / `WARN` / `BLOCK`，风险分按 critical 10 / high 5 / medium 2 / low 1 计；退出码 0 / 1 / 2。
`check`：有漂移退出码 1。`--json` 给机器读。`--verbose` 连 medium/low 一起列。

两条降噪约定：本机自有目录里的 medium 自动降为 low；同一行出现「不能 / 禁止 / 不代表 / 风险」
这类否定语境时降一级（因为安全文档大量在**讲**攻击而不是**发**攻击）。

## 局限（认真读）

- **它看不出意图。** 只会告诉你「这个文件里有会关沙箱的指令」，不会告诉你那是你自己写的还是别人塞的。
- **换个包名、换个文件名就绕过去了。** 这是基于特征和形状的检测，属于急救，不是长期方案。
- **它不提供任何强制力。** 真正的防线是审批门（别为了丝滑把确认框关掉）、上下文来源分级、
  以及把这类文件纳入 code review。研究者复现 Claude Code 变体时，**约一半的情况是被人批准才成功的**——
  审批门是唯一被数据证明有效的默认防线。
- 别在 `~/Downloads`（Windows 上是 `Downloads`）里启动 agent 会话。

## 许可

MIT
