# dsh-security-gate（展示名：dsh-code-security）

DSH 宿主门禁插件：**新插件安装时自动用本会话的大模型审计（免认证），并支持指定插件批量扫描。**
（非 OpenAI 官方产品；`Codex`/`Codex Security` 为 OpenAI 商标，本插件已改用中性命名。）

- 监控两类"插件安装"表面（轮询，默认 60s + 启动时立即一次）：
  1. `~/.dsh/.agent-presets/` 下新增/变更的 **agent preset**（用户预设法）
  2. `~/.dsh/profiles/*/` 下各 profile 的 **package.json 依赖、bundle 列表、node_modules 顶层包**（`dsh plugin` 装的插件）
- 新插件出现 → 采集插件源码（有界：跳过 node_modules/.git/bundled/二进制/超限文件）→ 用宿主
  `llm` 服务（与会话同一 provider/model，零新增认证）生成安全审计报告，写入
  `reports/<key>-<ts>/report.md`；自动跳过已审计且未变化的插件，版本/路径变化会重扫。
- 可选 CLI 引擎（`engine: 'cli'`）：执行 `npx --yes @openai/codex-security scan <根目录>`，
  需 OpenAI 侧认证。
- 状态与报告持久化在 `<DSH_HOME>/dsh-security/`：
  - `state.json` — 每个插件的审计历史
  - `summary.json` — 每插件最新状态（供人工/UI 查看）
  - `reports/<key>-<ts>/` — `report.md`（模型审计报告）+ `runner.log`
- 注册两个全局模型工具：
  - `dsh_security_scan_plugins` — 批量审计（标识：预设 id / 包名 / 绝对路径，可 `force` 重扫）
  - `dsh_security_scan_status` — 查看所有已知插件的审计状态
- **GUI 面板**：设置页新增「安全审计」分区（`settings.section`），展示每插件状态/最近
  审计/备注，支持打开报告与「重新审计」。数据经门禁注册的 HTTP 端点提供：
  - `GET /dsh-security/status.json` — 每插件最新状态（状态为空时实时发现兜底）
  - `GET /dsh-security/report?id=<报告目录>` — 报告 markdown（仅允许已记录的报告目录）
  - `POST /dsh-security/scan` — 触发指定插件审计 `{ "plugins": ["preset:x", ...] }`

零依赖（仅 Node 内置模块 + 一个手写 client bundle）；消费宿主服务时全部
`ctx.get()` 防御式访问，`apply()` 不抛错。

## 安装

```powershell
# 在项目根目录（Windows）
.\install.ps1
```

或手动（一条命令即可，无需再写 patch 行）：

```bash
dsh plugin --profile web add <本目录>
```

`gate/package.json` 声明了 `dsh.bundle.patch: ./cordis.patch.yml`，`dsh plugin add`
会自动把 `@dsh.so/dsh-security-gate` 加入 profile 的 `dsh.profile.bundles` 层并由 bundle
补丁插入插件行。**旧版手动安装**（`cordis.patch.yml` 里的 `- insert:` 行，旧包名
`dsh-security-gate`）需要删除该行：重跑 `install.ps1`/`install.sh` 会自动移除，否则会与
bundle 行产生重复 entry id（loader 直接报错）。

自定义配置用 id 覆盖补丁（**整体替换** config，需列全字段）追加到
`~/.dsh/profiles/web/cordis.patch.yml`：

```yaml
- id: dsh-security-gate
  config:
    autoScan: true
    scanOnBoot: false
    engine: cli
    sandboxMode: danger-full-access
```

（`sandboxMode: danger-full-access` 仅 `engine: 'cli'` 时需要——宿主级 shell 在本机
Windows 的 `workspace-write` 沙箱不可用；默认 `engine: 'llm'` 不需要它。）
组合改动在 DSH 重启后生效（补丁不会在当前进程热重载）。

## 配置（patch 行的 config）

| 字段 | 默认 | 说明 |
|---|---|---|
| `autoScan` | `true` | 是否自动扫描新插件 |
| `scanOnBoot` | `true` | 首次运行（无 state）时是否扫描现存插件 |
| `scanSystemPresets` | `false` | 是否扫描出厂预设（standard/code/cordis/minimal 等 system trust 预设） |
| `engine` | `llm` | `llm` = 宿主模型审计（免认证）；`cli` = @openai/codex-security CLI（需其自身认证） |
| `provider` / `model` | 宿主默认路由 | llm 引擎的模型路由覆盖（默认取 `agentDefaultModel`，即会话同款） |
| `intervalMs` | `60000` | 轮询间隔 |
| `ignorePrefixes` | `["@deepseek-ai/"]` | 按包名前缀忽略（出厂底座） |
| `ignoreIds` | `[]` | 按预设 id / 包名精确忽略 |
| `cliCommand` | `npx --yes @openai/codex-security` | CLI 引擎的调用 |
| `stateDir` | `<DSH_HOME>/dsh-security` | 状态/报告目录 |
| `scanTimeoutMs` | `900000` | CLI 引擎超时（15 分钟） |
| `allowPathTargetsOutsidePlugins` | `false` | 是否允许把**插件根目录之外**的路径作为扫描目标（默认拒绝，防止任意文件被采集并外发给模型） |
| `maxHarvestChars` | `400000` | llm 引擎源码采集字符预算 |
| `maxFileBytes` | `65536` | llm 引擎单文件上限（超出跳过） |
| `maxOutputTokens` | `8000` | llm 引擎输出 token 预算（审计提示较大，预留报告空间） |
| `reasoningEffort` | `off` | 关闭模型推理（推理会吃光输出预算，导致只有推理没有结论）；需要推理可设 `high`/`max` |
| `llmTimeoutMs` | `240000` | llm 调用超时（4 分钟），防扫描卡 `running` |
| `maxParallel` | `2` | 并发审计数 |
| `sandboxMode` | 继承执行器默认 | 仅 CLI 引擎需要；本机建议 `danger-full-access` |

## 前置条件

- **默认（llm 引擎）**：无需任何外部认证；使用宿主 `llm` 服务（同会话模型路由，如
  deepseek-official / deepseek-v4-flash）。模型每次审计会读取目标插件源码。
- 可选（cli 引擎）：`npx @openai/codex-security login` 或 `OPENAI_API_KEY`/`CODEX_API_KEY`。

### 数据流向与隐私（请先阅读）

- **llm 引擎会把被审计插件的源码（有界采集，默认 ≤ 400K 字符）随提示词发送给本会话
  配置的模型服务商**（默认 deepseek-official）。这是模型审计的工作方式，不是可选的
  功能分支。请勿在含敏感/专有代码且不允许外发的环境中启用自动审计。
- **关闭自动审计**：`autoScan: false`（停止轮询）；已发现插件的存量审计可手动触发
  （面板「审计全部」或 `dsh_security_scan_plugins`）。
- **不把源码发给模型**：只能用 `engine: 'cli'` 走 OpenAI Codex Security 官方扫描
  （需其自身认证与网络，源码仍会交给 OpenAI 扫描管线）。
- **路径目标受限**：扫描目标只能是指定插件根目录（预设/包目录）；其他绝对路径默认
  拒绝，需要时由管理员设 `allowPathTargetsOutsidePlugins: true`（不推荐）。
