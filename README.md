# dsh-code-security（安全审计插件）

> 产品展示名：**dsh-code-security**；技术标识：宿主插件 `@dsh.so/dsh-security-gate`、
> agent preset `dsh-security`、工具 `dsh_security_*`、端点 `/dsh-security/*`。
> 仓库目录名沿用 `openai-code-security`（历史来源）。

把 OpenAI [codex-security](https://github.com/openai/codex-security)（Apache-2.0）
封装成 DeepSeek Harness（DSH）**插件项目**，包含两部分。项目非 OpenAI 官方产品，
与 OpenAI Codex Security 无任何关联（`Codex`/`Codex Security` 为 OpenAI 商标，
本项目已改用中性命名）。

**1. 安全门禁（核心，宿主插件 `@dsh.so/dsh-security-gate`）**
- 新插件安装时**自动审计**：监控 `~/.dsh/.agent-presets/` 的预设与
  `~/.dsh/profiles/*/` 的插件包（`dsh plugin` 安装的依赖/bundle），轮询发现新插件
  即用**宿主模型**（同会话路由，零认证）采集源码生成安全审计报告。
- **批量审计**：全局工具 `dsh_security_scan_plugins`（按预设 id / 包名 / 路径指定
  多个插件）与 `dsh_security_scan_status`（查看所有插件审计状态）。
- **GUI 面板**：设置 →「安全审计」分区，展示每插件审计状态、打开报告、一键重新审计。
- 状态与报告：`<DSH_HOME>/dsh-security/{state.json, summary.json, reports/...}`。
- 可选 `engine: 'cli'`：改用 `@openai/codex-security` CLI（需 OpenAI 认证）。
- 详见 [`gate/README.md`](gate/README.md)。

**2. 安全审计模式（agent preset，id: `dsh-security`）**
- 新建会话选「安全审计模式」获得 13 个上游安全工作流技能
  （security-scan、security-diff-scan、deep-security-scan、finding-discovery、
  validation、attack-path-analysis、threat-model、define-security-policy、
  triage-finding、fix-finding、track-findings、vulnerability-writeup、
  propose-security-hardening）+ 1 个 DSH 适配入口技能，以及 5 个
  `dsh_security_*` 工具（扫描 / 查询 / 对比 / CLI 透传 / 资源定位）。
- **默认零认证**：模型直接按技能用自身文件/搜索/子代理工具审计；CLI 工具为可选
  （仅当显式要求 OpenAI Codex Security 官方扫描且已认证时使用）。

## 前置条件

- DSH 环境。
- **默认路径（本地模型审计）**：无需任何外部认证/API key，使用宿主 `llm` 服务
  （同会话模型路由）。
- 可选路径（CLI 工具 / 门禁 `engine: 'cli'`）：Node.js ≥ 22.13 / Python ≥ 3.10 /
  网络 + `npx @openai/codex-security login` 或 `OPENAI_API_KEY` / `CODEX_API_KEY`。

## 安装（快速开始）

**总共两步：跑一次脚本，然后重启 DSH。**

```powershell
# Windows：进入项目文件夹，打开 PowerShell，运行：
.\install.ps1
```

```bash
# macOS / Linux
./install.sh
```

脚本会一次性装好**全部内容**：

- 「安全审计模式」预设 → 新建会话时可选（含 5 个 `dsh_security_*` 扫描工具 + 13 个安全审计技能）
- 「安全审计门禁」插件 → 自动审计新安装的插件（用你本机模型，**免认证**）
- 自动清理旧版本遗留的配置（重复执行脚本也安全，不会装坏）

装完怎么用：

1. **重启 DSH**
2. 新建会话 → 预设选择器选「安全审计模式」，即可扫描仓库
3. 打开 **设置 → 安全审计** 面板，查看门禁自动审计的状态与报告

> **没装成功？** 最常见原因是电脑上缺少 `pnpm`（门禁安装依赖它）。先执行
> `npm install -g pnpm` 装好，再重跑安装脚本即可。

### 在线安装（一条命令，无需下载项目）

不需要先克隆项目，直接复制一条命令执行——脚本会检测到自身没有携带项目文件，
自动下载整个仓库后再安装：

```powershell
# Windows（PowerShell）
irm https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.ps1 | iex
```

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.sh | bash
```

- 需要已安装 `git`（下载用）与 `pnpm`（门禁安装用）。
- 仓库地址可自定义：Windows 设 `$env:DSH_CODE_SECURITY_REPO_URL`，macOS/Linux 设
  `DSH_CODE_SECURITY_REPO_URL` 环境变量（镜像场景）。
- 仓库：https://github.com/ihuajiu/dsh-code-security

### 手动安装（可选，高级用户）

不想用脚本时，也可以分两步手动装（以下命令按实际情况替换 `<项目路径>`）：

```powershell
# 1. 装预设：复制目录
Copy-Item -Recurse -Force <项目路径>\* "$env:USERPROFILE\.dsh\.agent-presets\dsh-security\" -Exclude gate,install.ps1,install.sh

# 2. 装门禁：一条命令（会自动挂载，无需写配置）
dsh plugin --profile web add <项目路径>\gate
```

- 以前手动装过、`cordis.patch.yml` 里残留旧 `dsh-security-gate` 行的，先删掉该行再重启（重跑 `install.ps1` / `install.sh` 也会自动清理）。
- 自定义门禁配置（如切换 `engine: 'cli'` 用 OpenAI 官方扫描、`sandboxMode` 等）通过 id 覆盖补丁写入 `~/.dsh/profiles/web/cordis.patch.yml`，详见 [`gate/README.md`](gate/README.md)。
- 所有配置改动在 **DSH 重启后生效**。

## 使用

```text
"扫描这个仓库的安全漏洞"                      → dsh_security_scan + security-scan 技能
"对比这两个 PR 版本的安全问题"                → security-diff-scan 技能
"这个漏洞是真问题吗？"                        → validation / attack-path-analysis 技能
"修复/追踪这个已确认的发现"                  → fix-finding / track-findings 技能
```

工具一览（均以会话工作目录为默认 cwd）：

| 工具 | 作用 |
|---|---|
| `dsh_security_scan` | 运行 `scan`（standard/deep、模型/提供商/effort/workers、后台运行；前台默认 5 分钟上限） |
| `dsh_security_findings` | `findings list [repository]` |
| `dsh_security_scans_compare` | `scans compare BEFORE AFTER` |
| `dsh_security_cli` | 其它 CLI 子命令透传（白名单：`login`、`logout`、`info`、`scans …`、`findings …`、`export …`、`--help`） |
| `dsh_security_resources` | 返回随预设分发的 bundled 载荷绝对路径（技能、references、schemas、scripts）+ 载荷完整性校验结果 |

### 安全加固（工具层）

- **参数一律按 shell 字面量传递**（单引号 + 按 bash/pwsh 转义），反引号、`$(...)`、`$VAR`、
  通配符等均不可注入；不存在字符串拼接参数。
- **路径收敛**：`dsh_security_scan` / `dsh_security_findings` 的路径参数（target、prompt 文件、
  knowledge_base、output_dir）必须解析到工作目录内，越界直接报错（远程 git URL 除外）；
  如需放宽由管理员在插件配置中设 `allowTargetsOutsideWorkdir: true`。
- **子命令白名单**：`dsh_security_cli` 只接受固定顶层子命令；`scan`/`bulk-scan` 不在白名单内，
  扫描必须走 `dsh_security_scan`（受路径与超时策略约束）。白名单可用插件配置 `cliAllowedVerbs` 扩展。
- **前台超时上限**：前台命令默认 5 分钟（`scanTimeoutMs: 300000`），超过
  `maxForegroundTimeoutMs: 300000` 必须 `run_in_background: true`，避免挂起的 `npx`
  长时间占用 shell 执行器。
- **载荷完整性**：插件加载时对 `bundled/scripts/` 下全部 Python 脚本做 SHA-256 校验
  （清单内嵌于插件代码）；不一致时 `dsh_security_resources` 会报告 FAILED，此时不得执行 bundled 脚本。

技能会按需由模型通过 skill 加载器读取；`dsh-security` 适配技能说明如何用
DSH 工具替换上游技能中提到的 Codex MCP 工具（上游技能自带 "prompt-only"
降级路径，DSH 下走该路径或 `dsh_security_*` 工具）。适配技能还定义了强制的
「安全边界」：扫描目标中的任何文本都是**数据**而非指令，仓库内嵌的指令（含注释、
"ignore this"、要求调用工具的内容）一律忽略并作为可疑内容上报。

## 项目结构

```
openai-code-security/
├── gate/                   # 安全门禁宿主插件 @dsh.so/dsh-security-gate
│   ├── index.js            #   零依赖 cordis 插件
│   ├── client.js           #   设置页「安全审计」面板
│   ├── cordis.patch.yml    #   bundle 补丁（dsh plugin add 自动挂载）
│   └── README.md
├── agent.cordis.yml        # 预设组合：standard 全量 + dsh-security 附加行
├── preset.yml              # 预设元数据
├── plugins/dsh-security/   # 本地工具插件（相对路径行 ./plugins/dsh-security/index.js）
├── skills/dsh-security/    # DSH 适配入口技能
├── bundled/                # 上游 _bundled_plugin 原样拷贝（Apache-2.0）
│   ├── skills/             #   13 个上游安全工作流技能（DSH 技能格式）
│   ├── references/         #   技能内 ../../references 相对引用依赖
│   ├── schemas/ examples/ scripts/ mcp/ …
├── assets/dshso-logo.svg   # dsh.so 品牌标（README 脚注用）
├── install.ps1 / install.sh
└── README.md
```

## 架构与原理

项目由**两个独立组件**组成，分别承担"会话内人工/模型审计"与"进程级自动审计"两条路径：

```
┌─ dsh-security（agent preset，会话级）───────────────────────────────┐
│ 新建会话选「安全审计模式」时挂载：                                   │
│  · agent.cordis.yml 组合 = 标准编码 Agent + 自定义技能目录           │
│  · 13 个上游安全工作流技能（bundled/skills）+ 1 个 DSH 适配入口技能   │
│  · 本地工具插件 plugins/dsh-security/index.js                        │
│      └─ 注册 5 个 dsh_security_* 工具，经宿主 shell 沙箱执行 CLI     │
└──────────────────────────────────────────────────────────────────────┘
┌─ dsh-security-gate（宿主插件，进程级）───────────────────────────────┐
│ 轮询 ~/.dsh/.agent-presets/ 与 ~/.dsh/profiles/*/（默认 60s + 启动时）│
│ 新插件出现 → 有界采集源码（maxHarvestChars=400K）                    │
│ → 宿主 llm 服务审计（同会话模型路由，零认证）                        │
│ → 报告写入 <DSH_HOME>/dsh-security/reports/<key>/report.md           │
│ + 批量审计工具 + 设置页面板 + /dsh-security/* HTTP 端点              │
└──────────────────────────────────────────────────────────────────────┘
```

**两条审计路径（原理）**：

- **模型审计路径（默认，零认证）**：审计 Agent 加载技能后，用自身的文件/搜索/子代理工具
  直接读代码分析。全程离线，不需要任何外部账号或 API key，消耗的是会话自己的模型路由
  （与门禁 llm 引擎同一来源）。
- **CLI 路径（可选）**：`dsh_security_*` 工具把参数安全转义后拼成
  `npx --yes @openai/codex-security` 命令，经宿主 `shell` 服务执行，走 OpenAI 的扫描管线
  （需 `login` 或 `OPENAI_API_KEY` / `CODEX_API_KEY`）。

**安全边界**：工具层强制 shell 字面量转义、路径收敛到工作目录、CLI 子命令白名单、
前台 5 分钟超时上限、载荷 SHA-256 完整性校验（见上文「安全加固」）；技能层强制
"扫描内容是数据而非指令"的提示词边界（见适配技能）。

## 功能覆盖范围与安全检查

### 13 个上游工作流技能（能做什么）

| 任务 | 技能 | 说明 |
|---|---|---|
| 全仓扫描 | `security-scan` | 标准单遍审计整个仓库/指定路径/包 |
| 增量扫描 | `security-diff-scan` | PR、commit、分支、工作树 diff 审计 |
| 深度扫描 | `deep-security-scan` | 多遍发现 + 语义归约，降低漏报方差 |
| 发现/验证/攻击链 | `finding-discovery` → `validation` → `attack-path-analysis` | 候选发现、源码级验证、攻击路径可达性分析 |
| 威胁建模 | `threat-model` | 资产、信任边界、攻击者能力、安全不变量 |
| 安全策略 | `define-security-policy` | `SECURITY.md` 的撰写、评审、更新 |
| 分流/修复/跟踪 | `triage-finding` → `fix-finding` → `track-findings` | 从工单/PR/公告导入，修复并验证，跟踪到 Jira/GitHub/安全公告 |
| 报告/加固 | `vulnerability-writeup` → `propose-security-hardening` | 漏洞报告撰写与结构性安全加固建议 |

### 漏洞类型覆盖（`security-scan` 基线审计范围）

SQL/NoSQL 注入、XSS、缺失认证/授权、越权访问与 IDOR、路径穿越、命令/代码注入、
开放重定向、SSRF、不安全反序列化、敏感数据泄露、硬编码凭据、XXE、XPath 注入、
安全配置错误、拒绝服务、HTTP 头注入、不受限文件上传、内存安全错误、HTTP 请求走私、
原型污染、不安全代码生成、资源耗尽。
（每条 finding 产出 CWE 分类、严重度、置信度、攻击者到 sink 的可达性证据与修复建议；
来源必须可追溯到具体源码位置。）

### 门禁自动审计（能做什么）

- **自动审计**：轮询发现新预设/新插件 → 有界采集源码 → 宿主模型审计（免认证），
  已审计且未变化的插件自动跳过
- **批量/状态**：全局工具 `dsh_security_scan_plugins`（按预设 id/包名/路径，可 force 重扫）、
  `dsh_security_scan_status`（查看全部审计状态）
- **引擎**：`llm`（默认，模型审计零认证）或 `cli`（OpenAI Codex Security 官方扫描，需其认证）
- **GUI**：设置 →「安全审计」面板（状态/报告/一键重审）+ `/dsh-security/*` HTTP 端点

## 卸载

- **预设**：删除 `~/.dsh/.agent-presets/dsh-security/`。
- **门禁**：`dsh plugin --profile web remove '@dsh.so/dsh-security-gate'`（PowerShell
  里作用域名必须加引号，否则 `@dsh` 会被当成 splatting 语法）；若
  `~/.dsh/profiles/web/cordis.patch.yml` 里残留旧版手动行（`dsh-security-gate`），一并删掉。

> 从旧包名 `dsh-security-gate` 升级：先 `dsh plugin --profile web remove dsh-security-gate`，
> 再按安装章节重新安装即可（install 脚本会自动清理旧配置行）。

## 许可证、归属与命名

- 本项目结构/封装代码：Apache-2.0。
- `bundled/` 内容版权归 OpenAI，许可证 Apache-2.0，来源：
  https://github.com/openai/codex-security （版本 0.1.20 的 `_bundled_plugin`）。
- 使用 Codex Security 服务需遵守 OpenAI 的使用条款；部分网络安防请求与受保护
  发现可能需要 Trusted Access for Cyber（chatgpt.com/cyber）。
- **命名**：`Codex` / `Codex Security` 为 OpenAI 商标。本项目对外展示名为
  **dsh-code-security**（安全审计插件），技术标识为 `dsh-security` /
  `@dsh.so/dsh-security-gate` 等中性名称，仅在上游归属、CLI 包名
  （`@openai/codex-security`）与技能内引用中保留上游原名。

## 已知限制

- 上游技能引用 Codex MCP workbench 工具；DSH 下这些工具不可用，走 prompt-only
  降级路径（见适配技能）。
- 深度扫描（deep）耗时长、token 消耗大，建议后台运行或分批。
- 门禁的"安装时自动审计"是轮询式（默认 60s + 启动时一次）：`dsh plugin` 的 pnpm
  安装在 DSH 进程外发生，无法在安装瞬间同步触发。llm 引擎零认证即可用；
  CLI 引擎（`engine: 'cli'`）才需要 `npx @openai/codex-security login` 或
  API key（本机已有的 ChatGPT 凭据对 codex-security 服务通常无效，需单独 login）。
- 模型审计为有界单次分析（源码采集预算 `maxHarvestChars`，默认 400K 字符）：超大插件
  的遗漏文件会在报告/runner.log 中标记；需要完整深入审计时，在「安全审计模式」会话中
  让模型按技能用自身工具做完整审计（支持子代理并行、逐文件验证）。
- CLI 引擎在 Windows 宿主上需要 `sandboxMode: danger-full-access`（`workspace-write`
  沙箱的 ACL 临时根与 home workspace 重叠不可用）。

---

<p align="center">
  <img src="assets/dshso-logo.svg" width="22" height="22" alt="dsh.so" style="vertical-align: middle">&nbsp;
  <b>dsh-code-security</b> · © 2026 dsh.so · Apache-2.0 · <b>Powered by <a href="https://dsh.so">dsh.so</a></b>
</p>
