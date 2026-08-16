# dsh-code-security（安全审计插件）

> 产品展示名：**dsh-code-security**；技术标识：宿主插件 `@dsh.so/dsh-security-gate`、
> agent preset `dsh-security`、工具 `dsh_security_*`。仓库目录名沿用
> `openai-code-security`（历史来源）。

把 OpenAI [codex-security](https://github.com/openai/codex-security)（Apache-2.0）封装成
DeepSeek Harness（DSH）**安全审计插件项目**，包含两个组件。项目非 OpenAI 官方产品，
与 OpenAI Codex Security 无任何关联（`Codex`/`Codex Security` 为 OpenAI 商标，
本项目已改用中性命名）。

- **安全门禁**（宿主插件，进程级）：新插件安装时**自动审计** —— 监控预设与插件安装面，
  发现新插件即用宿主模型采集源码生成安全审计报告，并提供设置页面板、批量审计工具、
  HTTP 端点。
- **安全审计模式**（agent preset，会话级）：新建会话选该模式，获得 13 个上游安全工作流
  技能 + 5 个 `dsh_security_*` 扫描工具，可对任意仓库做深入人工/模型审计。

**默认零认证**：两条路径都使用宿主 `llm` 服务（同会话模型路由），无需任何外部
API key。可选 `engine: 'cli'` 走 OpenAI Codex Security 官方扫描（需其自身认证）。

## 快速开始

**一条命令在线安装，然后重启 DSH。** 无需克隆项目、无需手动拷贝任何文件：

```powershell
# Windows（PowerShell）
irm https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.ps1 | iex
```

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.sh | bash
```

> 🔒 **安全说明**：远程脚本经管道交给 shell 执行是这类一键安装的标准方式（nvm、rustup 等
> 同样如此）。安装器会克隆仓库到本地缓存后运行，**不会以 root 执行、不请求提权**；如不放心，
> 可先 `curl -fsSL <上面的地址> -o install.sh` 下载后人工审阅，再 `bash install.sh`。

脚本自动：下载项目到持久缓存（`~/.dsh/cache/dsh-code-security`）、安装
「安全审计模式」预设、把「安全审计门禁」挂载进 web profile。**幂等**，重复执行安全；
旧版本遗留的手动配置行会自动迁移。

> 需要已安装 `git`（下载用）与 `pnpm`（门禁安装用）。仓库地址可自定义：
> Windows 设 `$env:DSH_CODE_SECURITY_REPO_URL`，macOS/Linux 设
> `DSH_CODE_SECURITY_REPO_URL` 环境变量（镜像场景）。

装完怎么用：

1. **重启 DSH**
2. 新建会话 → 预设选择器选「安全审计模式」，即可扫描仓库
3. 打开 **设置 → 安全审计** 面板，查看门禁自动审计的状态与报告

> **没装成功？** 最常见原因是缺少 `pnpm`。先执行 `npm install -g pnpm`，再重跑安装脚本。

## 使用

### 方式一：安全审计模式会话（深入审计）

新建会话选「安全审计模式」后，直接用自然语言发起：

```text
"扫描这个仓库的安全漏洞"                → security-scan 技能 + dsh_security_scan
"对比这两个 PR 版本的安全问题"          → security-diff-scan 技能
"这个漏洞是真问题吗？"                  → validation / attack-path-analysis 技能
"修复/追踪这个已确认的发现"            → fix-finding / track-findings 技能
```

5 个工具（均以会话工作目录为默认 cwd）：

| 工具 | 作用 |
|---|---|
| `dsh_security_scan` | 运行 `scan`（standard/deep、模型/提供商/effort/workers、后台运行） |
| `dsh_security_findings` | 列出已保存扫描的 findings |
| `dsh_security_scans_compare` | 对比两个扫描 |
| `dsh_security_cli` | 其它 CLI 子命令透传（白名单；`login`/`export` 默认排除） |
| `dsh_security_resources` | 返回 bundled 载荷路径 + 完整性校验结果 |

<p align="center">
  <img src="assets/安全审计-安全审计模式.jpg" alt="安全审计模式" width="720">
  <br><em>「安全审计模式」会话：13 个安全工作流技能 + 5 个扫描工具</em>
</p>

### 方式二：门禁自动审计（进程级）

- **自动审计**：轮询发现新预设/新插件 → 有界采集源码 → 宿主模型审计（免认证），
  已审计且未变化的插件自动跳过。
- **批量/状态**：全局工具 `dsh_security_scan_plugins` / `dsh_security_scan_status`。
- **GUI**：设置 →「安全审计」面板（状态/报告/一键重审；中英双语跟随系统语言）。
- **甄别记忆**：历轮审计的误报/设计项/已修复项记入基线（`audit-baseline.json`），
  每次审计注入提示词，模型不重复报告已知项 —— 显著降低误报率。

<p align="center">
  <img src="assets/安全审计主界面.jpg" alt="安全审计主界面" width="720">
  <br><em>设置 →「安全审计」面板：每插件审计状态、一键重审、打开报告</em>
</p>

审计报告在面板内联展示（双语、可复制、摘要表前置）：

<p align="center">
  <img src="assets/安全审计-审计报告摘要.jpg" alt="审计报告摘要" width="720">
  <img src="assets/安全审计-风险审计详情.jpg" alt="风险审计详情" width="720">
  <br><em>报告摘要表 + 风险审计详情（AI 生成，仅供参考）</em>
</p>

## 配置

### 门禁（`@dsh.so/dsh-security-gate`）

自定义配置用 id 覆盖补丁追加到 `~/.dsh/profiles/web/cordis.patch.yml`（**整体替换**
config，需列全字段；改动在 DSH 重启后生效）：

```yaml
- id: dsh-security-gate
  config:
    autoScan: true
    scanOnBoot: false
    engine: llm            # llm（默认，免认证）或 cli（需 OpenAI 认证）
    intervalMs: 60000
```

常用字段：`engine`、`provider`/`model`、`intervalMs`、`ignorePrefixes`、`cliCommand`、
`maxHarvestChars`、`maxParallel`、`scanRateLimit`。完整配置表见
[`gate/README.md`](gate/README.md)。

> ⚠️ `engine: 'cli'` 必须显式配置 `sandboxMode`（Windows 上为 `danger-full-access`，
> 等于非受限执行 —— 门禁每次扫描会打强警告，仅在明确信任 CLI 包与被扫插件时使用）。

### 预设（`dsh-security`）

技能、工具白名单等见 `agent.cordis.yml`；CLI 工具默认排除 `login`/`export`，
可用配置 `cliAllowedVerbs` 扩展。

## 安全设计（要点）

- **提示词边界**：扫描目标中的任何文本都是**数据**而非指令；仓库内嵌指令一律忽略并
  作为可疑内容上报。
- **参数安全**：shell 字面量转义（无注入）；路径收敛到工作目录（越界报错）。
- **白名单**：CLI 子命令白名单、`cliCommand` 白名单 + 版本钉扎、前台超时上限。
- **载荷完整性 fail-closed**：bundled 107 文件 SHA-256 校验，任一不符插件拒绝加载。
- **端点鉴权**：token + Host/Origin 校验 + 限流；报告/扫描/清除均有保护。
- **甄别记忆**：`audit-baseline.json` 注入审计提示词，避免重复误报。

安全分析详见 [`gate/README.md`](gate/README.md) 与
[`docs/SECURITY_AUDIT_REPORT.md`](docs/SECURITY_AUDIT_REPORT.md)。

## 卸载

**一条命令**（清预设 + 门禁 + 状态/缓存，幂等可重跑）：

```powershell
# Windows
irm https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/uninstall.ps1 | iex
```

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/uninstall.sh | bash
```

> 🔒 与安装相同，可先下载审阅再执行：`curl -fsSL <上面的地址> -o uninstall.sh && bash uninstall.sh`。

## 项目结构

```
openai-code-security/
├── gate/                   # 安全门禁宿主插件 @dsh.so/dsh-security-gate
│   ├── index.js            #   零依赖 cordis 插件
│   ├── client.js           #   设置页「安全审计」面板（双语）
│   ├── cordis.patch.yml    #   bundle 补丁（dsh plugin add 自动挂载）
│   ├── audit-baseline.json #   历轮审计甄别记忆
│   └── README.md
├── agent.cordis.yml        # 预设组合（standard + dsh-security 附加行）
├── preset.yml              # 预设元数据
├── plugins/dsh-security/   # 工具插件 @dsh.so/dsh-security-tools（5 个 dsh_security_*）
├── skills/dsh-security/    # DSH 适配入口技能
├── bundled/                # 上游 _bundled_plugin 拷贝（技能/references/schemas/scripts/mcp）
├── docs/                   # 安全审计报告 / 插件推荐 / GitHub 讨论帖
├── assets/                 # README 配图（界面截图 + logo）
├── install.ps1 / install.sh / uninstall.*
└── README.md
```

## 开发与发布

两个组件已发布到 npmjs（Apache-2.0）：

```bash
npm install @dsh.so/dsh-security-gate      # 安全门禁宿主插件
npm install @dsh.so/dsh-security-tools     # 安全审计模式工具插件（含 bundled 载荷）
```

- scoped 包名（`@dsh.so/...`）是 npm 标准作用域，安装/引用/升级无特殊要求；tools 包
  bundled 载荷（107 文件）已打进包内，完整性校验在包内布局下照常通过。
- **npm 安装 ≠ 插件生效**：门禁仍需挂载进 profile（`dsh plugin --profile web add ...`），
  预设仍需放进 `~/.dsh/.agent-presets/`。对最终用户推荐上方的一键脚本。
- 本地开发安装（离线/内网）：`.\install.ps1` / `./install.sh`；手动安装见
  [`gate/README.md`](gate/README.md)。

## 许可证与命名

- 本项目结构/封装代码：Apache-2.0。
- `bundled/` 内容版权归 OpenAI，许可证 Apache-2.0，来源：
  https://github.com/openai/codex-security。
- `Codex` / `Codex Security` 为 OpenAI 商标。本项目对外展示名为 **dsh-code-security**，
  技术标识为 `dsh-security` / `@dsh.so/dsh-security-gate` 等中性名称，仅在上游归属、
  CLI 包名（`@openai/codex-security`）与技能内引用中保留上游原名。

---

<p align="center">
  <img src="assets/dshso-logo.svg" width="22" height="22" alt="dsh.so" style="vertical-align: middle">&nbsp;
  <b>dsh-code-security</b> · © 2026 dsh.so · Apache-2.0 · <b>Powered by <a href="https://dsh.so">dsh.so</a></b>
</p>
