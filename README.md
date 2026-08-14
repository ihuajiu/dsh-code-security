# openai-code-security

把 OpenAI [codex-security](https://github.com/openai/codex-security)（Apache-2.0）
封装成 DeepSeek Harness（DSH）**插件项目**，包含两部分：

**1. 安全门禁（核心，宿主插件 `openai-code-security-gate`）**
- 新插件安装时**自动审计**：监控 `~/.dsh/.agent-presets/` 的预设与
  `~/.dsh/profiles/*/` 的插件包（`dsh plugin` 安装的依赖/bundle），轮询发现新插件
  即用**宿主模型**（同会话路由，零认证）采集源码生成安全审计报告。
- **批量审计**：全局工具 `codex_security_scan_plugins`（按预设 id / 包名 / 路径指定
  多个插件）与 `codex_security_scan_status`（查看所有插件审计状态）。
- **GUI 面板**：设置 →「安全审计」分区，展示每插件审计状态、打开报告、一键重新审计。
- 状态与报告：`<DSH_HOME>/codex-security/{state.json, summary.json, reports/...}`。
- 可选 `engine: 'cli'`：改用 `@openai/codex-security` CLI（需 OpenAI 认证）。
- 详见 [`gate/README.md`](gate/README.md)。

**2. 代码安全模式（agent preset，id: `codex-security`）**
- 新建会话选「代码安全模式」获得 13 个上游安全工作流技能
  （security-scan、security-diff-scan、deep-security-scan、finding-discovery、
  validation、attack-path-analysis、threat-model、define-security-policy、
  triage-finding、fix-finding、track-findings、vulnerability-writeup、
  propose-security-hardening）+ 1 个 DSH 适配入口技能，以及 5 个
  `codex_security_*` 工具（扫描 / 查询 / 对比 / CLI 透传 / 资源定位）。
- **默认零认证**：模型直接按技能用自身文件/搜索/子代理工具审计；CLI 工具为可选
  （仅当显式要求 OpenAI Codex Security 官方扫描且已认证时使用）。

## 前置条件

- DSH 环境。
- **默认路径（本地模型审计）**：无需任何外部认证/API key，使用宿主 `llm` 服务
  （同会话模型路由）。
- 可选路径（CLI 工具 / 门禁 `engine: 'cli'`）：Node.js ≥ 22.13 / Python ≥ 3.10 /
  网络 + `npx @openai/codex-security login` 或 `OPENAI_API_KEY` / `CODEX_API_KEY`。

## 安装

方式一：一键脚本（安装预设 + 门禁到 web profile）

```powershell
# Windows
.\install.ps1
```

```bash
# macOS / Linux
./install.sh          # 或 ./install.sh <profile>
```

方式二：手动安装

- **预设**：把 `agent.cordis.yml`、`preset.yml`、`plugins/`、`skills/`、`bundled/`
  复制到 `~/.dsh/.agent-presets/codex-security/`。
- **门禁**：`dsh plugin --profile web add <项目>/gate`，然后往
  `~/.dsh/profiles/web/cordis.patch.yml` 追加（插入新行必须用 `insert:` 补丁语法）：

  ```yaml
  - insert:
      - id: codex-security-gate
        name: openai-code-security-gate
        config:
          scanTimeoutMs: 900000
  ```

  （`sandboxMode: danger-full-access` 仅在改用 `engine: 'cli'` 时需要。）

组合改动在 DSH 重启后生效（当前进程不会热重载补丁）。安装后：新建会话在预设选择器里
选「代码安全模式」（id: `codex-security`）获得技能与工具；门禁挂载后自动审计新插件
（报告在 `<DSH_HOME>/codex-security/`，模型审计零认证）。

## 使用

```text
"扫描这个仓库的安全漏洞"                      → codex_security_scan + security-scan 技能
"对比这两个 PR 版本的安全问题"                → security-diff-scan 技能
"这个漏洞是真问题吗？"                        → validation / attack-path-analysis 技能
"修复/追踪这个已确认的发现"                  → fix-finding / track-findings 技能
```

工具一览（均以会话工作目录为默认 cwd）：

| 工具 | 作用 |
|---|---|
| `codex_security_scan` | 运行 `scan`（standard/deep、模型/提供商/effort/workers、后台运行、长超时） |
| `codex_security_findings` | `findings list [repository]` |
| `codex_security_scans_compare` | `scans compare BEFORE AFTER` |
| `codex_security_cli` | 其它 CLI 子命令透传（`login`、`scans list`、`scans logs` …） |
| `codex_security_resources` | 返回随预设分发的 bundled 载荷绝对路径（技能、references、schemas、scripts） |

技能会按需由模型通过 skill 加载器读取；`codex-security` 适配技能说明如何用
DSH 工具替换上游技能中提到的 Codex MCP 工具（上游技能自带 "prompt-only"
降级路径，DSH 下走该路径或 `codex_security_*` 工具）。

## 项目结构

```
openai-code-security/
├── gate/                   # 安全门禁宿主插件（安装时自动扫描 + 批量扫描工具）
│   ├── index.js            #   零依赖 cordis 插件
│   └── README.md
├── agent.cordis.yml        # 预设组合：standard 全量 + codex-security 附加行
├── preset.yml              # 预设元数据
├── plugins/codex-security/ # 本地工具插件（相对路径行 ./plugins/codex-security/index.js）
├── skills/codex-security/  # DSH 适配入口技能
├── bundled/                # 上游 _bundled_plugin 原样拷贝（Apache-2.0）
│   ├── skills/             #   13 个上游安全工作流技能（DSH 技能格式）
│   ├── references/         #   技能内 ../../references 相对引用依赖
│   ├── schemas/ examples/ scripts/ mcp/ …
├── install.ps1 / install.sh
└── README.md
```

## 卸载

- **预设**：删除 `~/.dsh/.agent-presets/codex-security/`。
- **门禁**：`dsh plugin --profile web remove openai-code-security-gate`，并从
  `~/.dsh/profiles/web/cordis.patch.yml` 删除 `codex-security-gate` 行。

## 许可证与归属

- 本项目结构/封装代码：Apache-2.0（与上游一致）。
- `bundled/` 内容版权归 OpenAI，许可证 Apache-2.0，来源：
  https://github.com/openai/codex-security （版本 0.1.20 的 `_bundled_plugin`）。
- 使用 Codex Security 服务需遵守 OpenAI 的使用条款；部分网络安防请求与受保护
  发现可能需要 Trusted Access for Cyber（chatgpt.com/cyber）。

## 已知限制

- 上游技能引用 Codex MCP workbench 工具；DSH 下这些工具不可用，走 prompt-only
  降级路径（见适配技能）。
- 深度扫描（deep）耗时长、token 消耗大，建议后台运行或分批。
- 门禁的"安装时自动审计"是轮询式（默认 60s + 启动时一次）：`dsh plugin` 的 pnpm
  安装在 DSH 进程外发生，无法在安装瞬间同步触发。llm 引擎零认证即可用；
  CLI 引擎（`engine: 'cli'`）才需要 `npx @openai/codex-security login` 或
  API key（本机已有的 ChatGPT 凭据对 codex-security 服务通常无效，需单独 login）。
- 模型审计为有界单次分析（源码采集预算 `maxHarvestChars`，默认 400K 字符）：超大插件
  的遗漏文件会在报告/runner.log 中标记；需要完整深入审计时，在「代码安全模式」会话中
  让模型按技能用自身工具做完整审计（支持子代理并行、逐文件验证）。
- CLI 引擎在 Windows 宿主上需要 `sandboxMode: danger-full-access`（`workspace-write`
  沙箱的 ACL 临时根与 home workspace 重叠不可用）。
