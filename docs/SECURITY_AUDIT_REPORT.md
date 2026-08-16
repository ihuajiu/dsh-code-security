# 代码安全审计报告 — dsh-code-security (openai-code-security)

审计时间: 2026-02（本会话）
审计范围: 全仓库源码（Node.js 插件/网关、Python 扫描脚本、安装脚本、MCP 运行时、配置）
审计方式: 人工静态审计 + 危险模式扫描 + 沙箱行为验证

---

## 1. 项目概况

DSH（DeepSeek Harness）安全审计插件，两部分组成：

- **安全门禁**（宿主插件 `gate/index.js` + `gate/client.js`）：监控 `~/.dsh/.agent-presets` 与 `~/.dsh/profiles/*` 下新安装的插件，用宿主模型采集源码生成审计报告；注册 `/dsh-security/*` 本地 HTTP 端点与 2 个全局工具。
- **安全审计模式**（agent preset，`agent.cordis.yml` + `plugins/dsh-security/index.js`）：封装 OpenAI codex-security 的 13 个工作流技能 + 5 个 `dsh_security_*` CLI 工具 + `bundled/scripts` 下 34 个 Python 辅助脚本（约 700KB）。

## 2. 总体评价

代码质量**显著高于一般水平**，明显经过安全意识强的开发者反复加固。未发现可利用的高危漏洞（命令注入 / SQL 注入 / 路径穿越 / 反序列化 / 硬编码密钥均未发现）。主要问题集中在**纵深防御缺口与供应链加固**，多为中低危。

### 已验证的正面措施（亮点）

| 面 | 措施 | 证据 |
|---|---|---|
| Shell 注入 | 所有参数按 bash/pwsh 方言单引号转义，无字符串拼接 | plugins/dsh-security/index.js:112-116, gate/index.js:220-224 |
| 命令执行 | subprocess 全部列表形式、无 shell=True，git 设置 `GIT_LITERAL_PATHSPECS=1`、禁用 core.fsmonitor | 全 Python 脚本 grep 验证；workbench_target.py:133-150 |
| SQL | 全部参数化查询；仅迁移内部标识符使用 f-string | workbench_schema.py:1193-1198 |
| 文件写入 | Linux dir_fd 相对写入 + 原子 rename + fsync；Windows 拒绝重解析点/ junction、句柄不共享 DELETE | finalize_scan_contract.py:450-535, windows_scan_local_files.py |
| 路径约束 | canonicalizePath（symlink 解析）后做包含性检查；harvest 永不越出插件根 | gate/index.js:44-57, 634-707 |
| 密钥防护 | 不采集 .env/*.pem/credentials 等文件 + 正则脱敏 + 采集量上限 | gate/index.js:60-97, 655-700 |
| 提示注入 | 系统提示声明"扫描内容是不可信数据" + <source_code> 定界 | gate/index.js:523-565 |
| 本地端点 | Host 白名单(防 DNS rebinding) + Origin 同源校验 + /scan 限流 | gate/index.js:964-1161 |
| 完整性 | 34 个 Python 脚本 SHA-256 清单，加载时与调用时双重校验（已实测清单与磁盘一致） | plugins/dsh-security/index.js:59-94 |
| 密钥硬编码 | 全仓库扫描：无任何真实密钥/token | — |
| 前端 XSS | markdown 先转义后套白名单标签，链接限 https? 且 rel=noreferrer | gate/client.js:221-308 |

## 3. 发现的问题

### F1 [中] 模型可控的 `workdir` 参数绕过扫描路径约束（plugins/dsh-security/index.js:314-317）

- **位置**: `resolveWorkdir()` —— `dsh_security_scan` / `dsh_security_findings` / `dsh_security_scans_compare` / `dsh_security_cli` 的 `workdir` 参数由模型提供，直接透传给 shell 服务，**未经过 `resolveTarget()` 的包含性校验**。
- **攻击链**: 插件对 `target` 的约束是"必须落在 workdir 内"——但模型**同时控制 workdir**。模型（或被扫描代码提示注入诱导的模型）可传 `workdir: ~/.ssh`、`target: .`，插件判定"在 workdir 内"放行，CLI 随即读取该目录全部文件并上传到 OpenAI 云扫描管线。实测 DSH shell 沙箱（dsh-bash-sandbox / dsh-sandbox）**只约束写入**（workspace 根 + /tmp），**读取不受限**，因此该链可实际成立。
- **影响**: 任意目录内容被外发给第三方模型/扫描服务（数据外泄）。
- **修复**: 把 `workdir` 视同扫描路径，用同一套 canonicalize+containment 校验（相对会话 cwd），或对 `args.workdir` 显式拒绝越界值；并在工具描述中声明 workdir 必须位于会话工作区内。

### F2 [低-中] `dsh_security_cli` 白名单动词参数无路径约束（plugins/dsh-security/index.js:293-296, 600-613）

- `export` 在白名单中，其子参数（如输出路径 flag）仅做引号转义、不做包含性校验。沙箱对写入有约束（workspace 内），但 `scans logs` 等读操作可指向任意扫描状态目录。建议：对 `export` 输出路径做与扫描输出目录相同的约束，或将 `export` 移出白名单改为专用工具。

### F3 [低] 门禁 LLM 引擎密钥脱敏为近似正则（gate/index.js:83-97, 655-700）

- 正则覆盖 AWS/OpenAI/GitHub/Slack/JWT/Google/Stripe/Azure/私钥/常见 key=value 赋值；但**短值（<8 字符）、含特殊字符的值（如 `p@ssw0rd!`）、非 BEGIN/END 格式私钥、`gho_` 等未覆盖格式**会漏脱敏，随源码发送给模型服务商。`harvestExcludePatterns` 仅按文件名匹配。有 maxFileBytes/maxHarvestChars 上限兜底。建议扩展模式（sk-proj-、gho_、SAS token、更多 key=value 形态），并在文档中明示残余风险。

### F4 [低] 供应链：CLI 未锁版本 + 安装脚本不校验克隆来源

- `npx --yes @openai/codex-security`（plugins/dsh-security/index.js:283, gate/index.js:142）：`--yes` 自动安装最新版，无版本钉扎；npm 缓存/源被污染时以用户权限执行任意代码。建议钉版本（`@openai/codex-security@<ver>`）并校验发布校验和。
- install.sh/install.ps1 管道安装（`irm ... | iex` / `curl | bash`）对 `git clone` 的仓库不校验 commit SHA/签名（install.sh:57, install.ps1:47），且 `repo_url` 来自环境变量、以 `-` 开头可被 git 解析为选项。建议校验 URL scheme 前缀并钉 commit。

### F5 [低] MCP 运行时不受完整性清单覆盖（bundled/mcp/server.mjs:8-24）

- `server.mjs` 运行时解压 `server.mjs.br.part-*`（Brotli）并 `Module._compile()` 执行；插件的 SHA-256 清单**只覆盖 bundled/scripts/*.py**。篡改 .br.part 即宿主进程内代码执行。已解压审阅该运行时（约 1.5MB，esbuild 打包的上游 codex-security MCP server），未见恶意逻辑（execFile/spawn 列表参数、无 shell:true、无网络监听）。建议将 MCP 运行时纳入完整性清单。

### F6 [低] `resolveTarget` 远程引用正则边界（plugins/dsh-security/index.js:216）

- scp 风格正则 `/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:/` 会把工作区内形如 `user@host:name` 的**本地目录**误判为远程引用而跳过包含性检查（CLI 会尝试按 scp 解释）。`https?://` 直通属设计意图（远程仓库）。建议对"远程"判定增加更严格的条件（如要求路径含 `/` 或验证不是已存在的工作区内路径）。

### F7 [信息] 其他观察

- gate 本地 HTTP 端点无认证：/dsh-security/clear 无限流（有同源+Host 校验兜底）；/scan 限流 10 次/10s。威胁模型（本机进程可接触 localhost）下可接受，建议 /clear 同样限流。
- 门禁默认 `scanOnBoot: true`：首次启动自动用 LLM 审计全部已发现插件，产生 token 消耗且将插件源码发送给模型服务商（面板有披露，但建议默认改为显式开启或提示确认）。
- `dsh_security_resources` 返回绝对安装路径（设计如此，模型需要）。
- 安装脚本 `rm -rf` 目标均为 $dsh 派生路径，含 DSH_HOME 空值兜底，无越界删除风险。

## 4. 修复优先级建议

1. **F1（workdir 校验）** — 高优先，一行校验即可闭合数据外泄链。
2. **F4（版本钉扎）** — 中优先，供应链基础卫生。
3. **F3（脱敏增强）/ F5（MCP 运行时入清单）** — 中优先，纵深防御。
4. **F2 / F6 / F7** — 低优先，按需处理。

## 5. 结论

未发现可直接利用的高危漏洞；核心执行路径（命令构造、SQL、文件写入、路径包含、前端渲染）防护扎实。建议按上表优先修复 F1（workdir 约束）与 F4（供应链钉扎），其余作为纵深加固。
---

## 6. 修复状态（已落地）

### F1 — workdir 包含性校验（已修复）

- plugins/dsh-security/index.js：resolveWorkdir() 现在将模型提供的 workdir 视同扫描路径，解析并 canonicalize 后必须落在会话工作目录内；file://、远程 URL、scp 风格引用直接拒绝；~/ 展开后同样受约束。四个工具（scan/findings/scans_compare/cli）统一生效，工具描述同步更新。
- 验证：通过真实插件 apply() 驱动的行为测试 11/11 通过（默认 workdir=会话 cwd、内部子目录放行并规范化、越界/~/../远程 URL 全部抛错、cli 工具同样受约束）。

### F4 — CLI 版本钉扎（已修复）

- plugins/dsh-security/index.js 与 gate/index.js 的 cliCommand 默认值/回退值钉扎为 npx --yes @openai/codex-security@0.1.12；agent.cordis.yml 预设配置、README.md、gate/README.md 同步更新。
- 实际使用澄清：该 npm 包不会自动执行——门禁默认 engine: 'llm'（宿主模型，不触网）；预设的 dsh_security_* 工具是可选路径，仅当模型显式调用且已配置 OpenAI 认证时才跑 npx。仓库 vendored 的上游载荷（bundled/skills、bundled/scripts、bundled/mcp 压缩运行时）才是工作流实际执行的部分；MCP 运行时内部直接 spawn codex CLI 可执行文件（CODEX_CLI_PATH），不走 npx。因此 F4 钉扎是廉价且正确的防御——一旦未来启用 CLI 路径，不会静默拉取最新版。
- 待办（未做）：install.sh/install.ps1 的 git clone 钉 commit SHA/校验签名（F4 的脚本部分）；MCP 运行时纳入完整性清单（F5）。
### 二次修复（门禁 LLM 审计 4 项发现，均已落地并测试通过）

| 门禁发现 | 级别 | 修复 |
|---|---|---|
| 1. scp 风格引用绕过路径约束 | 高 | resolveTarget()：仅 https/ssh/git URL 直接透传；scp 风格引用先探测是否为已存在的本地路径——存在则走正常包含性校验（符号链接逃逸被 canonicalize 拦截），不存在才按远程引用放行 |
| 2. login 在 CLI 白名单中 | 中 | 默认白名单移除 login（配置可经 cliAllowedVerbs 重新加回）；认证改为环境变量方式；工具描述与 SKILL.md 同步更新 |
| 3. timeout_ms 未约束 | 中 | 四个工具统一用 toBoundedInt 校验：整数、1000–86400000（24h）范围外直接抛错；schema 描述同步标注 |
| 4. cliCommand 前缀未校验 | 低 | apply() 加载时校验 cliCommand：含 shell 元字符（; & | ` $ < > ( ) % ^ \ CR LF TAB）则告警并回退到钉扎默认值，与门禁自身校验一致 |

验证：真实插件 apply() 驱动行为测试 15/15 通过（scp 远程透传保留、login 拒绝、超时越界拒绝/默认生效、恶意 cliCommand 不执行并回退）。
### 三次修复（门禁自审计 7 项发现，处理结果）

| 门禁发现 | 级别 | 状态 | 处理 |
|---|---|---|---|
| 1. CLI 引擎默认无沙箱 + cliCommand 仅黑名单校验 | 高 | **已修复** | cliCommand 改为**白名单**（首 token 限 npx/npm/node/codex-security，token 限安全字符，`sh -c "evil"` 直接拒绝并回退钉扎默认）；engine=cli 时 sandboxMode **必填**，缺失则扫描 fail-closed 并给出明确错误，加载时告警；README 同步 |
| 2. 报告渲染 XSS | 低 | 评估安全 | 渲染器全路径先转义后套标签、链接限 https?（复核确认不可利用）；在 client.js 增加**转义顺序不变式**注释，防止未来新增渲染分支破坏防线 |
| 3. resolveTargets TOCTOU/词法回退 | 低 | 评估安全 | canonicalizePath 词法回退有界且所有后续文件操作均重新 canonicalize（harvest 逐文件复验、clear/报告服务重验）；补充注释说明该不变式 |
| 4. 本地端点无鉴权 | 中 | **已修复（外部提交）** | 端点令牌白名单：随机 token 持久化 0600、经 tapIndex 注入页面、全部端点要求 x-dsh-security-token；本会话核查确认接线完整 |
| 5. 脱敏遗漏 URL 内嵌口令/Docker auth/AWS 行内 | 中 | **已修复** | redactSecrets 新增：URL userinfo（https://user:pass@host）、Docker registry auth（≥8 字符 base64）、AWS 行内赋值；SECRET_FILE_PATTERNS 增加 docker-config*.json |
| 6. /clear 无限流 | 低 | **已修复** | 速率限制改为共享桶（scan+clear 各自独立窗口，默认 10 次/10s），/clear 与 /scan 同等限流 |
| 7. path: 键来自原始输入 | 低 | 评估安全 | 该键仅作状态键；报告目录用 safeKey，所有文件操作（harvest/CLI/clear/报告服务）重新 canonicalize+校验；补充注释 |

验证：门禁真实 apply() 驱动行为测试 13/13 通过（fail-closed、白名单回退、sandboxPolicy 传递、新脱敏正则、/clear 限流与 token 校验）。
