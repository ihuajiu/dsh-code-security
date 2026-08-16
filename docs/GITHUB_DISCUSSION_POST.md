# 分享一个 DSH 安全审计插件，dsh-code-security

最近给 DeepSeek Harness 折腾了一个安全审计插件，叫 dsh-code-security。它不是又一个「点一下扫一遍」的玩具，而是把插件供应链审计和安全审计模式做成了两条能落地的路径。

## 为什么值得试

DSH 里装插件越来越方便，但插件一旦装进去，就有读取工作区、调用模型、执行脚本的能力。多数时候我们信任来源，可供应链风险是另一件事。这个插件想解决的问题很具体，新插件装进来之前，先让模型把源码看一遍；仓库要审计时，再走一套完整的安全工作流。

它封装了上游 Codex Security 的工作流，但对外命名是 dsh-code-security，不是 OpenAI 官方产品，归属和许可证在仓库里写得很清楚。

## 两条核心能力

自动门禁

监控 `~/.dsh/.agent-presets/` 和 `~/.dsh/profiles/*/`，发现新插件后采集源码生成审计报告。默认跳过 `node_modules`、`.git`、`bundled`、二进制和超限文件，敏感文件名直接不读，发送给模型前还会做行内密钥脱敏。已经审计且没变化的插件会自动跳过。

安全审计模式

新建会话选择「安全审计模式」，可以跑 `security-scan`、`security-diff-scan`、`deep-security-scan`，以及发现、验证、攻击路径分析、威胁建模、triage、fix、track、漏洞报告、加固提案这一整条流水线。

审计结果也不是聊天记录。扫描会产出 `scan-manifest.json`、`findings.json`、`coverage.json` 这类结构化产物，同一仓库扫两次还能对比变化。

## 我最喜欢的几个点

默认路径零认证。它用宿主会话同款模型做审计，不需要 OpenAI API key，不需要额外登录，不需要把代码先传到某个网页。

提示注入被当成真实威胁处理。扫描内容被视为不可信数据，不是指令，恶意插件不能靠源码里的文字指挥审计模型。

误报记忆。`audit-baseline.json` 会记录已甄别的 fixed、false-positive、accepted 结论，下一轮不会重复报旧账，除非能引用变化的代码行证明漏洞复活。

加固很具体。CLI 路径被限制在工作目录内，命令有白名单，默认不放行 `login` 和 `export`，CLI 版本钉扎在 `@openai/codex-security@0.1.12`，脚本载荷每次使用前做 SHA-256 校验。

## 安装

需要先有 git 和 pnpm。

Windows

```powershell
irm https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.ps1 | iex
```

macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.sh | bash
```

装完重启 DSH，新建会话选「安全审计模式」，或在设置页打开「安全审计」面板。

## 需要知道的限制

默认 llm 引擎会把有界采集的源码随提示词发给当前会话配置的模型服务商，通常是 deepseek-official。如果代码绝对不允许外发，请关闭自动审计，或改用 CLI 引擎。

门禁采集默认有 400K 字符上限，超大插件可能漏文件，报告里会标记。要做完整深入审计，请在安全审计模式里用完整工作流跑。

自动审计是轮询式，默认 60 秒加启动时一次，不是插件安装瞬间立刻出结果。

deep 扫描耗时长、token 消耗大，建议后台运行或分批。

## 链接

npm 包地址

- 安全门禁 https://www.npmjs.com/package/@dsh.so/dsh-security-gate

注意，npm 安装适合开发者按需集成，不等于插件已生效。DSH 最终用户仍推荐一键安装脚本。

仓库与文档

仓库地址 https://github.com/ihuajiu/dsh-code-security

完整 README https://github.com/ihuajiu/dsh-code-security/blob/main/README.md

安全审计报告 https://github.com/ihuajiu/dsh-code-security/blob/main/SECURITY_AUDIT_REPORT.md

完整公众号风格长文已放在仓库 https://github.com/ihuajiu/dsh-code-security/blob/main/SECURITY_PLUGIN_RECOMMENDATION.md

如果有朋友也在 DSH 上做插件供应链审计，欢迎一起聊聊使用场景和踩坑。