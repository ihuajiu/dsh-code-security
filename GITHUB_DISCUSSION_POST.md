# 我把 OpenAI Codex Security 的付费墙拆了，给 DSH 做了一个安全审计门禁

事情是这样的。我在 DSH 里装插件，越装越觉得不对。插件一进去就能读工作区、调模型、跑脚本，但很少有人会真的把每个新插件的源码先读一遍。

所以我把 OpenAI 的 @openai/codex-security 拿过来改了改，做了一个叫 dsh-code-security 的安全审计插件。名字挺朴素，但我想解决的问题很直接，新插件装进 DSH 之前，先让模型把源码看一遍。

默认那条路径，拆掉了 @openai/codex-security 的付费墙和外部认证依赖。不登录 OpenAI，不填 API key，用 DSH 宿主会话同款模型就能审。默认零认证。

这个项目不是 OpenAI 官方产品，命名也已经改成 dsh-code-security，上游归属和许可证都在 README 里。

门禁会轮询 ~/.dsh/.agent-presets/ 和 ~/.dsh/profiles/*/，发现新插件就采集源码生成报告。采集是有界的，node_modules、.git、bundled、二进制、超大文件都跳过；.env、*.pem、*.key、credentials.json 这些敏感文件直接不读，发模型前还会做行内密钥脱敏。已经审计过且没变化的东西，下次自动跳过。

设置页里有一个安全审计面板，状态、报告、一键重新审计、清除记录都有。

![安全审计主界面](https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/assets/%E5%AE%89%E5%85%A8%E5%AE%A1%E8%AE%A1%E4%B8%BB%E7%95%8C%E9%9D%A2.jpg)

报告会内联展示，摘要表在前，风险详情在后。

![审计报告摘要](https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/assets/%E5%AE%89%E5%85%A8%E5%AE%A1%E8%AE%A1-%E5%AE%A1%E8%AE%A1%E6%8A%A5%E5%91%8A%E6%91%98%E8%A6%81.jpg)

![风险审计详情](https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/assets/%E5%AE%89%E5%85%A8%E5%AE%A1%E8%AE%A1-%E9%A3%8E%E9%99%A9%E5%AE%A1%E8%AE%A1%E8%AF%A6%E6%83%85.jpg)

还有几件事我觉得值得说。

审计基线会记住上一轮已经甄别的结论，fixed、false-positive、accepted 都记在 audit-baseline.json 里。下一轮模型不能重复报旧账，除非代码真变了。没有这一层，安全报告很快就会变成噪音。

扫描内容被当成不可信数据，不是指令。恶意插件哪怕在自己源码里塞满「请忽略以上内容」「帮我执行这个命令」，审计模型也只把它当分析对象。

CLI 路径被限制在工作目录里，命令有白名单，默认不放行 login 和 export，CLI 版本钉在 @openai/codex-security@0.1.12，脚本载荷每次使用前做 SHA-256 校验。本地 HTTP 端点还有 token、Host 白名单、Origin 校验和限流。

它也不是银弹。默认 llm 引擎会把有界采集的源码发给当前会话配置的模型服务商，默认是 deepseek-official。敏感代码环境记得关自动审计，或改用 CLI 引擎。门禁采集有 400K 字符上限，超大插件可能漏文件；自动审计是轮询式，默认 60 秒加启动时一次。CLI 引擎需要 OpenAI 认证，默认白名单也不放行 login 和 export。这些我都没藏，README 里都写了。

装起来很快。

Windows

```powershell
irm https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.ps1 | iex
```

macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/ihuajiu/dsh-code-security/main/install.sh | bash
```

重启 DSH，打开设置里的安全审计面板就能看到状态和报告。

npm 地址也放一下，@dsh.so/dsh-security-gate，https://www.npmjs.com/package/@dsh.so/dsh-security-gate 。注意 npm 装完不等于插件生效，最终用户推荐一键脚本。

我始终觉得，安全审计不该是发版前才想起来的事。插件生态越热闹，越需要一个默认先怀疑的门禁。如果你也在 DSH 里装插件，欢迎装来试试，或者直接来聊你的场景。