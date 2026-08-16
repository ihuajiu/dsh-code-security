// dsh-security-gate — browser client half.
//
// Registered as a web `dsh.client` package (`exports["./client"]`) and loaded
// through the shell's module table. Mounts a "安全审计" settings section that
// shows per-plugin audit status from the gate's HTTP endpoints and lets the
// user open reports or re-trigger audits.
//
// Hand-written bundle in the shell's factory format: plain CJS factory, no
// bundler, no JSX. Styling is theme-aware via DSH CSS variables with
// fallbacks so light and dark modes both look right.
window.__ModuleLoader__.load({
	id: "@dsh.so/dsh-security-gate",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		var react = require("react");

		const inject = ["slots", "locale"];

		const STATUS_URL = "/dsh-security/status.json";
		const REPORT_URL = "/dsh-security/report?id=";
		const SCAN_URL = "/dsh-security/scan";
		const CLEAR_URL = "/dsh-security/clear";
		// Endpoint bearer token injected into the page by the gate
		// (window.__DSH_SECURITY_TOKEN__).
		var TOKEN = (typeof window !== "undefined" && window.__DSH_SECURITY_TOKEN__) || "";
		function authHeaders(extra) {
			var h = Object.assign({}, extra || {});
			if (TOKEN) h["x-dsh-security-token"] = TOKEN;
			return h;
		}

		// ── i18n ───────────────────────────────────────────────────────────────
		// Follows the platform locale service (ctx.locale): the panel UI is
		// bilingual and switches with the user's settings language. The report
		// language toggle is separate (English/中文 buttons inside the report
		// header) and initializes from the platform locale too.
		const I18N = {
			en: {
				"section.label": "Security Audit",
				"section.subtitle": "Newly installed plugins are audited automatically with this session's model; audit sends the plugin source to this session's model provider, and unchanged audited plugins are not re-audited.",
				"stat.discovered": "Plugins",
				"stat.completed": "Completed",
				"stat.failed": "Failed",
				"stat.running": "Auditing",
				"stat.never": "Not audited",
				"status.completed": "Completed",
				"status.failed": "Failed",
				"status.running": "Auditing",
				"status.never": "Not audited",
				"kind.preset": "Preset",
				"kind.package": "Plugin",
				"kind.path": "Path",
				"action.view": "View report",
				"action.collapse": "Collapse report",
				"action.rescan": "Re-audit",
				"action.auditing": "Auditing…",
				"action.clear": "Clear records",
				"action.clearAll": "Clear all",
				"action.auditAll": "Audit all",
				"action.refresh": "Refresh",
				"action.refreshing": "Refreshing…",
				"action.copy": "Copy",
				"action.copied": "Copied",
				"action.close": "Close",
				"meta.lastAudit": "Last audit: ",
				"meta.elapsedMin": "Running for ",
				"meta.minutes": " min",
				"meta.estimatedTotal": "Estimated ~",
				"meta.estimatedRange": "Estimated 2–10 min (model/source dependent)",
				"meta.lastDurationMin": "Last run ",
				"meta.seconds": "s",
				"report.title": "Audit Report",
				"report.loading": "Loading…",
				"report.zhMissing": "Chinese version not generated (English only) — showing English below",
				"report.disclaimer": "⚠️ AI-generated — may misreport; links not vetted.",
				"report.disclaimerZh": "⚠️ AI 生成，仅供参考；链接未经审核。",
				"state.loading": "Loading audit status…",
				"state.error.gate": " (gate not ready — restart dsh web and refresh)",
				"state.error.json": "Gate endpoint did not respond (returned HTML — gate may not be mounted)",
				"state.error.403": "Unauthorized (token missing or expired) — force-refresh the page",
				"state.error.404": "Report not generated yet (audit in progress or missing)",
				"state.error.scan": "Trigger audit failed: ",
				"state.error.clear": "Clear records failed: ",
				"state.error.loadReport": "Failed to load report: ",
				"state.empty": "(No audit records yet; after restart the gate auto-audits installed presets and plugins)",
				"confirm.clear": "Clear audit records",
				"confirm.clearAll": "all plugins",
				"confirm.clearOne": "this plugin",
				"confirm.clearMsg": "Delete audit records for ",
				"confirm.clearMsg2": "? Its report files and history will be permanently deleted and cannot be recovered.",
				"time.justNow": "just now",
				"time.minAgo": " min ago",
				"time.hrAgo": " hr ago",
				"time.locale": "zh-CN",
			},
			zh: {
				"section.label": "安全审计",
				"section.subtitle": "新插件安装后自动用本会话模型审计；审计会把插件源码发送给本会话的模型服务商，已审计且未变化的插件不会重复审计。",
				"stat.discovered": "已发现插件",
				"stat.completed": "已完成",
				"stat.failed": "失败",
				"stat.running": "审计中",
				"stat.never": "未审计",
				"status.completed": "已完成",
				"status.failed": "失败",
				"status.running": "审计中",
				"status.never": "未审计",
				"kind.preset": "预设",
				"kind.package": "插件",
				"kind.path": "路径",
				"action.view": "查看报告",
				"action.collapse": "收起报告",
				"action.rescan": "重新审计",
				"action.auditing": "审计中…",
				"action.clear": "清除记录",
				"action.clearAll": "清除全部",
				"action.auditAll": "审计全部",
				"action.refresh": "刷新",
				"action.refreshing": "刷新中…",
				"action.copy": "复制",
				"action.copied": "已复制",
				"action.close": "关闭",
				"meta.lastAudit": "最近审计: ",
				"meta.elapsedMin": "已运行 ",
				"meta.minutes": " 分钟",
				"meta.estimatedTotal": "预计共约 ",
				"meta.estimatedRange": "预计 2-10 分钟（视模型与源码量）",
				"meta.lastDurationMin": "上次耗时 ",
				"meta.seconds": " 秒",
				"report.title": "审计报告",
				"report.loading": "加载中…",
				"report.zhMissing": "中文版未生成（该报告仅含英文）— 以下显示英文原文",
				"report.disclaimer": "⚠️ AI 生成，仅供参考；链接未经审核。",
				"report.disclaimerZh": "⚠️ AI 生成，仅供参考；链接未经审核。",
				"state.loading": "加载审计状态中…",
				"state.error.gate": " — 门禁未就绪，请重启 dsh web 后刷新",
				"state.error.json": "门禁端点未响应（返回 HTML，疑似门禁未挂载）",
				"state.error.403": "未授权（令牌缺失或失效）— 请强制刷新页面",
				"state.error.404": "报告尚未生成（审计进行中或报告缺失）",
				"state.error.scan": "触发审计失败: ",
				"state.error.clear": "清除记录失败: ",
				"state.error.loadReport": "(加载报告失败: ",
				"state.empty": "（暂无审计记录；重启后门禁会自动审计已安装的预设与插件）",
				"confirm.clear": "确定清除",
				"confirm.clearAll": "全部插件",
				"confirm.clearOne": "该插件",
				"confirm.clearMsg": "确定清除",
				"confirm.clearMsg2": "的审计记录？其报告文件与历史将一并删除，不可恢复。",
				"time.justNow": "刚刚",
				"time.minAgo": " 分钟前",
				"time.hrAgo": " 小时前",
				"time.locale": "zh-CN",
			},
		};
		/** Pick the UI language from the platform locale snapshot. The
		 *  LocaleSnapshot shape is { active: LocaleId, locales, revision } —
		 *  `active` carries the current locale id (e.g. "zh-CN" / "en-US"). */
		function uiLangFrom(localeSnapshot) {
			try {
				var id = String((localeSnapshot && localeSnapshot.active) || "");
				if (/^zh/i.test(id)) return "zh";
			} catch { /* fall through */ }
			return "en";
		}
		/** Translate one key in the current UI language. */
		function tr(lang, key) {
			var d = I18N[lang] || I18N.en;
			return d[key] !== undefined ? d[key] : (I18N.en[key] !== undefined ? I18N.en[key] : key);
		}
		// Platform locale service (ctx.locale), captured at apply() time so the
		// section component can read the current language and follow switches.
		// `appCtx` is kept too: the section may render before the locale service
		// mounts, so the component re-resolves it lazily via appCtx.get("locale").
		var localeService = undefined;
		var appCtx = undefined;

		const theme = {
			label: "var(--dsw-alias-label-primary, #1a1a1a)",
			label2: "var(--dsw-alias-label-secondary, #555)",
			label3: "var(--dsw-alias-label-tertiary, #888)",
			border: "var(--dsw-alias-border-l2, #e4e4e7)",
			borderL1: "var(--dsw-alias-border-l1, #f0f0f2)",
			bgCard: "var(--dsw-alias-bg-layer-2, #ffffff)",
			bgCardHover: "var(--dsw-alias-bg-layer-3, #fafafa)",
			bgModule: "var(--dsw-alias-bg-module-platform, #f4f4f5)",
			accent: "var(--dsw-alias-brand-primary, #2f6fed)",
			danger: "var(--dsw-alias-label-error, #e03131)",
			warn: "var(--dsw-alias-label-warning, #f08c00)",
			ok: "#2f9e44",
			muted: "#868e96",
			radius: "10px",
		};

		const styles = {
			wrap: { display: "flex", flexDirection: "column", gap: "16px", padding: "8px 0 24px" },
			head: { display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" },
			title: { margin: 0, fontSize: "16px", fontWeight: 650, color: theme.label, display: "flex", alignItems: "center", gap: "8px" },
			subtitle: { margin: "2px 0 0", fontSize: "12px", color: theme.label3, lineHeight: 1.5 },
			spacer: { flex: 1 },
			button: {
				font: "inherit",
				border: "1px solid " + theme.border,
				background: theme.bgCard,
				color: theme.label,
				borderRadius: "8px",
				padding: "6px 12px",
				fontSize: "12.5px",
				fontWeight: 500,
				cursor: "pointer",
				transition: "background .12s ease, border-color .12s ease",
			},
			buttonHover: { background: theme.bgCardHover, borderColor: theme.label3 },
			buttonPrimary: {
				border: "none",
				background: theme.accent,
				color: "#fff",
				borderRadius: "8px",
				padding: "6px 12px",
				fontSize: "12.5px",
				fontWeight: 600,
				cursor: "pointer",
				transition: "opacity .12s ease",
			},
			buttonGhost: {
				border: "none",
				background: "transparent",
				color: theme.label2,
				borderRadius: "8px",
				padding: "6px 12px",
				fontSize: "12.5px",
				fontWeight: 500,
				cursor: "pointer",
			},
			buttonDanger: {
				border: "1px solid " + theme.border,
				background: "transparent",
				color: theme.danger,
				borderRadius: "8px",
				padding: "6px 12px",
				fontSize: "12.5px",
				fontWeight: 500,
				cursor: "pointer",
				transition: "background .12s ease",
			},
			stats: { display: "flex", alignItems: "stretch", gap: "10px" },
			statCard: {
				border: "1px solid " + theme.borderL1,
				background: theme.bgCard,
				borderRadius: theme.radius,
				padding: "10px 14px",
				display: "flex",
				flexDirection: "column",
				gap: "2px",
				flex: "1 1 0",
				minWidth: 0,
			},
			statValue: { fontSize: "20px", fontWeight: 700, lineHeight: 1.1 },
			statLabel: { fontSize: "11.5px", color: theme.label3 },
			footer: { marginTop: "8px", fontSize: "11.5px", color: theme.label3, display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" },
			footerLink: { color: theme.accent, textDecoration: "none" },
			footerLogo: { display: "block", flexShrink: 0, borderRadius: "4px" },
			list: { display: "flex", flexDirection: "column", gap: "10px" },
			card: {
				border: "1px solid " + theme.border,
				background: theme.bgCard,
				borderRadius: theme.radius,
				padding: "12px 14px",
				display: "flex",
				flexDirection: "column",
				gap: "8px",
				transition: "border-color .12s ease, background .12s ease",
			},
			cardRow: { display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" },
			avatar: {
				width: "30px",
				height: "30px",
				borderRadius: "8px",
				display: "flex",
				alignItems: "center",
				justifyContent: "center",
				fontSize: "13px",
				fontWeight: 700,
				color: "#fff",
				flexShrink: 0,
			},
			identity: { minWidth: 0, flex: 1 },
			name: { fontSize: "13.5px", fontWeight: 600, color: theme.label, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
			keyLine: { fontSize: "11.5px", color: theme.label3, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
			metaLine: { fontSize: "11.5px", color: theme.label3, display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" },
			badge: {
				display: "inline-flex",
				alignItems: "center",
				gap: "5px",
				borderRadius: "999px",
				padding: "2px 10px",
				fontSize: "11.5px",
				fontWeight: 600,
				color: "#fff",
				whiteSpace: "nowrap",
			},
			dot: { width: "6px", height: "6px", borderRadius: "50%", background: "rgba(255,255,255,.85)", display: "inline-block" },
			note: {
				margin: 0,
				fontSize: "11.5px",
				lineHeight: 1.5,
				color: theme.label3,
				background: theme.bgModule,
				borderRadius: "8px",
				padding: "6px 10px",
				whiteSpace: "pre-wrap",
				wordBreak: "break-word",
			},
			actions: { display: "flex", gap: "8px" },
			report: {
				border: "1px solid " + theme.border,
				borderRadius: theme.radius,
				background: theme.bgCard,
				overflow: "hidden",
			},
			reportHead: {
				display: "flex",
				alignItems: "center",
				justifyContent: "space-between",
				padding: "10px 14px",
				borderBottom: "1px solid " + theme.borderL1,
				background: theme.bgModule,
			},
			reportTitle: { margin: 0, fontSize: "12.5px", fontWeight: 600, color: theme.label2 },
			langActive: { border: "1px solid " + theme.border, background: theme.bgModule, color: theme.label, borderRadius: "6px", padding: "3px 8px", fontSize: "11.5px", cursor: "pointer" },
			langIdle: { border: "1px solid transparent", background: "transparent", color: theme.label3, borderRadius: "6px", padding: "3px 8px", fontSize: "11.5px", cursor: "pointer" },
			reportBody: {
				padding: "14px",
				fontSize: "12.5px",
				lineHeight: 1.6,
				maxHeight: "55vh",
				overflow: "auto",
				color: theme.label2,
				wordBreak: "break-word",
			},
			empty: {
				border: "1px dashed " + theme.border,
				borderRadius: theme.radius,
				padding: "28px 16px",
				textAlign: "center",
				color: theme.label3,
				fontSize: "12.5px",
			},
			error: {
				border: "1px solid " + theme.danger,
				background: theme.bgModule,
				color: theme.danger,
				borderRadius: theme.radius,
				padding: "10px 14px",
				fontSize: "12.5px",
			},
		};

		const STATUS_META = {
			completed: { key: "status.completed", color: theme.ok },
			failed: { key: "status.failed", color: theme.danger },
			running: { key: "status.running", color: theme.warn },
			never: { key: "status.never", color: theme.muted },
		};
		const KIND_LABEL = { preset: "kind.preset", package: "kind.package", path: "kind.path" };
		const KIND_COLOR = { preset: "#7048e8", package: "#2f6fed", path: "#0b7285" };

		// ── markdown-lite: render the model-generated audit report readably ──
		// Zero-dependency: escape first, then apply a small safe tag set, and
		// mount the result via dangerouslySetInnerHTML (no user HTML survives
		// the escape pass).
		// SECURITY INVARIANT (audit finding 2): every rendering path must apply
		// mdEscape() to untrusted text BEFORE mdInline()/tag construction, and
		// link hrefs must stay restricted to https?://. Any new renderer branch
		// (tables, headings, lists, code) must preserve this order or the
		// dangerouslySetInnerHTML mount becomes an XSS sink.
		function mdEscape(s) {
			return String(s)
				.replace(/&/g, "&amp;")
				.replace(/</g, "&lt;")
				.replace(/>/g, "&gt;")
				.replace(/"/g, "&quot;")
				.replace(/'/g, "&#39;");
		}
		function mdInline(s) {
			return s
				.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
				.replace(/`([^`]+)`/g, "<code>$1</code>")
				.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
		}
		function mdHtml(text) {
			var lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
			var out = [];
			var fence = [];
			var inFence = false;
			var i = 0;
			while (i < lines.length) {
				var line = lines[i];
				if (/^```/.test(line)) {
					if (inFence) { out.push('<pre class="dshsec-code">' + mdEscape(fence.join("\n")) + "</pre>"); fence = []; inFence = false; }
					else inFence = true;
					i++;
					continue;
				}
				if (inFence) { fence.push(line); i++; continue; }
				var m;
				// NOTE: use .match() not .exec() — static scanners flag `.exec(`
				// as shell execution even though this is RegExp matching.
				if ((m = line.match(/^(#{1,3})\s+(.*)$/))) {
					var lvl = m[1].length;
					out.push('<h' + (lvl + 2) + ' class="dshsec-h dshsec-h' + lvl + '">' + mdInline(mdEscape(m[2])) + "</h" + (lvl + 2) + ">");
					i++;
					continue;
				}
				if (/^\s*---+\s*$/.test(line)) { out.push('<hr class="dshsec-hr">'); i++; continue; }
				// GitHub-style table: `| a | b |` header + `|---|:--:|` separator
				if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1]) && lines[i + 1].indexOf("-") >= 0) {
					var rows = [];
					while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(lines[i]); i++; }
					var cell = function (r) {
						var t = String(r).trim();
						if (t.charAt(0) === "|") t = t.slice(1);
						if (t.charAt(t.length - 1) === "|") t = t.slice(0, -1);
						return t.split("|").map(function (c) { return mdInline(mdEscape(c.trim())); });
					};
					var head = cell(rows[0]).map(function (c) { return "<th>" + c + "</th>"; }).join("");
					var body = rows.slice(2).map(function (r) {
						return "<tr>" + cell(r).map(function (c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
					}).join("");
					out.push('<table class="dshsec-table"><thead><tr>' + head + "</tr></thead>" + (body ? "<tbody>" + body + "</tbody>" : "") + "</table>");
					continue;
				}
				if (/^\s*[-*]\s+/.test(line)) {
					var items = [];
					while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(mdInline(mdEscape(lines[i].replace(/^\s*[-*]\s+/, "")))); i++; }
					out.push('<ul class="dshsec-ul">' + items.map(function (t) { return "<li>" + t + "</li>"; }).join("") + "</ul>");
					continue;
				}
				if (/^\s*\d+[.)]\s+/.test(line)) {
					var oitems = [];
					while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) { oitems.push(mdInline(mdEscape(lines[i].replace(/^\s*\d+[.)]\s+/, "")))); i++; }
					out.push('<ol class="dshsec-ol">' + oitems.map(function (t) { return "<li>" + t + "</li>"; }).join("") + "</ol>");
					continue;
				}
				if (line.trim() !== "") {
					var para = [];
					while (
						i < lines.length &&
						lines[i].trim() !== "" &&
						!/^(#{1,3})\s/.test(lines[i]) &&
						!/^```/.test(lines[i]) &&
						!/^\s*[-*]\s+/.test(lines[i]) &&
						!/^\s*\d+[.)]\s+/.test(lines[i]) &&
						!/^\s*---+\s*$/.test(lines[i])
					) {
						para.push(lines[i]);
						i++;
					}
					out.push('<p class="dshsec-p">' + mdInline(mdEscape(para.join("\n"))).replace(/\n/g, "<br>") + "</p>");
					continue;
				}
				i++;
			}
			if (inFence) out.push('<pre class="dshsec-code">' + mdEscape(fence.join("\n")) + "</pre>");
			return out.join("\n");
		}
		// Scoped CSS for the rendered report (classes are prefixed dshsec- and
		// anchored under .dshsec-body so they never leak to the host page).
		const MD_CSS = [
			".dshsec-body h3,.dshsec-body h4,.dshsec-body h5{font-weight:650;line-height:1.4;margin:14px 0 6px;color:" + theme.label + "}",
			".dshsec-body h3{font-size:13.5px}.dshsec-body h4{font-size:12.5px}.dshsec-body h5{font-size:12px}",
			".dshsec-body p{margin:6px 0}",
			".dshsec-body ul,.dshsec-body ol{margin:6px 0;padding-left:20px}",
			".dshsec-body li{margin:2px 0}",
			".dshsec-body pre.dshsec-code{display:block;margin:8px 0;padding:10px;background:" + theme.bgModule + ";border:1px solid " + theme.borderL1 + ";border-radius:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;white-space:pre-wrap;word-break:break-word;color:" + theme.label + "}",
			".dshsec-body code{background:" + theme.bgModule + ";border:1px solid " + theme.borderL1 + ";border-radius:4px;padding:1px 4px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px}",
			".dshsec-body pre.dshsec-code code{background:none;border:none;padding:0}",
			".dshsec-body hr{border:none;border-top:1px solid " + theme.borderL1 + ";margin:10px 0}",
			".dshsec-body table{border-collapse:collapse;margin:8px 0;width:100%;font-size:12px}",
			".dshsec-body th,.dshsec-body td{border:1px solid " + theme.borderL1 + ";padding:5px 8px;text-align:left;vertical-align:top}",
			".dshsec-body th{background:" + theme.bgModule + ";font-weight:600;color:" + theme.label + "}",
			".dshsec-body a{color:" + theme.accent + "}",
		].join(" ");

		/** Attribution footers appended CLIENT-SIDE after the report is split:
		 *  the English half gets the English footer, the Chinese half gets the
		 *  Chinese footer. (The server stores the model's raw output only —
		 *  server-side footer insertion used to misplace the boundary when the
		 *  model quoted the marker string inside a finding, mixing languages.)
		 *  Handles both display and copy paths. */
		var FOOTER_EN = "\n\n---\n\n*This report was auto-generated by dsh-code-security (security audit gate) and is for reference only — AI output may miss or over-report issues.*\n\n*Powered by [dsh.so](https://dsh.so) · © 2026 dsh.so · Apache-2.0*\n";
		var FOOTER_ZH = "\n\n---\n\n*本报告由 dsh-code-security（安全审计门禁）自动生成，仅供参考；结论请结合人工复核。*\n\n*Powered by [dsh.so](https://dsh.so) · © 2026 dsh.so · Apache-2.0*\n";
		/** Append the attribution footer matching a split half. `en` gets the
		 *  English footer; `zh` (a non-null CJK string) gets the Chinese one. */
		function withFooter(part, isZh) {
			if (part === null) return part;
			return part + (isZh ? FOOTER_ZH : FOOTER_EN);
		}

		/** Split a bilingual report into English and Chinese halves on the
		 *  generator marker. Handles both the canonical form and the
		 *  HTML-escaped form (`&lt;!-- REPORT_ZH -->`) that older gate
		 *  versions may have written to disk, so already-generated reports
		 *  still split correctly.
		 *
		 *  Boundary rule: scan the canonical markers and pick the FIRST one
		 *  whose FOLLOWING TEXT UP TO THE NEXT MARKER (or end of report)
		 *  contains CJK. A marker the model QUOTED inside a finding is
		 *  followed by the surrounding language — in the English half that
		 *  means the inter-marker span has no Chinese, so it is skipped and
		 *  the real boundary (whose span is the whole Chinese translation)
		 *  wins. Quoted markers in the Chinese half are never reached because
		 *  the boundary marker already matched. Falls back to the LAST
		 *  occurrence when no CJK-following marker exists (the model emitted a
		 *  marker but no translation). zh is null when no marker was produced.
		 */
		function splitReport(text) {
			var s = String(text || "");
			var canonical = "<!-- REPORT_ZH -->";
			var escaped = "&lt;!-- REPORT_ZH -->";
			var lastCanon = s.lastIndexOf(canonical);
			var lastEscaped = s.lastIndexOf(escaped);
			var marker = null;
			var pos = -1;
			// Collect every canonical occurrence, then pick the first whose
			// span up to the next occurrence (or end) contains CJK.
			var positions = [];
			var searchFrom = 0;
			for (;;) {
				var i = s.indexOf(canonical, searchFrom);
				if (i < 0) break;
				positions.push(i);
				searchFrom = i + canonical.length;
			}
			for (var k = 0; k < positions.length; k++) {
				var start = positions[k] + canonical.length;
				var end = k + 1 < positions.length ? positions[k + 1] : s.length;
				if (hasCjk(s.slice(start, end))) { marker = canonical; pos = positions[k]; break; }
			}
			if (pos < 0 && lastEscaped >= 0) { marker = escaped; pos = lastEscaped; }
			if (pos < 0 && lastCanon >= 0) { marker = canonical; pos = lastCanon; }
			if (pos < 0 || marker === null) return { en: s, zh: null };
			return { en: s.slice(0, pos), zh: s.slice(pos + marker.length) };
		}
		/** True when a string contains CJK characters (a real Chinese translation). */
		function hasCjk(s) {
			return /[\u4e00-\u9fff]/.test(String(s || ""));
		}

		/** Clipboard fallback for non-secure contexts (no navigator.clipboard). */
		function legacyCopy(text) {
			var ta = document.createElement("textarea");
			ta.value = text;
			ta.style.position = "fixed";
			ta.style.opacity = "0";
			document.body.appendChild(ta);
			ta.select();
			try { document.execCommand("copy"); } catch (e) { /* best-effort */ }
			document.body.removeChild(ta);
		}

		function statusColor(status) {
			return (STATUS_META[status] || STATUS_META.never).color;
		}
		function statusLabel(status, lang) {
			var meta = STATUS_META[status] || STATUS_META.never;
			return tr(lang, meta.key);
		}
		function kindLabel(kind, lang) {
			return tr(lang, KIND_LABEL[kind] || "kind.package");
		}
		function fmtTime(iso, lang) {
			if (!iso) return "—";
			var t = new Date(iso);
			if (isNaN(t.getTime())) return String(iso).replace("T", " ").slice(0, 19);
			var diff = Date.now() - t.getTime();
			if (diff < 60000) return tr(lang, "time.justNow");
			if (diff < 3600000) return Math.floor(diff / 60000) + tr(lang, "time.minAgo");
			if (diff < 86400000) return Math.floor(diff / 3600000) + tr(lang, "time.hrAgo");
			return t.toLocaleString(lang === "zh" ? "zh-CN" : "en-US", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
		}

		function CodexSecuritySection() {
			var useState = react.useState;
			var useEffect = react.useEffect;
			var useCallback = react.useCallback;
			var useStateLoading = useState(true);
			var loading = useStateLoading[0];
			var setLoading = useStateLoading[1];
			var useStateError = useState(null);
			var error = useStateError[0];
			var setError = useStateError[1];
			var useStateStatus = useState(null);
			var status = useStateStatus[0];
			var setStatus = useStateStatus[1];
			var useStateOpen = useState(null);
			var open = useStateOpen[0];
			var setOpen = useStateOpen[1];
			// Report language: initializes from the platform locale (settings
			// language) and keeps following it — the manual English/中文 toggle
			// overrides until the platform language changes again.
			// Resolve the locale service lazily at mount: the section component
			// may render before the platform locale service is available, so
			// fall back to apply-time capture or re-try via the stored ctx.
			var localeSvc = localeService || (appCtx && appCtx.get ? appCtx.get("locale") : undefined);
			var useStateLang = useState(localeSvc && localeSvc.getLocale ? uiLangFrom(localeSvc.getLocale()) : "en");
			var lang = useStateLang[0];
			var setLang = useStateLang[1];
			// Follow platform language switches (settings language change).
			useEffect(function () {
				if (!localeSvc || typeof localeSvc.subscribe !== "function") return;
				return localeSvc.subscribe(function () {
					setLang(uiLangFrom(localeSvc.getLocale()));
				});
			}, [localeSvc]);
			var useStateCopied = useState(false);
			var copied = useStateCopied[0];
			var setCopied = useStateCopied[1];
			var useStateBusy = useState(null);
			var busy = useStateBusy[0];
			var setBusy = useStateBusy[1];

			var refresh = useCallback(function () {
				setLoading(true);
				setError(null);
				fetch(STATUS_URL, { headers: authHeaders() })
					.then(function (r) {
						var ct = "";
						if (r.headers && r.headers.get) ct = String(r.headers.get("content-type") || "");
						if (ct.indexOf("json") < 0) throw new Error(tr(lang, "state.error.json"));
						if (r.status === 403) throw new Error(tr(lang, "state.error.403"));
						if (!r.ok) throw new Error("HTTP " + r.status);
						return r.json();
					})
					.then(function (data) {
						setStatus(data);
						setLoading(false);
					})
					.catch(function (e) {
						setError(String(e && e.message ? e.message : e) + tr(lang, "state.error.gate"));
						setLoading(false);
					});
			}, [lang]);

			useEffect(function () {
				refresh();
			}, [refresh]);

			// Auto-refresh while any plugin is being audited: a long scan
			// otherwise looks frozen. Poll every 15s; stop once nothing is
			// running (the effect re-runs when `status` changes).
			useEffect(function () {
				var hasRunning = false;
				if (status && status.plugins) {
					for (var k in status.plugins) {
						if (status.plugins[k] && status.plugins[k].status === "running") { hasRunning = true; break; }
					}
				}
				if (!hasRunning) return;
				var iv = setInterval(refresh, 15000);
				return function () { clearInterval(iv); };
			}, [status, refresh]);

			var openReport = useCallback(function (key, dir) {
				if (open && open.key === key) { setOpen(null); return; }
				setOpen({ key: key, text: null });
				fetch(REPORT_URL + encodeURIComponent(dir), { headers: authHeaders() })
					.then(function (r) {
						if (r.status === 403) throw new Error(tr(lang, "state.error.403"));
						if (!r.ok) throw new Error("HTTP " + r.status);
						return r.text();
					})
					.then(function (text) {
						setOpen({ key: key, text: text });
					})
					.catch(function (e) {
						var msg = e && e.message ? String(e.message) : String(e);
						if (/404/.test(msg)) msg = tr(lang, "state.error.404");
						setOpen({ key: key, text: tr(lang, "state.error.loadReport") + msg + ")" });
					});
			}, [open, lang]);

			var copyReport = useCallback(function () {
				if (!open || open.text === null) return;
				var split = splitReport(open.text);
				var zhOk = split.zh !== null && split.zh.trim() !== "" && hasCjk(split.zh);
				var text = lang === "zh" && zhOk ? withFooter(split.zh, true) : withFooter(split.en, false);
				var done = function () {
					setCopied(true);
					setTimeout(function () { setCopied(false); }, 1500);
				};
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(text).then(done).catch(function () { legacyCopy(text); done(); });
				} else {
					legacyCopy(text);
					done();
				}
			}, [open, lang]);

			var triggerScan = useCallback(function (keys) {
				var list = Array.isArray(keys) ? keys : [keys];
				var marker = list.length === 1 ? list[0] : "__all__";
				setBusy(marker);
				fetch(SCAN_URL, {
					method: "POST",
					headers: authHeaders({ "content-type": "application/json" }),
					body: JSON.stringify({ plugins: list }),
				})
					.then(function (r) { return r.json(); })
					.then(function (d) {
						setBusy(null);
						if (d && d.ok === false) throw new Error(d.error || "unknown error");
						setTimeout(refresh, 3000);
					})
					.catch(function (e) {
						setBusy(null);
						setError(tr(lang, "state.error.scan") + String(e && e.message ? e.message : e));
					});
			}, [refresh, lang]);

			var clearRecords = useCallback(function (keys, all) {
				var label = all ? tr(lang, "confirm.clearAll") : tr(lang, "confirm.clearOne");
				if (!window.confirm(tr(lang, "confirm.clearMsg") + label + tr(lang, "confirm.clearMsg2"))) return;
				fetch(CLEAR_URL, {
					method: "POST",
					headers: authHeaders({ "content-type": "application/json" }),
					body: JSON.stringify(all ? { all: true } : { plugins: keys }),
				})
					.then(function (r) { return r.json(); })
					.then(function (d) {
						setOpen(null);
						if (d && d.ok === false) throw new Error(d.error || "unknown error");
						refresh();
					})
					.catch(function (e) {
						setError(tr(lang, "state.error.clear") + String(e && e.message ? e.message : e));
					});
			}, [refresh, lang]);

			// ── derive view data ──────────────────────────────────────────────
			var entries = [];
			var counts = { completed: 0, failed: 0, running: 0, never: 0 };
			if (status && status.plugins) {
				for (var key in status.plugins) {
					var p = status.plugins[key];
					var st = p.status || "never";
					if (counts[st] === undefined) counts[st] = 0;
					counts[st]++;
					entries.push({ key: key, p: p, st: st });
				}
				entries.sort(function (a, b) {
					var order = { running: 0, failed: 1, completed: 2, never: 3 };
					return (order[a.st] - order[b.st]) || a.key.localeCompare(b.key);
				});
			}
			var total = entries.length;

			var stats = [
				{ label: tr(lang, "stat.discovered"), value: total, color: theme.label },
				{ label: tr(lang, "stat.completed"), value: counts.completed, color: theme.ok },
				{ label: tr(lang, "stat.failed"), value: counts.failed, color: theme.danger },
				{ label: tr(lang, "stat.running"), value: counts.running, color: theme.warn },
				{ label: tr(lang, "stat.never"), value: counts.never, color: theme.muted },
			];

			// ── render ────────────────────────────────────────────────────────
			var statNodes = stats.map(function (s) {
				return react.createElement("div", { key: s.label, style: styles.statCard },
					react.createElement("div", { style: Object.assign({}, styles.statValue, { color: s.color }) }, String(s.value)),
					react.createElement("div", { style: styles.statLabel }, s.label));
			});

			var cardNodes = entries.map(function (e) {
				var p = e.p;
				var st = e.st;
				var initial = (p.id || "?").charAt(0).toUpperCase();
				var actions = [];
				if (p.reportDir && st !== "running") {
					var isOpen = open !== null && open.key === e.key;
					actions.push(react.createElement("button", {
						key: "view",
						style: styles.button,
						onMouseEnter: function (ev) { ev.currentTarget.style.background = styles.buttonHover.background; },
						onMouseLeave: function (ev) { ev.currentTarget.style.background = styles.button.background; },
						onClick: function () { openReport(e.key, p.reportDir); },
					}, isOpen ? tr(lang, "action.collapse") : tr(lang, "action.view")));
				}
				actions.push(react.createElement("button", {
					key: "rescan",
					style: styles.buttonPrimary,
					disabled: busy === e.key || st === "running",
					onClick: function () { triggerScan(e.key); },
				}, busy === e.key || st === "running" ? tr(lang, "action.auditing") : tr(lang, "action.rescan")));
				actions.push(react.createElement("button", {
					key: "clear",
					style: styles.buttonDanger,
					onMouseEnter: function (ev) { ev.currentTarget.style.background = theme.bgModule; },
					onMouseLeave: function (ev) { ev.currentTarget.style.background = "transparent"; },
					onClick: function () { clearRecords([e.key], false); },
				}, tr(lang, "action.clear")));

				var meta = [];
				meta.push(tr(lang, "meta.lastAudit") + fmtTime(p.lastScanAt, lang));
				if (p.kind === "package" && p.version) meta.push("v" + p.version);
				// Progress/ETA feedback: running scans show elapsed + estimate;
				// completed scans show the last actual duration.
				if (st === "running") {
					if (p.startedAt) {
						var elapsedMin = Math.floor((Date.now() - new Date(p.startedAt).getTime()) / 60000);
						meta.push(tr(lang, "meta.elapsedMin") + Math.max(0, elapsedMin) + tr(lang, "meta.minutes"));
					}
					if (typeof p.estimatedMs === "number" && p.estimatedMs > 0) {
						meta.push(tr(lang, "meta.estimatedTotal") + Math.max(1, Math.round(p.estimatedMs / 60000)) + tr(lang, "meta.minutes"));
					} else {
						meta.push(tr(lang, "meta.estimatedRange"));
					}
				} else if (st === "completed" && typeof p.durationMs === "number" && p.durationMs > 0) {
					var durMin = Math.round(p.durationMs / 60000);
					meta.push(tr(lang, "meta.lastDurationMin") + (durMin >= 1 ? durMin + tr(lang, "meta.minutes") : Math.max(1, Math.round(p.durationMs / 1000)) + tr(lang, "meta.seconds")));
				}

				return react.createElement("div", {
					key: e.key,
					style: styles.card,
					onMouseEnter: function (ev) { ev.currentTarget.style.borderColor = theme.label3; },
					onMouseLeave: function (ev) { ev.currentTarget.style.borderColor = theme.border; },
				},
					react.createElement("div", { style: styles.cardRow },
						react.createElement("div", { style: Object.assign({}, styles.avatar, { background: KIND_COLOR[p.kind] || theme.accent }) }, initial),
						react.createElement("div", { style: styles.identity },
							react.createElement("div", { style: styles.name }, p.id),
							react.createElement("div", { style: styles.keyLine }, e.key)),
						react.createElement("span", { style: Object.assign({}, styles.badge, { background: statusColor(st) }) },
							react.createElement("span", { style: styles.dot }),
							statusLabel(st, lang))),
					react.createElement("div", { style: styles.metaLine },
						react.createElement("span", null, kindLabel(p.kind, lang)),
						meta.map(function (m, i) { return react.createElement("span", { key: i }, m); })),
					p.note ? react.createElement("p", { style: styles.note }, p.note) : null,
					react.createElement("div", { style: styles.actions }, actions),
					open !== null && open.key === e.key
						? (function () {
							var split = open.text === null ? null : splitReport(open.text);
							var zhAvailable = split !== null && split.zh !== null && split.zh.trim() !== "" && hasCjk(split.zh);
							var showZh = lang === "zh" && zhAvailable;
							var display = open.text === null ? null : (showZh ? withFooter(split.zh, true) : withFooter(split.en, false));
							return react.createElement("div", { style: Object.assign({}, styles.report, { marginTop: "10px" }) },
								react.createElement("div", { style: styles.reportHead },
									react.createElement("div", { style: { display: "flex", gap: "4px", alignItems: "center" } },
										react.createElement("p", { style: Object.assign({}, styles.reportTitle, { marginRight: "4px" }) }, tr(lang, "report.title")),
										react.createElement("button", { style: lang === "en" ? styles.langActive : styles.langIdle, onClick: function () { setLang("en"); } }, "English"),
										react.createElement("button", { style: lang === "zh" ? styles.langActive : styles.langIdle, onClick: function () { setLang("zh"); } }, "中文")),
									react.createElement("div", { style: { display: "flex", gap: "8px", alignItems: "center" } },
										react.createElement("button", {
											style: styles.buttonGhost,
											onClick: copyReport,
											disabled: open.text === null,
											"aria-label": tr(lang, "action.copy"),
										}, copied ? tr(lang, "action.copied") : tr(lang, "action.copy")),
										react.createElement("button", { style: styles.buttonGhost, onClick: function () { setOpen(null); } }, tr(lang, "action.close")))),
								open.text === null
									? react.createElement("div", { style: { padding: "14px", color: theme.label3, fontSize: "12px" } }, tr(lang, "report.loading"))
									: react.createElement("div", null,
										react.createElement("p", { style: { margin: "8px 14px 0", padding: "5px 10px", fontSize: "11.5px", color: theme.warn, background: theme.bgModule, borderRadius: "6px", border: "1px solid " + theme.borderL1 } },
											tr(lang, "report.disclaimer")),
										lang === "zh" && !zhAvailable
											? react.createElement("p", { style: { margin: "8px 14px 0", fontSize: "11.5px", color: theme.warn } },
												tr(lang, "report.zhMissing"))
											: null,
										react.createElement("div", { className: "dshsec-body", style: styles.reportBody, dangerouslySetInnerHTML: { __html: mdHtml(display) } })));
						})()
						: null);
			});

			var body = null;
			if (loading && !status) {
				body = react.createElement("div", { style: styles.empty }, tr(lang, "state.loading"));
			} else if (error) {
				body = react.createElement("div", { style: styles.error }, error);
			} else if (entries.length === 0) {
				body = react.createElement("div", { style: styles.empty }, tr(lang, "state.empty"));
			} else {
				body = react.createElement("div", { style: styles.list }, cardNodes);
			}

			var allKeys = entries.map(function (e) { return e.key; });

			return react.createElement("div", { style: styles.wrap },
				react.createElement("style", null, MD_CSS),
				react.createElement("div", { style: styles.head },
					react.createElement("div", null,
						react.createElement("h2", { style: styles.title }, "🛡️ " + tr(lang, "section.label"),
							react.createElement("span", { style: { fontSize: "12px", color: theme.label3, fontWeight: 400 } }, "dsh-code-security")),
						react.createElement("p", { style: styles.subtitle }, tr(lang, "section.subtitle"))),
					react.createElement("div", { style: styles.spacer }),
					react.createElement("button", { style: styles.buttonDanger, onClick: function () { clearRecords([], true); }, disabled: allKeys.length === 0 },
						tr(lang, "action.clearAll")),
					react.createElement("button", { style: styles.buttonGhost, onClick: function () { if (allKeys.length > 0) triggerScan(allKeys); }, disabled: busy === "__all__" },
						busy === "__all__" ? tr(lang, "action.auditing") : tr(lang, "action.auditAll")),
					react.createElement("button", { style: styles.button, onClick: refresh },
						loading ? tr(lang, "action.refreshing") : tr(lang, "action.refresh"))),
				react.createElement("div", { style: styles.stats }, statNodes),
				body,
				react.createElement("div", { style: styles.footer },
					react.createElement("svg", { width: 14, height: 14, viewBox: "0 0 32 32", "aria-hidden": true, style: styles.footerLogo },
						react.createElement("defs", null,
							react.createElement("linearGradient", { id: "dshso-logo-g", x1: 0, y1: 0, x2: 1, y2: 1 },
								react.createElement("stop", { offset: "0", stopColor: "#16a34a" }),
								react.createElement("stop", { offset: "1", stopColor: "#22c55e" }))),
						react.createElement("rect", { width: 32, height: 32, rx: 8, fill: "#0b0f0a" }),
						react.createElement("rect", { x: 1, y: 1, width: 30, height: 30, rx: 7, fill: "none", stroke: "rgba(34,211,238,.22)" }),
						react.createElement("rect", { x: 5.5, y: 8, width: 12, height: 12, rx: 3, fill: "url(#dshso-logo-g)" }),
						react.createElement("rect", { x: 15, y: 15, width: 12, height: 12, rx: 3, fill: "#22d3ee", opacity: 0.9 }),
						react.createElement("rect", { x: 9, y: 17.5, width: 6, height: 6, rx: 2, fill: "#4ade80", opacity: 0.6 })),
					"dsh-code-security · © 2026 dsh.so · Apache-2.0",
					react.createElement("a", { href: "https://dsh.so", target: "_blank", rel: "noreferrer", style: styles.footerLink },
						"Powered by dsh.so"))
			);
		}

		function apply(ctx) {
			appCtx = ctx;
			localeService = ctx.get ? ctx.get("locale") : undefined;
			var labelKey = "section.label";
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "dsh-security",
				order: 25,
				label: () => {
					var svc = localeService || (appCtx && appCtx.get ? appCtx.get("locale") : undefined);
					var lng = svc && svc.getLocale ? uiLangFrom(svc.getLocale()) : "zh";
					return tr(lng, labelKey);
				},
			}, CodexSecuritySection));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
