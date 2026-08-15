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

		const inject = ["slots"];

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
			completed: { label: "已完成", color: theme.ok },
			failed: { label: "失败", color: theme.danger },
			running: { label: "审计中", color: theme.warn },
			never: { label: "未审计", color: theme.muted },
		};
		const KIND_LABEL = { preset: "预设", package: "插件", path: "路径" };
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
				.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
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
				if ((m = /^(#{1,3})\s+(.*)$/.exec(line))) {
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

		/** Split a bilingual report into English and Chinese halves on the
		 *  generator marker. Splits on the LAST occurrence: flash models
		 *  sometimes drop a stray marker after an intro sentence, which would
		 *  otherwise leave the English view empty. zh is null when the model
		 *  produced no marker. */
		function splitReport(text) {
			var marker = "<!-- REPORT_ZH -->";
			var s = String(text || "");
			var idx = s.lastIndexOf(marker);
			if (idx < 0) return { en: s, zh: null };
			return { en: s.slice(0, idx), zh: s.slice(idx + marker.length) };
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
		function statusLabel(status) {
			return (STATUS_META[status] || STATUS_META.never).label;
		}
		function fmtTime(iso) {
			if (!iso) return "—";
			var t = new Date(iso);
			if (isNaN(t.getTime())) return String(iso).replace("T", " ").slice(0, 19);
			var diff = Date.now() - t.getTime();
			if (diff < 60000) return "刚刚";
			if (diff < 3600000) return Math.floor(diff / 60000) + " 分钟前";
			if (diff < 86400000) return Math.floor(diff / 3600000) + " 小时前";
			return t.toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
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
			var useStateLang = useState("en");
			var lang = useStateLang[0];
			var setLang = useStateLang[1];
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
						if (ct.indexOf("json") < 0) throw new Error("门禁端点未响应（返回 HTML，疑似门禁未挂载）");
						if (r.status === 403) throw new Error("未授权（令牌缺失或失效）— 请强制刷新页面");
						if (!r.ok) throw new Error("HTTP " + r.status);
						return r.json();
					})
					.then(function (data) {
						setStatus(data);
						setLoading(false);
					})
					.catch(function (e) {
						setError(String(e && e.message ? e.message : e) + " — 门禁未就绪，请重启 dsh web 后刷新");
						setLoading(false);
					});
			}, []);

			useEffect(function () {
				refresh();
			}, [refresh]);

			var openReport = useCallback(function (key, dir) {
				if (open && open.key === key) { setOpen(null); return; }
				setOpen({ key: key, text: null });
				fetch(REPORT_URL + encodeURIComponent(dir), { headers: authHeaders() })
					.then(function (r) {
						if (r.status === 403) throw new Error("未授权（令牌缺失或失效）— 请强制刷新页面");
						if (!r.ok) throw new Error("HTTP " + r.status);
						return r.text();
					})
					.then(function (text) {
						setOpen({ key: key, text: text });
					})
					.catch(function (e) {
						var msg = e && e.message ? String(e.message) : String(e);
						if (/404/.test(msg)) msg = "报告尚未生成（审计进行中或报告缺失）";
						setOpen({ key: key, text: "(加载报告失败: " + msg + ")" });
					});
			}, [open]);

			var copyReport = useCallback(function () {
				if (!open || open.text === null) return;
				var split = splitReport(open.text);
				var zhOk = split.zh !== null && split.zh.trim() !== "" && hasCjk(split.zh);
				var text = lang === "zh" && zhOk ? split.zh : split.en;
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
						setError("触发审计失败: " + String(e && e.message ? e.message : e));
					});
			}, [refresh]);

			var clearRecords = useCallback(function (keys, all) {
				var label = all ? "全部插件" : "该插件";
				if (!window.confirm("确定清除" + label + "的审计记录？其报告文件与历史将一并删除，不可恢复。")) return;
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
						setError("清除记录失败: " + String(e && e.message ? e.message : e));
					});
			}, [refresh]);

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
				{ label: "已发现插件", value: total, color: theme.label },
				{ label: "已完成", value: counts.completed, color: theme.ok },
				{ label: "失败", value: counts.failed, color: theme.danger },
				{ label: "审计中", value: counts.running, color: theme.warn },
				{ label: "未审计", value: counts.never, color: theme.muted },
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
					}, isOpen ? "收起报告" : "查看报告"));
				}
				actions.push(react.createElement("button", {
					key: "rescan",
					style: styles.buttonPrimary,
					disabled: busy === e.key || st === "running",
					onClick: function () { triggerScan(e.key); },
				}, busy === e.key || st === "running" ? "审计中…" : "重新审计"));
				actions.push(react.createElement("button", {
					key: "clear",
					style: styles.buttonDanger,
					onMouseEnter: function (ev) { ev.currentTarget.style.background = theme.bgModule; },
					onMouseLeave: function (ev) { ev.currentTarget.style.background = "transparent"; },
					onClick: function () { clearRecords([e.key], false); },
				}, "清除记录"));

				var meta = [];
				meta.push("最近审计: " + fmtTime(p.lastScanAt));
				if (p.kind === "package" && p.version) meta.push("v" + p.version);

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
							statusLabel(st))),
					react.createElement("div", { style: styles.metaLine },
						react.createElement("span", null, KIND_LABEL[p.kind] || p.kind),
						meta.map(function (m, i) { return react.createElement("span", { key: i }, m); })),
					p.note ? react.createElement("p", { style: styles.note }, p.note) : null,
					react.createElement("div", { style: styles.actions }, actions),
					open !== null && open.key === e.key
						? (function () {
							var split = open.text === null ? null : splitReport(open.text);
							var zhAvailable = split !== null && split.zh !== null && split.zh.trim() !== "" && hasCjk(split.zh);
							var showZh = lang === "zh" && zhAvailable;
							var display = open.text === null ? null : (showZh ? split.zh : split.en);
							return react.createElement("div", { style: Object.assign({}, styles.report, { marginTop: "10px" }) },
								react.createElement("div", { style: styles.reportHead },
									react.createElement("div", { style: { display: "flex", gap: "4px", alignItems: "center" } },
										react.createElement("p", { style: Object.assign({}, styles.reportTitle, { marginRight: "4px" }) }, "审计报告"),
										react.createElement("button", { style: lang === "en" ? styles.langActive : styles.langIdle, onClick: function () { setLang("en"); } }, "English"),
										react.createElement("button", { style: lang === "zh" ? styles.langActive : styles.langIdle, onClick: function () { setLang("zh"); } }, "中文")),
									react.createElement("div", { style: { display: "flex", gap: "8px", alignItems: "center" } },
										react.createElement("button", {
											style: styles.buttonGhost,
											onClick: copyReport,
											disabled: open.text === null,
											"aria-label": "复制报告",
										}, copied ? "已复制" : "复制"),
										react.createElement("button", { style: styles.buttonGhost, onClick: function () { setOpen(null); } }, "关闭"))),
								open.text === null
									? react.createElement("div", { style: { padding: "14px", color: theme.label3, fontSize: "12px" } }, "加载中…")
									: react.createElement("div", null,
										lang === "zh" && !zhAvailable
											? react.createElement("p", { style: { margin: "8px 14px 0", fontSize: "11.5px", color: theme.warn } },
												"中文版未生成（该报告仅含英文）— 以下显示英文原文")
											: null,
										react.createElement("div", { className: "dshsec-body", style: styles.reportBody, dangerouslySetInnerHTML: { __html: mdHtml(display) } })));
						})()
						: null);
			});

			var body = null;
			if (loading && !status) {
				body = react.createElement("div", { style: styles.empty }, "加载审计状态中…");
			} else if (error) {
				body = react.createElement("div", { style: styles.error }, error);
			} else if (entries.length === 0) {
				body = react.createElement("div", { style: styles.empty },
					"（暂无审计记录；重启后门禁会自动审计已安装的预设与插件）");
			} else {
				body = react.createElement("div", { style: styles.list }, cardNodes);
			}

			var allKeys = entries.map(function (e) { return e.key; });

			return react.createElement("div", { style: styles.wrap },
				react.createElement("style", null, MD_CSS),
				react.createElement("div", { style: styles.head },
					react.createElement("div", null,
						react.createElement("h2", { style: styles.title }, "🛡️ 安全审计",
							react.createElement("span", { style: { fontSize: "12px", color: theme.label3, fontWeight: 400 } }, "dsh-code-security")),
						react.createElement("p", { style: styles.subtitle },
							"新插件安装后自动用本会话模型审计；审计会把插件源码发送给本会话的模型服务商，已审计且未变化的插件不会重复审计。")),
					react.createElement("div", { style: styles.spacer }),
					react.createElement("button", { style: styles.buttonDanger, onClick: function () { clearRecords([], true); }, disabled: allKeys.length === 0 },
						"清除全部"),
					react.createElement("button", { style: styles.buttonGhost, onClick: function () { if (allKeys.length > 0) triggerScan(allKeys); }, disabled: busy === "__all__" },
						busy === "__all__" ? "审计中…" : "审计全部"),
					react.createElement("button", { style: styles.button, onClick: refresh },
						loading ? "刷新中…" : "刷新")),
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
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "dsh-security",
				order: 25,
				label: () => "安全审计",
			}, CodexSecuritySection));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
