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
	id: "dsh-security-gate",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		var react = require("react");

		const inject = ["slots"];

		const STATUS_URL = "/dsh-security/status.json";
		const REPORT_URL = "/dsh-security/report?id=";
		const SCAN_URL = "/dsh-security/scan";

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
			pre: {
				margin: 0,
				padding: "14px",
				fontSize: "12px",
				lineHeight: 1.6,
				whiteSpace: "pre-wrap",
				wordBreak: "break-word",
				maxHeight: "55vh",
				overflow: "auto",
				color: theme.label,
				fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
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
			var useStateReport = useState(null);
			var report = useStateReport[0];
			var setReport = useStateReport[1];
			var useStateBusy = useState(null);
			var busy = useStateBusy[0];
			var setBusy = useStateBusy[1];

			var refresh = useCallback(function () {
				setLoading(true);
				setError(null);
				fetch(STATUS_URL)
					.then(function (r) {
						var ct = "";
						if (r.headers && r.headers.get) ct = String(r.headers.get("content-type") || "");
						if (ct.indexOf("json") < 0) throw new Error("门禁端点未响应（返回 HTML，疑似门禁未挂载）");
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

			var openReport = useCallback(function (dir) {
				setReport(null);
				fetch(REPORT_URL + encodeURIComponent(dir))
					.then(function (r) {
						if (!r.ok) throw new Error("HTTP " + r.status);
						return r.text();
					})
					.then(function (text) {
						setReport(text);
					})
					.catch(function (e) {
						setReport("(加载报告失败: " + String(e && e.message ? e.message : e) + ")");
					});
			}, []);

			var triggerScan = useCallback(function (keys) {
				var list = Array.isArray(keys) ? keys : [keys];
				var marker = list.length === 1 ? list[0] : "__all__";
				setBusy(marker);
				fetch(SCAN_URL, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ plugins: list }),
				})
					.then(function (r) { return r.json(); })
					.then(function () {
						setBusy(null);
						setTimeout(refresh, 3000);
					})
					.catch(function (e) {
						setBusy(null);
						setError("触发审计失败: " + String(e && e.message ? e.message : e));
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
				if (p.reportDir) {
					actions.push(react.createElement("button", {
						key: "view",
						style: styles.button,
						onMouseEnter: function (ev) { ev.currentTarget.style.background = styles.buttonHover.background; },
						onMouseLeave: function (ev) { ev.currentTarget.style.background = styles.button.background; },
						onClick: function () { openReport(p.reportDir); },
					}, "查看报告"));
				}
				actions.push(react.createElement("button", {
					key: "rescan",
					style: styles.buttonPrimary,
					disabled: busy === e.key,
					onClick: function () { triggerScan(e.key); },
				}, busy === e.key ? "审计中…" : "重新审计"));

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
					react.createElement("div", { style: styles.actions }, actions));
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
				react.createElement("div", { style: styles.head },
					react.createElement("div", null,
						react.createElement("h2", { style: styles.title }, "🛡️ 安全审计",
							react.createElement("span", { style: { fontSize: "12px", color: theme.label3, fontWeight: 400 } }, "dsh-code-security")),
						react.createElement("p", { style: styles.subtitle },
							"新插件安装后自动用本会话模型审计；已审计且未变化的插件不会重复审计。")),
					react.createElement("div", { style: styles.spacer }),
					react.createElement("button", { style: styles.buttonGhost, onClick: function () { if (allKeys.length > 0) triggerScan(allKeys); }, disabled: busy === "__all__" },
						busy === "__all__" ? "审计中…" : "审计全部"),
					react.createElement("button", { style: styles.button, onClick: refresh },
						loading ? "刷新中…" : "刷新")),
				react.createElement("div", { style: styles.stats }, statNodes),
				body,
				report !== null
					? react.createElement("div", { style: styles.report },
						react.createElement("div", { style: styles.reportHead },
							react.createElement("p", { style: styles.reportTitle }, "审计报告"),
							react.createElement("button", { style: styles.buttonGhost, onClick: function () { setReport(null); } }, "关闭")),
						react.createElement("pre", { style: styles.pre }, report))
					: null,
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
