// openai-code-security-gate — browser client half.
//
// Registered as a web `dsh.client` package (`exports["./client"]`) and loaded
// through the shell's module table. Mounts a "安全审计" settings section that
// shows per-plugin audit status from the gate's HTTP endpoints and lets the
// user open reports or re-trigger audits.
//
// Hand-written bundle in the shell's factory format: plain CJS factory, no
// bundler, no JSX.
window.__ModuleLoader__.load({
	id: "openai-code-security-gate",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		var react = require("react");

		const inject = ["slots"];

		const STATUS_URL = "/codex-security/status.json";
		const REPORT_URL = "/codex-security/report?id=";
		const SCAN_URL = "/codex-security/scan";

		const styles = {
			wrap: { padding: "16px 0" },
			head: { display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" },
			title: { margin: 0, fontSize: "15px", fontWeight: 600 },
			button: {
				font: "inherit",
				border: "1px solid var(--dsw-alias-border-l2, #ccc)",
				background: "var(--dsw-alias-bg-layer-3, transparent)",
				color: "var(--dsw-alias-label-primary, inherit)",
				borderRadius: "6px",
				padding: "4px 10px",
				fontSize: "12px",
				cursor: "pointer",
			},
			table: { width: "100%", borderCollapse: "collapse", fontSize: "12px" },
			th: { textAlign: "left", padding: "6px 8px", color: "var(--dsw-alias-label-tertiary, #888)", fontWeight: 500 },
			td: { padding: "6px 8px", borderTop: "1px solid var(--dsw-alias-border-l2, #eee)", verticalAlign: "top" },
			badge: {
				display: "inline-block",
				borderRadius: "999px",
				padding: "1px 8px",
				fontSize: "11px",
				fontWeight: 500,
				color: "#fff",
			},
			badgeCompleted: { background: "#2f9e44" },
			badgeFailed: { background: "#e03131" },
			badgeRunning: { background: "#f08c00" },
			badgeNever: { background: "#868e96" },
			note: { margin: 0, color: "var(--dsw-alias-label-tertiary, #888)", fontSize: "11px", maxWidth: "480px", whiteSpace: "pre-wrap" },
			pre: {
				background: "var(--dsw-alias-bg-module-platform, #f6f6f6)",
				borderRadius: "8px",
				padding: "12px",
				fontSize: "12px",
				lineHeight: 1.55,
				whiteSpace: "pre-wrap",
				maxHeight: "60vh",
				overflow: "auto",
			},
			hint: { color: "var(--dsw-alias-label-tertiary, #888)", fontSize: "12px", margin: "8px 0 0" },
		};

		function statusColor(status) {
			if (status === "completed") return styles.badgeCompleted;
			if (status === "failed") return styles.badgeFailed;
			if (status === "running") return styles.badgeRunning;
			return styles.badgeNever;
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

			var triggerScan = useCallback(function (key) {
				setBusy(key);
				fetch(SCAN_URL, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ plugins: [key] }),
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

			var rows = [];
			if (status && status.plugins) {
				for (var key in status.plugins) {
					var p = status.plugins[key];
					rows.push(
						react.createElement("tr", { key: key },
							react.createElement("td", null, p.id, react.createElement("div", { style: { color: "var(--dsw-alias-label-tertiary, #888)", fontSize: "11px" } }, key)),
							react.createElement("td", null, p.kind),
							react.createElement("td", null,
								react.createElement("span", { style: Object.assign({}, styles.badge, statusColor(p.status)) }, p.status)),
							react.createElement("td", null, p.lastScanAt ? p.lastScanAt.replace("T", " ").slice(0, 19) : "—"),
							react.createElement("td", null,
								p.reportDir ? react.createElement("button", { style: styles.button, onClick: function () { openReport(p.reportDir); } }, "查看报告") : null,
								" ",
								react.createElement("button", { style: styles.button, disabled: busy === key, onClick: function () { triggerScan(key); } }, busy === key ? "审计中…" : "重新审计")),
							react.createElement("td", null, p.note ? react.createElement("p", { style: styles.note }, p.note) : null)
						)
					);
				}
			}

			return react.createElement("div", { style: styles.wrap },
				react.createElement("div", { style: styles.head },
					react.createElement("h2", { style: styles.title }, "安全审计（codex-security）"),
					react.createElement("button", { style: styles.button, onClick: refresh }, loading ? "刷新中…" : "刷新")),
				react.createElement("p", { style: styles.hint },
					"新插件安装后由门禁自动用本会话模型审计；状态每 60 秒轮询。已审计且未变化的插件不会重复审计。"),
				error ? react.createElement("p", { style: Object.assign({}, styles.note, { color: "var(--dsw-alias-label-error, #e03131)" }) }, error) : null,
				react.createElement("table", { style: styles.table },
					react.createElement("thead", null,
						react.createElement("tr", null,
							react.createElement("th", { style: styles.th }, "插件"),
							react.createElement("th", { style: styles.th }, "类型"),
							react.createElement("th", { style: styles.th }, "状态"),
							react.createElement("th", { style: styles.th }, "最近审计"),
							react.createElement("th", { style: styles.th }, "操作"),
							react.createElement("th", { style: styles.th }, "备注"))),
					react.createElement("tbody", null,
						rows.length > 0 ? rows : react.createElement("tr", null,
							react.createElement("td", { colSpan: 6 }, loading ? "加载中…" : "（暂无审计记录；重启后门禁会自动审计已安装插件）")))),
				report !== null
					? react.createElement("div", { style: { marginTop: "12px" } },
						react.createElement("pre", { style: styles.pre }, report),
						react.createElement("button", { style: Object.assign({}, styles.button, { marginTop: "8px" }), onClick: function () { setReport(null); } }, "关闭报告"))
					: null
			);
		}

		function apply(ctx) {
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "codex-security",
				order: 25,
				label: () => "安全审计",
			}, CodexSecuritySection));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
