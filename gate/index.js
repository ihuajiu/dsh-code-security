// dsh-security-gate
//
// DSH host plugin: a security gate for plugin installation.
//
//   - Watches plugin-install surfaces and auto-audits newly installed plugins
//     with the harness's own model (llm engine, no external authentication):
//       1. user agent presets under <dshHome>/.agent-presets
//       2. profile plugin packages (package.json dependencies + bundles and
//          top-level node_modules) under <dshHome>/profiles/*
//   - Results, state, and a per-plugin summary are persisted under
//     <dshHome>/dsh-security/.
//   - Registers two global model tools: `dsh_security_scan_plugins` (batch
//     audit of specified plugins) and `dsh_security_scan_status`.
//
// Zero-dependency by design (Node builtins only) so the module loads from any
// profile's node_modules without peer-package resolution concerns. It consumes
// host services defensively via ctx.get() and never throws from apply(), so a
// composition that includes it degrades gracefully instead of failing to mount.
//
// Install: `dsh plugin --profile <name> add <this directory>` — the
// `dsh.bundle.patch` declaration makes `dsh plugin add` append this package
// (`@dsh.so/dsh-security-gate`) to the profile's bundle layer automatically;
// no manual cordis.patch.yml row is needed.
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, statSync, realpathSync, rmSync } from 'node:fs';
import { join, dirname, relative, basename, resolve as resolvePath, sep as pathSep } from 'node:path';
import { homedir } from 'node:os';

export const name = 'dsh-security-gate';

/** Attribution footer appended to every generated audit report. */
const REPORT_FOOTER =
  '\n\n---\n\n' +
  '*本报告由 dsh-code-security（安全审计门禁）自动生成，仅供参考；结论请结合人工复核。*\n\n' +
  '*Powered by [dsh.so](https://dsh.so) · © 2026 dsh.so · Apache-2.0*\n';

/**
 * Canonicalize a path through symlinks: realpath the deepest EXISTING
 * ancestor, then re-append the missing suffix. Falls back to the lexical path
 * when nothing exists or a symlink loop is detected. Used so path containment
 * cannot be bypassed by a symlink inside a plugin root pointing outside it,
 * and so harvests never escape the plugin directory.
 */
function canonicalizePath(p) {
  let probe = p;
  const missing = [];
  for (;;) {
    try {
      return realpathSync(probe) + (missing.length > 0 ? pathSep + missing.reverse().join(pathSep) : '');
    } catch {
      const parent = dirname(probe);
      if (parent === probe) return p;
      missing.push(basename(probe));
      probe = parent;
    }
  }
}

/** Basename patterns of files that must never leave the host (F3). */
const SECRET_FILE_PATTERNS = [
  '.env', '.env.*', '.npmrc', '.pypirc', '.netrc',
  '*.pem', '*.key', '*.p12', '*.pfx', '*.keystore', '*.jks',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
  'credentials.json', 'credentials.yml', 'credentials.yaml',
  'secrets.yml', 'secrets.yaml', '*.secret', '*.credentials',
  'service-account*.json', 'client-secret*.json', 'oauth*.json',
];
/** Match one basename against secret patterns (mini-glob, `*` wildcard). */
function matchesSecretName(name, patterns = SECRET_FILE_PATTERNS) {
  const n = String(name);
  for (const pat of patterns) {
    const re = new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
    if (re.test(n)) return true;
  }
  return false;
}

/**
 * Mask common inline secret values in harvested text before it is sent to the
 * model provider (F3): cloud keys, private key blocks, and generic
 * `password/secret/token/api_key = value` assignments.
 */
function redactSecrets(text) {
  return String(text)
    .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED:AWS_KEY]')
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED:API_KEY]')
    .replace(/\bghp_[A-Za-z0-9]{36}\b/g, '[REDACTED:GITHUB_TOKEN]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[REDACTED:GITHUB_PAT]')
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED:SLACK_TOKEN]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED:PRIVATE_KEY]')
    .replace(/(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{8,}/gi, '$1: [REDACTED]');
}

export function apply(ctx, config = {}) {
  const dshHome = config.dshHome ?? join(homedir(), '.dsh');
  const cfg = {
    autoScan: config.autoScan !== false,
    scanOnBoot: config.scanOnBoot !== false,
    scanSystemPresets: config.scanSystemPresets === true,
    intervalMs: config.intervalMs ?? 60000,
    ignorePrefixes: config.ignorePrefixes ?? ['@deepseek-ai/'],
    ignoreIds: config.ignoreIds ?? [],
    // Scan engine: 'llm' runs the audit on the harness's own model route (no
    // external auth, offline source review); 'cli' shells out to the
    // @openai/codex-security CLI (requires its own authentication).
    engine: config.engine ?? 'llm',
    cliCommand: config.cliCommand ?? 'npx --yes @openai/codex-security',
    // Model route override for the llm engine; defaults to the deployment's
    // agent default selection (the same route this session uses).
    provider: config.provider,
    model: config.model,
    stateDir: config.stateDir ?? join(dshHome, 'dsh-security'),
    scanTimeoutMs: config.scanTimeoutMs ?? 900000,
    maxParallel: config.maxParallel ?? 2,
    profileDirs: config.profileDirs,
    // Path-type scan targets (dsh_security_scan_plugins / POST scan) must
    // ALWAYS resolve inside a discovered plugin root — no escape hatch — so
    // arbitrary files can never be harvested and shipped to the model provider.
    sandboxMode: config.sandboxMode, // undefined = executor default (cli engine only)
    maxHarvestChars: config.maxHarvestChars ?? 400000,
    maxFileBytes: config.maxFileBytes ?? 65536,
    // Secret hardening for the llm engine: never harvest secret-bearing files
    // and redact inline secret values before the content reaches the provider.
    harvestExcludePatterns: config.harvestExcludePatterns ?? SECRET_FILE_PATTERNS,
    redactSecrets: config.redactSecrets !== false,
    // Rate limit for unauthenticated localhost HTTP triggers (POST /scan).
    scanRateLimit: config.scanRateLimit ?? 10,
    scanRateWindowMs: config.scanRateWindowMs ?? 10000,
    maxOutputTokens: config.maxOutputTokens ?? 32000,
    llmTimeoutMs: config.llmTimeoutMs ?? 240000,
    tickWatchdogMs: config.tickWatchdogMs ?? 180000,
    // DeepSeek reasoning models burn the output budget on reasoning and then
    // stop without a final answer; for one-shot bounded audits we disable
    // thinking so the whole budget goes to the report text.
    reasoningEffort: config.reasoningEffort ?? 'off',
  };
  // Validate the CLI engine command (F4): it is admin config, but reject shell
  // metacharacters so a misconfigured value cannot become an arbitrary command.
  if (typeof cfg.cliCommand === 'string' && /[;&|`$<>()%^]/.test(cfg.cliCommand)) {
    console.error(
      '[dsh-security-gate] cliCommand contains shell metacharacters (' + JSON.stringify(cfg.cliCommand) +
        ') — refusing it and falling back to the default.'
    );
    cfg.cliCommand = 'npx --yes @openai/codex-security';
  }
  mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 });

  const statePath = join(cfg.stateDir, 'state.json');
  const summaryPath = join(cfg.stateDir, 'summary.json');

  // Ensure the state dir + a summary exist from the moment the gate mounts,
  // so the settings panel and status endpoint always have a surface even
  // before the first poll tick completes.
  try {
    if (!existsSync(statePath)) saveState(loadState());
    if (!existsSync(summaryPath)) writeSummary(loadState());
  } catch {
    /* best-effort */
  }

  // ── tiny helpers ──────────────────────────────────────────────────────────
  // Deliberately function declarations (hoisted): the boot warm-up above calls
  // writeSummary/saveState before these lines execute, and a const arrow would
  // sit in the temporal dead zone there ("Cannot access 'nowIso' before
  // initialization" on first run, when summary.json does not exist yet).
  /** Shell dialect of the host executor: bash on POSIX, pwsh on win32. */
  function shellDialect() {
    return typeof process !== 'undefined' && process.platform === 'win32' ? 'pwsh' : 'bash';
  }
  /**
   * Quote one value as a literal shell word so paths can never become shell
   * syntax. Single quotes make backticks, `$(...)`, `$VAR`, globs, `;`, `|`,
   * `&`, and quotes inert on both executors:
   *  - bash (`bash -c`): embed `'` as `'\''` (POSIX-correct).
   *  - pwsh (`pwsh -Command`): embed `'` by doubling (`''`).
   */
  function quote(value) {
    const s = String(value);
    if (shellDialect() === 'pwsh') return `'${s.replace(/'/g, "''")}'`;
    return `'${s.replace(/'/g, "'\\''")}'`;
  }
  function safeKey(key) {
    return key.replace(/[^a-zA-Z0-9._-]/g, '_');
  }
  function nowIso() {
    return new Date().toISOString();
  }
  function tsForDir() {
    return nowIso().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
  }

  function loadState() {
    try {
      if (!existsSync(statePath)) return { version: 1, plugins: {} };
      return JSON.parse(readFileSync(statePath, 'utf8'));
    } catch {
      return { version: 1, plugins: {} };
    }
  }
  function saveState(state) {
    try {
      writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
    } catch (error) {
      console.error('[dsh-security-gate] could not write state: ' + String(error));
    }
  }
  function writeSummary(state) {
    try {
      const plugins = {};
      for (const [key, entry] of Object.entries(state.plugins)) {
        plugins[key] = {
          id: entry.id,
          kind: entry.kind,
          root: entry.root,
          version: entry.version,
          status: entry.lastScan ? entry.lastScan.status : 'never',
          lastScanAt: entry.lastScan ? entry.lastScan.at : null,
          reportDir: entry.lastScan ? entry.lastScan.reportDir : null,
        };
      }
      writeFileSync(summaryPath, JSON.stringify({ updatedAt: nowIso(), plugins }, null, 2), { mode: 0o600 });
    } catch (error) {
      console.error('[dsh-security-gate] could not write summary: ' + String(error));
    }
  }

  function readVersion(root) {
    try {
      const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
      return typeof pkg.version === 'string' ? pkg.version : undefined;
    } catch {
      return undefined;
    }
  }

  function resolveProfileDirs() {
    if (Array.isArray(cfg.profileDirs) && cfg.profileDirs.length > 0) return cfg.profileDirs;
    const profilesDir = join(dshHome, 'profiles');
    if (!existsSync(profilesDir)) return [];
    return readdirSync(profilesDir)
      .filter((n) => !n.startsWith('.'))
      .map((n) => join(profilesDir, n))
      .filter((dir) => existsSync(join(dir, 'package.json')));
  }

  function resolvePackageRoot(profileDir, name) {
    try {
      const req = createRequire(join(profileDir, 'package.json'));
      return dirname(req.resolve(name + '/package.json'));
    } catch {
      const scoped = name.startsWith('@')
        ? join(profileDir, 'node_modules', ...name.split('/'))
        : join(profileDir, 'node_modules', name);
      return existsSync(join(scoped, 'package.json')) ? scoped : undefined;
    }
  }

  // ── discovery of installed plugins ────────────────────────────────────────
  async function discoverPlugins() {
    const found = new Map();
    const add = (info) => {
      const existing = found.get(info.key);
      if (!existing || (existing.root !== info.root && info.kind === 'preset')) found.set(info.key, info);
    };

    // 1. user agent presets (system presets skipped unless scanSystemPresets)
    const presets = ctx.get('agentPresets');
    if (presets !== undefined) {
      try {
        const list = await presets.list();
        for (const p of list) {
          if (p.trust === 'system' && !cfg.scanSystemPresets) continue;
          add({
            key: 'preset:' + p.id,
            kind: 'preset',
            id: p.id,
            root: dirname(p.path),
            broken: p.broken === true,
          });
        }
      } catch (error) {
        console.error('[dsh-security-gate] agentPresets.list failed: ' + String(error));
      }
    }

    // 2. profile plugin packages
    for (const profileDir of resolveProfileDirs()) {
      const pkgPath = join(profileDir, 'package.json');
      if (existsSync(pkgPath)) {
        try {
          const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
          const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
          for (const depName of Object.keys(deps)) {
            const root = resolvePackageRoot(profileDir, depName);
            if (root) add({ key: 'package:' + depName, kind: 'package', id: depName, root, version: readVersion(root) });
          }
          const bundles = (pkg.dsh && pkg.dsh.profile && pkg.dsh.profile.bundles) || [];
          for (const bundle of bundles) {
            if (typeof bundle !== 'string') continue;
            const root = resolvePackageRoot(profileDir, bundle);
            if (root) add({ key: 'package:' + bundle, kind: 'package', id: bundle, root, version: readVersion(root) });
          }
        } catch (error) {
          console.error('[dsh-security-gate] could not read ' + pkgPath + ': ' + String(error));
        }
      }
      const nm = join(profileDir, 'node_modules');
      if (existsSync(nm)) {
        for (const entryName of readdirSync(nm)) {
          if (entryName.startsWith('.')) continue;
          const root = join(nm, entryName);
          if (!existsSync(join(root, 'package.json'))) continue;
          // Only treat top-level packages as plugins when they look like one:
          // a `dsh` profile/bundle marker, a cordis.yml, or a plugin patch file.
          // This keeps transitive dependencies (e.g. commander) out of the scan.
          let pkg;
          try {
            pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
          } catch {
            continue;
          }
          const looksLikePlugin =
            pkg.dsh !== undefined ||
            existsSync(join(root, 'cordis.yml')) ||
            existsSync(join(root, 'cordis.patch.yml'));
          if (!looksLikePlugin) continue;
          add({ key: 'package:' + entryName, kind: 'package', id: entryName, root, version: readVersion(root) });
        }
      }
    }
    return found;
  }

  function isIgnored(info) {
    if (cfg.ignoreIds.includes(info.id)) return true;
    return cfg.ignorePrefixes.some((prefix) => info.id.startsWith(prefix));
  }

  // ── scanning ──────────────────────────────────────────────────────────────
  /** Normalize one shell stream (object `{text, truncated, spillPath}` or string). */
  function streamText(stream) {
    if (typeof stream === 'string') return stream;
    if (stream && typeof stream === 'object') {
      const text = typeof stream.text === 'string' ? stream.text : '';
      if (stream.truncated) {
        return text + '\n[output truncated; full output: ' + (stream.spillPath ?? '(unavailable)') + ']';
      }
      return text;
    }
    return '';
  }

  async function runScan(info, { force = false, timeoutMs, signal } = {}) {
    const state = loadState();
    const entry = state.plugins[info.key] ?? { key: info.key, kind: info.kind, id: info.id, root: info.root, version: info.version, firstSeenAt: nowIso(), scans: [], lastScan: null };
    state.plugins[info.key] = entry;
    if (!force && entry.lastScan && entry.lastScan.status === 'running') {
      return { key: info.key, status: 'running', reportDir: entry.lastScan.reportDir, note: 'already running' };
    }
    const scan = { at: nowIso(), status: 'running', reportDir: null };
    entry.scans.push(scan);
    entry.lastScan = scan;
    saveState(state);

    const reportDir = join(cfg.stateDir, 'reports', safeKey(info.key) + '_' + tsForDir());
    try {
      mkdirSync(reportDir, { recursive: true, mode: 0o700 });
    } catch {
      /* report dir is best-effort */
    }
    scan.reportDir = reportDir;
    saveState(state);

    if (cfg.engine === 'cli') {
      await runScanCli(info, scan, state, reportDir, { timeoutMs, signal });
    } else {
      await runScanLlm(info, scan, state, reportDir, { signal });
    }
    saveState(state);
    writeSummary(state);
    console.log('[dsh-security-gate] scan ' + info.key + ' -> ' + scan.status + (scan.reportDir ? ' @ ' + scan.reportDir : ''));
    return { key: info.key, status: scan.status, reportDir: scan.reportDir, note: scan.note };
  }

  /** CLI engine: shell out to the @openai/codex-security CLI (requires its own auth). */
  async function runScanCli(info, scan, state, reportDir, { timeoutMs, signal }) {
    const shell = ctx.get('shell');
    if (shell === undefined) {
      scan.status = 'failed';
      scan.note = 'shell service unavailable';
      return;
    }
    const command = [cfg.cliCommand, 'scan', quote(info.root), '--output-dir', quote(reportDir)].join(' ');
    const request = { command, workdir: info.root, timeoutMs: timeoutMs ?? cfg.scanTimeoutMs };
    if (cfg.sandboxMode) request.sandboxPolicy = { mode: cfg.sandboxMode };
    let output = '';
    try {
      const result = await shell.run(shell.resolve({ ...request, ...(signal !== undefined ? { signal } : {}) }));
      scan.exitCode = result.exitCode ?? null;
      scan.timedOut = result.timedOut === true;
      const outText = streamText(result.stdout);
      const errText = streamText(result.stderr);
      output = outText;
      if (errText.length > 0) {
        output += output.length > 0 ? '\n[stderr]\n' + errText : '[stderr]\n' + errText;
      }
      if (result.sandbox && result.sandbox.denied) {
        scan.sandboxDenied = true;
        scan.note = 'sandbox denied the scan under ' + result.sandbox.mode + ' mode';
      }
      if (result.sandbox && result.sandbox.runnerFailed) {
        scan.note = 'sandbox runner failed: the command did not run';
      }
      scan.status = scan.exitCode === 0 ? 'completed' : 'failed';
      if (scan.sandboxDenied) scan.status = 'failed';
      if (scan.note === undefined && output.length > 0) scan.note = output.slice(0, 2000);
    } catch (error) {
      scan.status = 'failed';
      scan.note = String(error && error.message ? error.message : error);
    }
    try {
      writeFileSync(join(reportDir, 'runner.log'), 'command: ' + command + '\n\n' + output, { mode: 0o600 });
    } catch {
      /* best-effort */
    }
  }

  /** LLM engine: harvest the plugin's source and audit it with the harness's own model route. */
  async function runScanLlm(info, scan, state, reportDir, { signal }) {
    const llm = ctx.get('llm');
    if (llm === undefined) {
      scan.status = 'failed';
      scan.note = 'llm service unavailable';
      return;
    }
    const selection = ctx.get('agentDefaultModel')?.currentSelection?.() ?? {};
    const provider = cfg.provider ?? selection.provider ?? 'deepseek-official';
    const model = cfg.model ?? selection.model ?? 'deepseek-v4-flash';
    const harvested = harvestFiles(info.root);
    const system =
      'You are a meticulous application security auditor. Analyze only the provided source code ' +
      'and report findings that are directly supported by the code, with exact file:line evidence. ' +
      'Be precise and concise. Do not invent attack chains the code does not support.';
    const user =
      'Perform a static security audit of the plugin at: ' + info.root + '\n' +
      'Below is a harvested view of its source files (paths relative to the plugin root; ' +
      'oversized/omitted files are marked).\n' +
      'Follow this self-contained baseline audit only:\n' +
      '- Build a practical threat model from the code: what the plugin does, its entry points, ' +
      'trust boundaries, and sensitive operations (filesystem, network, command execution, ' +
      'authentication, secrets, deserialization, template expansion, SQL, etc.).\n' +
      '- Find every REAL security vulnerability supported by specific source evidence. ' +
      'Distinguish real vulnerabilities from correctness bugs or false positives.\n' +
      '- For each finding record: severity (critical/high/medium/low), affected file:line, ' +
      'the attacker and entry point, reachability, the broken control, concrete impact, ' +
      'and a practical remediation.\n' +
      '- Missing deployment evidence lowers confidence; it does not by itself defeat a ' +
      'source-backed vulnerability.\n\n' +
      'Output a markdown report. START with a "Summary" section containing a ' +
      'markdown table counting findings by severity (rows: 严重/Critical, 高/High, ' +
      '中/Medium, 低/Low, 合计/Total, with counts) — the summary comes FIRST so ' +
      'readers see the verdict immediately. Then a concise Threat Model section; ' +
      'a Findings section with one subsection per finding (title, Location, ' +
      'Description, Attack path, Impact, Remediation); and a short conclusion. ' +
      'If there are no findings, state "No findings" with the evidence-grounded ' +
      'rationale.\n\n' +
      // Bilingual reports: complete English report first, then a complete
      // Chinese translation, separated by a marker the panel splits on.
      'Language: write the ENTIRE report in ENGLISH first — it must be complete and standalone. ' +
      'Then append a complete CHINESE translation of the same report (same structure and headings, ' +
      'translated, not summarized). Separate the two parts with a single line containing exactly ' +
      'this marker: <!-- REPORT_ZH -->\n\n' +
      harvested;
    let report = '';
    let reasoning = '';
    let finishText = 'unknown';
    let usageText = '';
    const ctrl = new AbortController();
    const abortTimer = setTimeout(() => ctrl.abort('dsh-security-gate llm timeout'), cfg.llmTimeoutMs);
    try {
      const callSignal = signal !== undefined && typeof AbortSignal.any === 'function'
        ? AbortSignal.any([signal, ctrl.signal])
        : ctrl.signal;
      const chunks = llm.stream({
        provider,
        model,
        system,
        reasoningEffort: cfg.reasoningEffort,
        // content MUST be a ContentBlock array — the adapters call message.content.filter/map
        messages: [{ role: 'user', content: [{ type: 'text', text: user }] }],
        maxTokens: cfg.maxOutputTokens ?? 8000,
        signal: callSignal,
      });
      for await (const chunk of chunks) {
        if (!chunk || typeof chunk !== 'object') continue;
        if (chunk.type === 'text-delta' && typeof chunk.text === 'string') report += chunk.text;
        else if (chunk.type === 'reasoning-delta' && typeof chunk.text === 'string') reasoning += chunk.text;
        else if (chunk.type === 'finish') {
          const r = chunk.reason;
          finishText = r && typeof r === 'object'
            ? r.kind + (r.failure ? ' [' + String(r.failure.code ?? '') + '] ' + String(r.failure.message ?? '') : '')
            : String(r);
        } else if (chunk.type === 'usage') {
          try {
            usageText = JSON.stringify(chunk.usage);
          } catch {
            /* best-effort */
          }
        }
      }
      const hasContent = report.length > 0;
      if (!hasContent && reasoning.length > 0) {
        // model reasoned but produced no final text — surface the reasoning so the report is never empty
        report = '# Security Audit（模型只输出了推理，未给出结论）\n\n<details><summary>模型推理过程</summary>\n\n' + reasoning + '\n\n</details>\n';
      }
      if (!hasContent && reasoning.length === 0) {
        scan.status = 'failed';
        scan.note = 'model returned no content (finish: ' + finishText + (usageText ? ', usage: ' + usageText : '') + ')';
      } else if (finishText.startsWith('error') || finishText.startsWith('aborted')) {
        scan.status = 'failed';
        scan.note = 'model stream failed (finish: ' + finishText + ')' + (usageText ? ', usage: ' + usageText : '');
      } else {
        scan.exitCode = 0;
        scan.status = 'completed';
        scan.note = 'model audit (' + provider + '/' + model + '), harvested ' + harvested.length + ' chars, finish=' + finishText + (usageText ? ', usage: ' + usageText : '');
      }
    } catch (error) {
      scan.status = 'failed';
      scan.note = String(error && error.message ? error.message : error);
    } finally {
      clearTimeout(abortTimer);
    }
    try {
      writeFileSync(join(reportDir, 'report.md'), report + REPORT_FOOTER, { mode: 0o600 });
      writeFileSync(join(reportDir, 'runner.log'), 'engine: llm\nprovider: ' + provider + '\nmodel: ' + model + '\ntarget: ' + info.root + '\nharvested chars: ' + harvested.length + '\nfinish: ' + finishText + (usageText ? '\nusage: ' + usageText : '') + (reasoning.length > 0 ? '\nreasoning chars: ' + reasoning.length : ''), { mode: 0o600 });
    } catch {
      /* best-effort */
    }
  }

  /** Collect a bounded, text-only view of a plugin's source files for the llm engine. */
  function harvestFiles(root) {
    const skipDirs = new Set(['node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '__pycache__', 'coverage', '.dsh', 'bundled']);
    const patterns = cfg.harvestExcludePatterns ?? SECRET_FILE_PATTERNS;
    const out = [];
    let total = 0;
    // Canonicalize the harvest root once: a path-target that is itself a
    // symlink must not pull in files from outside the plugin directory.
    const canonRoot = canonicalizePath(resolvePath(root));
    const keyed = (p) => (typeof process !== 'undefined' && process.platform === 'win32' ? p.toLowerCase() : p);
    const outsideRoot = (full) => {
      let canon;
      try {
        canon = canonicalizePath(full);
      } catch {
        return true;
      }
      const k = keyed(canon);
      const r = keyed(canonRoot);
      return k !== r && !k.startsWith(r + pathSep);
    };
    const walk = (dir) => {
      let entries;
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!skipDirs.has(entry.name) && !entry.name.startsWith('.')) walk(full);
        } else if (entry.isFile() && !entry.name.startsWith('.')) {
          // Never harvest secret-bearing files (F3): .env / *.pem / id_rsa /
          // credentials / secrets / service-account etc. stay on the host.
          if (matchesSecretName(entry.name, patterns)) continue;
          // A file that resolves outside the plugin root (symlinked) is skipped,
          // and the read below uses the CANONICAL path — the check and the read
          // operate on the same resolved target, so swapping a symlink between
          // them cannot redirect the read (F6).
          let canon;
          try {
            canon = canonicalizePath(full);
          } catch {
            continue;
          }
          if (outsideRoot(canon)) continue;
          let st;
          try {
            st = statSync(canon);
          } catch {
            continue;
          }
          if (!st.size || st.size > cfg.maxFileBytes) continue;
          let text;
          try {
            text = readFileSync(canon, 'utf8');
          } catch {
            continue;
          }
          if (text.includes('\u0000')) continue; // binary
          if (cfg.redactSecrets) text = redactSecrets(text);
          const rel = relative(canonRoot, canon) || entry.name;
          if (total + text.length > cfg.maxHarvestChars) {
            out.push('\n[file omitted: ' + rel + ' exceeds harvest budget]');
            continue;
          }
          total += text.length;
          out.push('\n===== ' + rel + ' =====\n' + text);
        }
      }
    };
    walk(canonRoot);
    return out.join('\n');
  }

  // bounded concurrent queue for auto-scans
  const pending = [];
  let running = 0;
  function pump() {
    while (running < cfg.maxParallel && pending.length > 0) {
      const job = pending.shift();
      running += 1;
      job()
        .catch((error) => console.error('[dsh-security-gate] scan job failed: ' + String(error)))
        .finally(() => {
          running -= 1;
          pump();
        });
    }
  }
  function queueScan(info, options = {}) {
    pending.push(() => runScan(info, options));
    pump();
  }

  /** True when the plugin's last scan was reported complete but produced no report.md. */
  function lastScanReportEmpty(entry) {
    const last = entry.lastScan;
    if (!last || !last.reportDir) return false;
    if (last.status === 'failed') return false;
    try {
      const st = statSync(join(last.reportDir, 'report.md'));
      return st.size === 0;
    } catch {
      return true; // report file missing
    }
  }

  // ── the watcher ───────────────────────────────────────────────────────────
  let ticking = false;
  let bootPassDone = false;
  async function tick() {
    if (ticking || !cfg.autoScan) return;
    ticking = true;
    try {
      if (!routesRegistered) registerWebRoutes();
      const found = await discoverPlugins();
      const state = loadState();
      const firstRun = Object.keys(state.plugins).length === 0;
      const rescanFailed = !bootPassDone; // first pass after boot retries previously failed scans
      const toQueue = [];
      for (const info of found.values()) {
        if (isIgnored(info)) continue;
        const entry = state.plugins[info.key];
        if (!entry) {
          state.plugins[info.key] = {
            key: info.key,
            kind: info.kind,
            id: info.id,
            root: info.root,
            version: info.version,
            firstSeenAt: nowIso(),
            scans: [],
            lastScan: null,
          };
          if (firstRun && !cfg.scanOnBoot) continue;
          toQueue.push(info);
        } else if (
          entry.root !== info.root ||
          (info.version !== undefined && entry.version !== info.version) ||
          lastScanReportEmpty(entry) ||
          (rescanFailed && entry.lastScan && entry.lastScan.status === 'failed')
        ) {
          entry.root = info.root;
          entry.version = info.version;
          toQueue.push(info);
        }
      }
      bootPassDone = true;
      // Persist the new/changed entries BEFORE launching scans, so a concurrent
      // runScan's loadState sees them and its saveState cannot be clobbered.
      saveState(state);
      writeSummary(state);
      for (const info of toQueue) queueScan(info);
    } catch (error) {
      console.error('[dsh-security-gate] tick failed: ' + String(error));
    } finally {
      ticking = false;
    }
  }

  // ── resolve user-specified targets for the batch tool ─────────────────────
  async function resolveTargets(ids) {
    const found = await discoverPlugins();
    const out = [];
    const errors = [];
    for (const id of ids) {
      const trimmed = String(id).trim();
      if (trimmed.length === 0) continue;
      // full key form ('preset:x' / 'package:x') — as returned by status endpoints
      if (trimmed.startsWith('preset:') || trimmed.startsWith('package:')) {
        if (found.has(trimmed)) {
          out.push(found.get(trimmed));
          continue;
        }
      }
      // absolute path — must ALWAYS resolve inside a discovered plugin root
      // (canonicalized through symlinks). An unconstrained path target would
      // let any scan harvest arbitrary files outside the plugin tree and ship
      // them to the model provider.
      if (/^[a-zA-Z]:[\\/]/.test(trimmed) || trimmed.startsWith('/')) {
        const resolved = canonicalizePath(resolvePath(trimmed));
        const keyed = (p) => (typeof process !== 'undefined' && process.platform === 'win32' ? p.toLowerCase() : p);
        const inside = [...found.values()].some((info) => {
          const root = keyed(canonicalizePath(resolvePath(info.root)));
          return keyed(resolved) === root || keyed(resolved).startsWith(root + pathSep);
        });
        if (inside) {
          out.push({ key: 'path:' + trimmed, kind: 'path', id: trimmed, root: trimmed });
        } else {
          errors.push(trimmed + ' (path outside all discovered plugin roots; scan a preset/package root only)');
        }
        continue;
      }
      // preset id
      const presetKey = 'preset:' + trimmed;
      if (found.has(presetKey)) {
        out.push(found.get(presetKey));
        continue;
      }
      // explicit preset id even when auto-scan skips it (e.g. system presets)
      const presets = ctx.get('agentPresets');
      if (presets !== undefined) {
        try {
          const list = await presets.list();
          const match = list.find((p) => p.id === trimmed);
          if (match) {
            out.push({ key: 'preset:' + trimmed, kind: 'preset', id: trimmed, root: dirname(match.path) });
            continue;
          }
        } catch {
          /* fall through */
        }
      }
      // package name (any profile)
      const packageKey = 'package:' + trimmed;
      if (found.has(packageKey)) {
        out.push(found.get(packageKey));
        continue;
      }
      errors.push(trimmed + ' (not found: not a preset id, package name, or existing path)');
    }
    return { targets: out, errors };
  }

  // ── tools ─────────────────────────────────────────────────────────────────
  // Registered directly (no ctx.effect wrapper), matching the surviving
  // include-tree plugin pattern (`dsh-plugin-finder`): the fiber owns disposal.
  const tools = ctx.get('tools');
  if (tools !== undefined) {
    const output = {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    };
    tools.register({
      name: 'dsh_security_scan_plugins',
      description:
        'Batch-audit one or more plugins with the harness\'s own model (no external authentication) and return per-plugin results. Identifiers may be an agent-preset id (e.g. codex-security), a profile plugin package name (e.g. dsh-plugin-finder), or an absolute directory path. Each audit harvests the plugin source and produces a markdown report under the gate state dir (summary in summary.json).',
      parameters: {
        type: 'object',
        properties: {
          plugins: {
            type: 'array',
            items: { type: 'string' },
            description: 'Plugin identifiers to scan.',
          },
          force: {
            type: 'boolean',
            description: 'Force a fresh scan even when this plugin was already scanned.',
          },
          timeout_ms: {
            type: 'number',
            description: 'Per-scan timeout in milliseconds (default 3600000).',
          },
        },
        required: ['plugins'],
      },
      output,
      async execute(args, exec) {
        const { targets, errors } = await resolveTargets(Array.isArray(args.plugins) ? args.plugins : []);
        const lines = [];
        for (const target of targets) {
          const result = await runScan(target, { force: args.force === true, timeoutMs: args.timeout_ms, signal: exec.signal });
          lines.push(
            result.key + ': ' + result.status + (result.reportDir ? ' @ ' + result.reportDir : '') + (result.note ? ' | ' + String(result.note).slice(0, 300) : '')
          );
        }
        if (errors.length > 0) lines.push('unresolved: ' + errors.join('; '));
        return lines.join('\n');
      },
    });
    tools.register({
      name: 'dsh_security_scan_status',
      description:
        'Show the current scan status of every plugin known to the codex-security gate (presets and profile packages) from summary.json, plus the state dir location.',
      parameters: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      output,
      async execute() {
        const lines = ['state dir: ' + cfg.stateDir];
        const state = loadState();
        const entries = Object.values(state.plugins);
        if (entries.length === 0) {
          lines.push('(no plugins recorded yet)');
          return lines.join('\n');
        }
        for (const entry of entries) {
          const last = entry.lastScan;
          lines.push(
            entry.key + ' [' + entry.kind + ']' +
              (entry.version ? ' v' + entry.version : '') +
              ' — ' + (last ? last.status + ' @ ' + last.at : 'never scanned')
          );
        }
        return lines.join('\n');
      },
    });
  }

  // ── HTTP endpoints for the settings panel ─────────────────────────────────
  // Registered directly (fiber owns disposal). If webServer is not available
  // yet at apply time, registerWebRoutes() is retried from the watcher tick.
  let routesRegistered = false;
  const scanHits = []; // timestamps of recent POST /scan triggers (rate limit)
  /** CSRF guard: allow only same-origin browser requests (Origin == Host). */
  const sameOrigin = (req) => {
    const origin = req.headers && req.headers.origin;
    const host = req.headers && req.headers.host;
    if (!origin || !host) return true; // no Origin (curl/tooling) -> allowed, rate-limited elsewhere
    try {
      return new URL(String(origin)).host === String(host);
    } catch {
      return false;
    }
  };
  /** Wipe audit records for the given plugin keys (or all) and their report dirs. */
  function clearRecords(keys, all) {
    const state = loadState();
    const entries = all ? Object.values(state.plugins) : keys.map((k) => state.plugins[k]).filter(Boolean);
    if (all) state.plugins = {};
    else for (const k of keys) delete state.plugins[k];
    for (const entry of entries) {
      for (const scan of entry.scans ?? []) {
        if (scan.reportDir) {
          try {
            rmSync(scan.reportDir, { recursive: true, force: true });
          } catch {
            /* best-effort */
          }
        }
      }
    }
    saveState(state);
    writeSummary(state);
    return entries.map((e) => e.key);
  }
  const sendJson = (res, payload, status = 200) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(payload));
  };
  const summaryPayload = async () => {
    const state = loadState();
    const payload = { updatedAt: nowIso(), plugins: {} };
    for (const [key, entry] of Object.entries(state.plugins)) {
      const last = entry.lastScan;
      payload.plugins[key] = {
        id: entry.id,
        kind: entry.kind,
        // `root` is intentionally omitted from the HTTP view: it leaks
        // absolute filesystem layout. State.json keeps it for internal use.
        version: entry.version,
        status: last ? last.status : 'never',
        lastScanAt: last ? last.at : null,
        reportDir: last ? last.reportDir : null,
        note: last && last.status !== 'completed' ? (last.note ?? null) : null,
      };
    }
    // Resilient fallback: if nothing has been recorded yet (e.g. the boot tick
    // never ran in this process), serve a LIVE discovery view so the panel
    // always shows the plugin list instead of an empty state.
    if (Object.keys(payload.plugins).length === 0) {
      try {
        const found = await discoverPlugins();
        for (const info of found.values()) {
          if (isIgnored(info)) continue;
          payload.plugins[info.key] = {
            id: info.id,
            kind: info.kind,
            version: info.version,
            status: 'never',
            lastScanAt: null,
            reportDir: null,
            note: null,
          };
        }
      } catch {
        /* live discovery is best-effort */
      }
    }
    return payload;
  };
  function registerWebRoutes() {
    if (routesRegistered) return true;
    const webServer = ctx.get('webServer');
    if (webServer === undefined) return false;
    try {
      webServer.register({
        kind: 'exact',
        path: '/dsh-security/status.json',
        handler: async (_req, res) => sendJson(res, await summaryPayload()),
      });
      webServer.register({
        kind: 'exact',
        path: '/dsh-security/report',
        handler: (req, res) => {
          const parsed = new URL(req.url ?? '/', 'http://localhost');
          const id = parsed.searchParams.get('id') ?? '';
          const state = loadState();
          let target = null;
          outer: for (const entry of Object.values(state.plugins)) {
            for (const scan of entry.scans ?? []) {
              if (scan.reportDir === id) {
                target = scan.reportDir;
                break outer;
              }
            }
          }
          if (!target) {
            res.statusCode = 404;
            res.end('report not found');
            return;
          }
          // Defense-in-depth: reportDir values are exact matches against stored
          // scan records, but never serve a path outside the reports root even
          // if state.json was tampered with.
          const reportsRoot = canonicalizePath(resolvePath(join(cfg.stateDir, 'reports')));
          const targetPath = canonicalizePath(resolvePath(target));
          if (targetPath !== reportsRoot && !targetPath.startsWith(reportsRoot + pathSep)) {
            res.statusCode = 404;
            res.end('report not found');
            return;
          }
          try {
            const text = readFileSync(join(target, 'report.md'), 'utf8');
            res.statusCode = 200;
            res.setHeader('content-type', 'text/plain; charset=utf-8');
            res.end(text);
          } catch {
            res.statusCode = 404;
            res.end('report file missing');
          }
        },
      });
      webServer.register({
        kind: 'exact',
        path: '/dsh-security/scan',
        handler: async (req, res) => {
          // CSRF guard (F10): the settings panel is same-origin, so a
          // cross-origin browser POST (malicious page) is rejected outright.
          // Origin-less requests (curl, local tooling) still hit the rate
          // limit below.
          if (!sameOrigin(req)) {
            sendJson(res, { ok: false, error: 'cross-origin request rejected' }, 403);
            return;
          }
          // Rate limit (F1): the endpoint is unauthenticated on localhost, so
          // bound how often scans can be triggered to avoid resource/billing
          // exhaustion.
          const now = Date.now();
          while (scanHits.length > 0 && now - scanHits[0] > cfg.scanRateWindowMs) scanHits.shift();
          if (scanHits.length >= cfg.scanRateLimit) {
            sendJson(res, { ok: false, error: 'rate limited: too many scan triggers (max ' + cfg.scanRateLimit + ' per ' + cfg.scanRateWindowMs + 'ms)' }, 429);
            return;
          }
          scanHits.push(now);
          let body = '';
          for await (const chunk of req) body += chunk;
          let plugins = [];
          try {
            plugins = (JSON.parse(body || '{}').plugins ?? []);
          } catch {
            /* invalid body -> no plugins */
          }
          if (!Array.isArray(plugins)) plugins = [];
          if (plugins.length > 50) {
            sendJson(res, { ok: false, error: 'too many plugins in one request (max 50)' }, 400);
            return;
          }
          const { targets, errors } = await resolveTargets(plugins);
          const started = [];
          for (const target of targets) {
            queueScan(target, { force: true });
            started.push(target.key);
          }
          sendJson(res, { ok: true, started, errors });
        },
      });
      webServer.register({
        kind: 'exact',
        path: '/dsh-security/clear',
        handler: async (req, res) => {
          // Destructive but local: same CSRF origin guard as /scan; no LLM
          // cost involved, so no rate limit.
          if (!sameOrigin(req)) {
            sendJson(res, { ok: false, error: 'cross-origin request rejected' }, 403);
            return;
          }
          let body = '';
          for await (const chunk of req) body += chunk;
          let parsed = {};
          try {
            parsed = JSON.parse(body || '{}');
          } catch {
            /* invalid body */
          }
          const all = parsed.all === true;
          const keys = Array.isArray(parsed.plugins) ? parsed.plugins.map(String) : [];
          if (!all && keys.length === 0) {
            sendJson(res, { ok: false, error: 'specify { "all": true } or { "plugins": [...] }' }, 400);
            return;
          }
          const cleared = clearRecords(keys, all);
          sendJson(res, { ok: true, cleared: all ? 'all' : cleared });
        },
      });
      routesRegistered = true;
      console.log('[dsh-security-gate] web routes registered');
      return true;
    } catch (error) {
      console.error('[dsh-security-gate] route registration failed: ' + String(error));
      return false;
    }
  }
  registerWebRoutes();

  // ── lifecycle ─────────────────────────────────────────────────────────────
  const timer = ctx.get('timer');
  let tickStartedAt = 0;
  const safeTick = () => {
    // Watchdog: if a previous tick is still marked running beyond the budget,
    // force-reset the flag so the poll loop can never wedge permanently.
    if (ticking && tickStartedAt > 0 && Date.now() - tickStartedAt > cfg.tickWatchdogMs) {
      console.error('[dsh-security-gate] tick watchdog fired — resetting stuck tick');
      ticking = false;
    }
    if (!ticking) tickStartedAt = Date.now();
    tick().catch((error) => console.error('[dsh-security-gate] tick failed: ' + String(error)));
  };
  if (timer !== undefined && cfg.autoScan) {
    timer.timeout(safeTick, 3000);
    timer.interval(safeTick, cfg.intervalMs);
  } else if (cfg.autoScan) {
    // no timer service: run one boot scan via the event loop and stop
    setTimeout(safeTick, 3000);
  }

  console.log('[dsh-security-gate] active: autoScan=' + cfg.autoScan + ' intervalMs=' + cfg.intervalMs + ' stateDir=' + cfg.stateDir);
}
