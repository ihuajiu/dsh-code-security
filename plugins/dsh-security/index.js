// DSH agent-preset plugin wrapping the @openai/codex-security CLI.
//
// Loaded from an agent preset composition as a relative row:
//   - id: dsh-security-tools
//     name: ./plugins/dsh-security/index.js
//
// Registers model-facing tools that execute the Codex Security CLI through the
// host `shell` service (the same sandboxed executor the bash/pwsh tools use).
// Real scans require network access, Node.js >= 22.13, Python >= 3.10, and
// Codex Security authentication (`npx @openai/codex-security login`, or
// OPENAI_API_KEY / CODEX_API_KEY for noninteractive runs).
//
// Security posture (hardened per security audit):
//   1. Shell injection. Every model-supplied argument is passed as a literal
//      shell word: single-quoted with shell-aware escaping, so backticks,
//      `$(...)`, `$VAR`, quotes, and globs are inert on both the bash
//      (`bash -c`) and PowerShell (`pwsh -Command`) executors. No argument is
//      ever spliced into the command string unquoted.
//   2. Path confinement. `dsh_security_scan` / `dsh_security_findings` path
//      arguments (target, prompt files, knowledge base, output dir) must
//      resolve inside the run's working directory unless the plugin config
//      explicitly sets `allowTargetsOutsideWorkdir: true`, so a scan cannot be
//      pointed at `~/.ssh`, `/etc`, or any other unrelated readable tree.
//   3. Subcommand whitelist. `dsh_security_cli` accepts only a fixed set of
//      top-level subcommands (`cliAllowedVerbs`). `scan`/`bulk-scan` are
//      intentionally NOT in it: scans must go through `dsh_security_scan`,
//      which applies the path and timeout policy.
//   4. Timeout policy. Foreground commands are capped at
//      `maxForegroundTimeoutMs` (default 5 minutes); anything longer must run
//      as a background job (`run_in_background: true`), so one hung `npx`
//      cannot hold the shell executor for an hour.
//   5. Payload integrity. The bundled scripts under `../../bundled/scripts/`
//      are checksum-verified at load against the manifest below; a mismatch is
//      surfaced through `dsh_security_resources` so the model never runs a
//      tampered script.
//
// Zero-dependency by design (Node builtins only): a preset subtree loads with
// ESM resolution rooted at the preset directory, which has no node_modules, so
// no @deepseek-ai/* import can resolve there. Tools are registered as raw
// ToolDefinitions with raw JSON-Schema parameters.
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve as resolvePath, sep as pathSep } from 'node:path';

export const name = 'dsh-security-tools';

/**
 * SHA-256 manifest of the bundled payload scripts, keyed by path relative to
 * `bundled/`. Verified at plugin load; `dsh_security_resources` reports
 * pass/fail so the agent never runs a script whose content is not the pristine
 * bundled one. Regenerate after a payload update with:
 *
 *   Get-ChildItem -Recurse -File bundled/scripts | ForEach-Object {
 *     "{0}`t{1}" -f $_.FullName.Substring($PWD.Path.Length + 1).Replace('\','/'),
 *       (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant() }
 */
const SCRIPTS_CHECKSUMS = {
  'scripts/config_preflight.py': 'cdf8cd6083488f9c1ceb1ea55c7450a36ab140d5f014ac03fa77521957dc6665',
  'scripts/deep_scan_config.py': '0100785de2281e7184572b043377d22e18b9cc6d7a78a8d607d69251253ad0ac',
  'scripts/deep_scan_workbench.py': '37e7e8e67899a4f2ce1fb637214cfaa6ce68e39a9e85eb88f318a7c85036895e',
  'scripts/filesystem_identity.py': '18338ac1cf28102d55340a7b2b71d479b57ee75a5d95262ff52129432b40aff0',
  'scripts/finalize_scan_contract.py': '4133588fcf306d8854e633eb4011264aa1677deafe3a53466471c0cd9b1ba493',
  'scripts/finding_preview.py': '5f43ed6d8bcf97d7af7fc727a34fc3782afdda445e804137a7f78f2c2495aa16',
  'scripts/generate_in_scope_files.py': 'f61198674e61e814e20f3f3f21304700e5a9192e3b8b87d7036fd36679b1a0c5',
  'scripts/generate_rank_input.py': 'c723de9c1de96c8f1788a8c3b73cd320533352abc30b416c9fe35643dfa20e6c',
  'scripts/normalize_candidates.py': '73bcda48937e624da364d22718b58a5dd3816b748a3cff0635080abb6577650c',
  'scripts/rank_preview.py': '129506f846fbfd380d871169f84e7dfce2fe6671cf3ca142e5a4a2578a78b218',
  'scripts/report_projection.py': '2b7f344233ab1f2ccbb57cbfe60591a85ac39f61b2816e9efa5f361f103c41ab',
  'scripts/resolve_security_md.py': '128e62db89755112b941b4a5330aa2a5f40c2b68563a7053c2d51056e2b66517',
  'scripts/snapshot_sqlite.py': '7c03bb87c7ffab755f45d1104210dfa849f089707f1d77bfb393c1591d9896e5',
  'scripts/validate_report_format.py': '1e717bf9a6048414f85445ddd058d27d47ebaa16a0ca86860a8abde7bca27efb',
  'scripts/validate_scan_contract.py': 'e876733bc1ac0efbccbac112c1e43975451bb199e7e51e876e9b9b7fbd3c30ce',
  'scripts/validate_tracking_source.py': '8335c0392c49cd8229997c34f7df1c1ebda029b5a185b647ed702d6f91cd840a',
  'scripts/windows_scan_local_files.py': 'badcd9d7a2ece5448fec50436394dd9456223e6c6cf8489aa8645e4d2a0b987d',
  'scripts/workbench/__init__.py': '4fe54d953e899a1c5b59902f0cdbb4fe0537fa5c4e19fe243832439b8687fa74',
  'scripts/workbench/handoff.py': '168c25ac240f42f2c2a48506693738e629884feaf3516390af500bb3f104c45c',
  'scripts/workbench_cli.py': '8ffba209a7322a160c35ae98567990fbe203d2e031bf251ba27392c41eedd362',
  'scripts/workbench_constants.py': 'a8ee358d041d2d6652ad78c3fdfd8302311867b3f5c0d8ca4756ec54b6f778a2',
  'scripts/workbench_db.py': '7f1f8e789d102e6088da9292b87d9442becc18f6970acaf5bd331fcd0d2c4900',
  'scripts/workbench_feedback.py': '507a03a2303d9e5d341f59363f6c9d8eaa53d5f871764d0cab393e615a79ec20',
  'scripts/workbench_native_indexes.py': 'b7db598d194725adb4de4ae2378c50067a19242795d0103274f92e7ab8b3ae61',
  'scripts/workbench_progress.py': '67866c19a46e41a5f05f72829c838a65f744d2cee9abdf7f1dbb3fd75893eb69',
  'scripts/workbench_remediation.py': 'ecbc85d1779c82e9b7ae9f0fa2ae2698c2dbe1de87462b49de4d26c8d94f35a5',
  'scripts/workbench_scan_history.py': 'de4b15c3b44c7aee8ccd4aeaaaf588009ce90d1e86a9ee29d6553f167f1c8784',
  'scripts/workbench_scan_start.py': '47d99770476d2617b59cb0b773c3b0ad99d504256627bea613a03bce0a5d0a52',
  'scripts/workbench_scan_usage.py': '23977d483a8ba46f16cda7f3714778bd9feef6aff5d8b7e8a1e2be2644fc3533',
  'scripts/workbench_schema.py': 'd7a96fd84f139e7ffb0348ae41763623e9edc8c36d7e0f98796f60f72faa8f69',
  'scripts/workbench_source_excerpt.py': '1510d4e64682684316fd1f25f3d3a564724e2cdf4ace25763e1cc5d938bac39d',
  'scripts/workbench_target.py': '4d38d9ab7bf4dae35964cd51635edf928f089dc48376963bca709ad37569276e',
  'scripts/workbench_target_state.py': '925ce0abd864bd5312b5e2df309de6dd3285793b56af91286eaf2ece29815a0b',
  'scripts/workbench_validation.py': '8a44c79ee6675907ce7bb8577f21b6c45be74085ff638cb24a20dcf871568514',
};

/** Resolve the quoting dialect: explicit config, else auto by host platform. */
function detectShell(configShell) {
  if (configShell === 'bash' || configShell === 'pwsh') return configShell;
  // The preset composition runs bash on POSIX hosts and pwsh on win32 hosts.
  if (typeof process !== 'undefined' && process.platform === 'win32') return 'pwsh';
  return 'bash';
}

/**
 * Quote one argument as a literal shell word.
 * - bash (`bash -c`): single-quote, embedding `'` as `'\''`. POSIX-correct:
 *   backticks, `$(...)`, `$VAR`, globs, spaces, and newlines are all inert.
 * - pwsh (`pwsh -Command`): single-quote, embedding `'` by doubling (`''`) —
 *   the PowerShell literal-string escape. Backticks and `$` are inert inside
 *   PowerShell single-quoted strings.
 */
function quoteArg(value, shell) {
  const s = String(value);
  if (shell === 'pwsh') return `'${s.replace(/'/g, "''")}'`;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * Verify the bundled payload scripts against the embedded manifest: every
 * expected file must exist with its recorded hash, and no unexpected `.py`
 * file may appear. Returns `{ ok, failures }`; failures are human-readable.
 */
function verifyPayloadIntegrity(bundledDirUrl) {
  const failures = [];
  const expected = new Set(Object.keys(SCRIPTS_CHECKSUMS));
  const seen = new Set();
  const walk = (dirRel) => {
    for (const entry of readdirSync(new URL(dirRel, bundledDirUrl), { withFileTypes: true })) {
      const rel = dirRel + entry.name;
      if (entry.isDirectory()) {
        walk(rel + '/');
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith('.py')) continue;
      seen.add(rel);
      const want = SCRIPTS_CHECKSUMS[rel];
      if (want === undefined) {
        failures.push(`${rel} (unexpected file)`);
        continue;
      }
      const digest = createHash('sha256').update(readFileSync(new URL(rel, bundledDirUrl))).digest('hex');
      if (digest !== want) failures.push(`${rel} (hash mismatch)`);
    }
  };
  walk('scripts/');
  for (const rel of expected) {
    if (!seen.has(rel)) failures.push(`${rel} (missing)`);
  }
  return { ok: failures.length === 0, failures };
}

/**
 * Resolve a scan/findings path argument against the run's working directory
 * and enforce containment: the resolved path must stay inside the working
 * directory unless `allowOutside` is set. Remote repository references (URLs
 * and scp-style git refs) pass through — the CLI fetches those over the
 * network instead of reading local paths. Throws with an actionable message on
 * violation.
 */
function resolveTarget(rawTarget, workdir, allowOutside) {
  let target = String(rawTarget ?? '.');
  if (target.length === 0) target = '.';
  // Remote references are the CLI's business, not local file reads.
  if (/^(https?|ssh|git|file):\/\//i.test(target) || /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:/.test(target)) {
    return target;
  }
  // Expand a leading `~` (the shell would expand it later; we must check it).
  if (target === '~') target = homedir();
  else if (target.startsWith('~/') || target.startsWith('~\\')) target = homedir() + target.slice(1);
  const root = resolvePath(workdir || (typeof process !== 'undefined' ? process.cwd() : '.'));
  const resolved = resolvePath(root, target);
  const rootKey = typeof process !== 'undefined' && process.platform === 'win32' ? root.toLowerCase() : root;
  const resolvedKey = typeof process !== 'undefined' && process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  if (!allowOutside && resolvedKey !== rootKey && !resolvedKey.startsWith(rootKey + pathSep)) {
    throw new Error(
      `dsh_security: path ${JSON.stringify(rawTarget)} resolves outside the working directory (${root}); ` +
      'only paths inside the working directory may be scanned. Choose a path under the working directory ' +
      '(or pass a workdir that contains it), or have an administrator set the plugin config ' +
      'allowTargetsOutsideWorkdir: true to permit outside paths.'
    );
  }
  return resolved;
}

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

/** Model-facing text for one finished foreground run. */
function renderResult(result) {
  const out = streamText(result.stdout);
  const err = streamText(result.stderr);
  let body = out;
  if (err.length > 0) {
    if (body.length > 0 && !body.endsWith('\n')) body += '\n';
    body += `[stderr]\n${err}`;
  }
  if (body.length === 0) body = '(no output)';
  const markers = [];
  if (result.timedOut) markers.push(`[timed out after ${result.timeoutMs}ms]`);
  if (result.signal !== null && result.signal !== undefined) {
    markers.push(`[killed by signal: ${result.signal}]`);
  } else if (result.exitCode !== undefined && result.exitCode !== 0) {
    markers.push(`[exit code: ${result.exitCode}]`);
  }
  if (markers.length === 0) return body;
  if (!body.endsWith('\n')) body += '\n';
  return body + markers.join('\n');
}

function renderProcessRead(read) {
  let text = read.delta ?? '';
  if (read.lossy) {
    const path = read.stdoutSpillPath ?? read.stderrSpillPath;
    text += `\n[some output was dropped from memory; full output: ${path ?? '(unavailable)'}]`;
  }
  return text;
}

export function apply(ctx, config = {}) {
  // Trusted, administrator-set CLI prefix (split once; not model input).
  const cliPrefix = (config.cliCommand ?? 'npx --yes @openai/codex-security').split(/\s+/).filter(Boolean);
  // Foreground scan default and hard cap: anything over the cap must run in
  // the background, so a hung `npx` cannot tie up the shell executor.
  const scanTimeoutMs = config.scanTimeoutMs ?? 300000;
  const maxForegroundTimeoutMs = config.maxForegroundTimeoutMs ?? 300000;
  // Path confinement for scan/findings path arguments (see resolveTarget).
  const allowTargetsOutsideWorkdir = config.allowTargetsOutsideWorkdir === true;
  // Top-level subcommands `dsh_security_cli` may pass through. Scan verbs are
  // deliberately excluded: scans go through dsh_security_scan (path + timeout
  // policy). Extend via config `cliAllowedVerbs`.
  const cliAllowedVerbs = config.cliAllowedVerbs ?? [
    '--help', '-h', '--version', '--schema', '--llms', '--llms-full',
    'info', 'login', 'logout', 'scans', 'findings', 'export',
  ];
  const shell = detectShell(config.shell);

  const bundledDirUrl = new URL('../../bundled/', import.meta.url);
  const bundledDir = fileURLToPath(bundledDirUrl);
  // Load-time integrity check of the bundled payload scripts.
  const integrity = verifyPayloadIntegrity(bundledDirUrl);
  if (!integrity.ok && ctx.logger) {
    ctx.logger.warn(
      `codex-security: bundled payload integrity check FAILED for ${integrity.failures.length} script(s): ` +
        integrity.failures.join(', ')
    );
  }

  const tools = ctx.get('tools');
  if (tools === undefined) return;

  /** Resolve the working directory for a call: explicit arg, else session cwd. */
  function resolveWorkdir(exec, argWorkdir) {
    if (argWorkdir !== undefined) return argWorkdir;
    return exec.agent?.session?.header?.cwd;
  }

  /**
   * Run the CLI. Returns `{ text }` for a foreground run or
   * `{ background: true, jobId }` when started as a background job. Enforces
   * the foreground timeout cap: a command whose effective timeout exceeds
   * `maxForegroundTimeoutMs` must run in the background.
   */
  async function runCli(exec, parts, { timeoutMs, workdir, background = false }) {
    if (!background && timeoutMs > maxForegroundTimeoutMs) {
      throw new Error(
        `codex-security: foreground timeout ${timeoutMs}ms exceeds the ${maxForegroundTimeoutMs}ms cap; ` +
        'set run_in_background: true for long-running commands.'
      );
    }
    const shellSvc = ctx.get('shell');
    if (shellSvc === undefined) throw new Error('codex-security: shell service unavailable');
    const command = parts.join(' ');
    const request = {
      command,
      timeoutMs,
      ...(workdir !== undefined ? { workdir } : {}),
    };
    const shellEnv = ctx.get('shellEnv');
    if (shellEnv !== undefined) {
      try {
        request.dshEnv = shellEnv.collect(exec);
      } catch {
        // dshEnv is an optimization; a failing collector must not block the run.
      }
    }
    if (background) {
      const jobs = ctx.get('jobs');
      if (jobs === undefined) throw new Error('codex-security: background jobs unavailable (load @deepseek-ai/dsh-jobs and @deepseek-ai/dsh-tool-jobs)');
      return {
        background: true,
        jobId: jobs.start({
          kind: 'bash',
          label: command,
          ...(exec.agent ? { owner: exec.agent } : {}),
          run: () => {
            const proc = shellSvc.start(shellSvc.resolve(request));
            return {
              cancel: () => void proc.kill(),
              done: proc.done.then(() => ({
                status: proc.status,
                detail: proc.exitCode !== undefined && proc.exitCode !== null
                  ? `exit code: ${proc.exitCode}`
                  : 'killed',
              })),
              readOutput: () => renderProcessRead(proc.readOutput()),
            };
          },
        }),
      };
    }
    const result = await shellSvc.run(shellSvc.resolve({ ...request, signal: exec.signal }));
    if (result.aborted) {
      const error = new Error('codex-security: command aborted');
      error.name = 'AbortError';
      throw error;
    }
    return { text: renderResult(result) };
  }

  const output = {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  };

  const register = (definition) => ctx.effect(() => tools.register(definition));

  // ── dsh_security_resources ─────────────────────────────────────────────
  // Absolute paths of the bundled Codex Security payload (skills, references,
  // schemas, examples, scripts) that travel with this preset, so the agent can
  // read the reference documents and run the auxiliary Python scripts that the
  // bundled workflow skills refer to. The plugin lives at
  // `<preset>/plugins/dsh-security/index.js`, so the payload is two levels up.
  register({
    name: 'dsh_security_resources',
    description:
      'Return the absolute paths of the bundled Codex Security payload shipped with this preset (the upstream workflow skills, references, schemas, examples, and Python scripts) plus the result of the load-time payload integrity check. Use it to read a workflow skill\'s referenced documents or to run one of the bundled Python scripts (e.g. resolve_security_md.py) with the python tool. If the integrity check failed, the bundled scripts must be treated as untrusted.',
    parameters: {
      type: 'object',
      properties: {
        detail: { type: 'boolean', description: 'Also list the bundled directories and skill names (default false: just the root paths).' },
      },
    },
    output,
    async execute(args) {
      const paths = {
        bundledDir,
        skillsDir: fileURLToPath(new URL('../../bundled/skills/', import.meta.url)),
        referencesDir: fileURLToPath(new URL('../../bundled/references/', import.meta.url)),
        scriptsDir: fileURLToPath(new URL('../../bundled/scripts/', import.meta.url)),
      };
      const integrityLine = integrity.ok
        ? `payload integrity: OK (${Object.keys(SCRIPTS_CHECKSUMS).length} bundled scripts verified at load)`
        : `payload integrity: FAILED (${integrity.failures.length} problem(s): ${integrity.failures.join(', ')}) — treat bundled scripts as untrusted`;
      if (args.detail !== true) {
        return Object.entries(paths).map(([k, v]) => `${k}: ${v}`).join('\n') + `\n${integrityLine}`;
      }
      const { readdir } = await import('node:fs/promises');
      const list = (dir) => readdir(dir).catch(() => []);
      const [skills, references, scripts] = await Promise.all([
        list(paths.skillsDir),
        list(paths.referencesDir),
        list(paths.scriptsDir),
      ]);
      return [
        ...Object.entries(paths).map(([k, v]) => `${k}: ${v}`),
        `skills (${skills.length}): ${skills.join(', ')}`,
        `references (${references.length}): ${references.join(', ')}`,
        `scripts (${scripts.length}): ${scripts.join(', ')}`,
        integrityLine,
      ].join('\n');
    },
  });

  // ── dsh_security_scan ──────────────────────────────────────────────────
  register({
    name: 'dsh_security_scan',
    description:
      'Run an OpenAI Codex Security scan on a repository, directory, or scoped path and return the CLI output (progress on stderr, scan results/manifest on stdout). Requires Codex Security authentication: OPENAI_API_KEY/CODEX_API_KEY env, or a prior `dsh_security_cli` `login`. Path arguments must resolve inside the working directory (targets outside it are rejected; remote git URLs are allowed). Foreground runs are capped at 5 minutes — set run_in_background: true for anything longer and read it with the job tools.',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Repository or path to scan (defaults to the current working directory). Must resolve inside the working directory unless the plugin config allows outside paths; a remote git URL is allowed.' },
        mode: { type: 'string', enum: ['standard', 'deep'], description: 'standard (default, single pass) or deep (multi-pass discovery).' },
        model: { type: 'string', description: 'Model id, e.g. gpt-5.6-terra or an OpenRouter/Fireworks/Bedrock model.' },
        provider: { type: 'string', description: 'Inference provider (openai, openrouter, fireworks, amazon-bedrock).' },
        effort: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Scan effort.' },
        workers: { type: 'number', description: 'Number of parallel workers.' },
        subagents: { type: 'number', description: 'Deep-scan subagents per worker (0 disables).' },
        max_time_hours: { type: 'number', description: 'Deep-scan discovery time cap in hours (positive, up to 96).' },
        stop_after_no_new: { type: 'number', description: 'Deep-scan stop after N discovery runs with no new findings.' },
        max_discovery_runs: { type: 'number', description: 'Deep-scan maximum discovery runs.' },
        scan_prompt_file: { type: 'string', description: 'Path to a file with shared scan instructions; must resolve inside the working directory.' },
        post_scan_prompt_file: { type: 'string', description: 'Path to a file with post-scan follow-up instructions; must resolve inside the working directory.' },
        knowledge_base: { type: 'array', items: { type: 'string' }, description: 'Security documents to share with the scan (files or directories inside the working directory); repeatable.' },
        auth: { type: 'string', enum: ['chatgpt', 'api-key'], description: 'Credential selection for interactive scans.' },
        output_dir: { type: 'string', description: 'Directory for scan results (defaults to the Codex Security scans dir); must resolve inside the working directory when provided.' },
        verbose: { type: 'boolean', description: 'Print scan diagnostics to stderr.' },
        workdir: { type: 'string', description: 'Working directory for the scan (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Foreground timeout in ms (default 300000). Ignored when run_in_background is true. Values above 300000 require run_in_background: true.' },
        run_in_background: { type: 'boolean', description: 'Start the scan as a background job and return its job id (required for scans longer than 5 minutes).' },
      },
    },
    output,
    async execute(args, exec) {
      const workdir = resolveWorkdir(exec, args.workdir);
      const parts = [...cliPrefix, 'scan'];
      parts.push(quoteArg(resolveTarget(args.target, workdir, allowTargetsOutsideWorkdir), shell));
      if (args.mode) parts.push('--mode', args.mode);
      if (args.model) parts.push('--model', quoteArg(args.model, shell));
      if (args.provider) parts.push('--provider', quoteArg(args.provider, shell));
      if (args.effort) parts.push('--effort', args.effort);
      if (args.workers !== undefined) parts.push('--workers', String(args.workers));
      if (args.subagents !== undefined) parts.push('--subagents', String(args.subagents));
      if (args.max_time_hours !== undefined) parts.push('--max-time-hours', String(args.max_time_hours));
      if (args.stop_after_no_new !== undefined) parts.push('--stop-after-no-new', String(args.stop_after_no_new));
      if (args.max_discovery_runs !== undefined) parts.push('--max-discovery-runs', String(args.max_discovery_runs));
      if (args.scan_prompt_file) parts.push('--scan-prompt-file', quoteArg(resolveTarget(args.scan_prompt_file, workdir, allowTargetsOutsideWorkdir), shell));
      if (args.post_scan_prompt_file) parts.push('--post-scan-prompt-file', quoteArg(resolveTarget(args.post_scan_prompt_file, workdir, allowTargetsOutsideWorkdir), shell));
      for (const kb of args.knowledge_base ?? []) {
        parts.push('--knowledge-base', quoteArg(resolveTarget(kb, workdir, allowTargetsOutsideWorkdir), shell));
      }
      if (args.auth) parts.push('--auth', args.auth);
      if (args.output_dir) parts.push('--output-dir', quoteArg(resolveTarget(args.output_dir, workdir, allowTargetsOutsideWorkdir), shell));
      if (args.verbose) parts.push('--verbose');
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms ?? scanTimeoutMs,
        workdir,
        background: args.run_in_background === true,
      });
      return result.background
        ? `started background scan job ${result.jobId} (read it with the job_output tool)`
        : result.text;
    },
  });

  // ── dsh_security_findings ──────────────────────────────────────────────
  register({
    name: 'dsh_security_findings',
    description:
      'List security findings for a repository from saved Codex Security scans. Equivalent to `codex-security findings list [repository]`. The repository path must resolve inside the working directory.',
    parameters: {
      type: 'object',
      properties: {
        repository: { type: 'string', description: 'Repository path; defaults to the working directory. Must resolve inside the working directory.' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000).' },
      },
    },
    output,
    async execute(args, exec) {
      const workdir = resolveWorkdir(exec, args.workdir);
      const parts = [
        ...cliPrefix,
        'findings',
        'list',
        quoteArg(resolveTarget(args.repository, workdir, allowTargetsOutsideWorkdir), shell),
      ];
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms ?? 120000,
        workdir,
      });
      return result.text;
    },
  });

  // ── dsh_security_scans_compare ─────────────────────────────────────────
  register({
    name: 'dsh_security_scans_compare',
    description:
      'Compare two saved Codex Security scans by scan id, matching findings by root cause and reporting new, persisting, reopened, resolved, or unknown findings. Equivalent to `codex-security scans compare BEFORE AFTER`.',
    parameters: {
      type: 'object',
      properties: {
        before_scan_id: { type: 'string', description: 'The earlier scan id.' },
        after_scan_id: { type: 'string', description: 'The later scan id.' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000).' },
      },
      required: ['before_scan_id', 'after_scan_id'],
    },
    output,
    async execute(args, exec) {
      const parts = [
        ...cliPrefix,
        'scans',
        'compare',
        quoteArg(args.before_scan_id, shell),
        quoteArg(args.after_scan_id, shell),
      ];
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms ?? 120000,
        workdir: resolveWorkdir(exec, args.workdir),
      });
      return result.text;
    },
  });

  // ── dsh_security_cli ───────────────────────────────────────────────────
  register({
    name: 'dsh_security_cli',
    description:
      'Run an allowlisted @openai/codex-security CLI command (e.g. `login`, `logout`, `info`, `scans list`, `scans logs SCAN_ID`, `findings list`, `scans compare`, `export ...`, `--help`). Provide the subcommand and its arguments exactly as the CLI expects, without the leading `codex-security` binary name. Only the top-level verbs in the whitelist are accepted — use the dedicated dsh_security_scan tool for scans (it applies path and timeout policy). Arguments are passed as shell literals; separate them with spaces.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Full subcommand and arguments, e.g. `login` or `scans logs <scan-id>`. The first token must be an allowlisted verb.' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000); values above 300000 require run_in_background: true.' },
        run_in_background: { type: 'boolean', description: 'Start the command as a background job and return its job id.' },
      },
      required: ['command'],
    },
    output,
    async execute(args, exec) {
      const tokens = String(args.command).trim().split(/\s+/).filter(Boolean);
      if (tokens.length === 0) {
        throw new Error('codex-security: `command` must name a subcommand');
      }
      const verb = tokens[0];
      if (!cliAllowedVerbs.includes(verb)) {
        throw new Error(
          `codex-security: subcommand ${JSON.stringify(verb)} is not allowed through dsh_security_cli ` +
            `(allowed: ${cliAllowedVerbs.join(', ')}). Prefer the dedicated dsh_security_scan / ` +
            'dsh_security_findings / dsh_security_scans_compare tools; an administrator can extend the ' +
            'whitelist via the plugin config `cliAllowedVerbs`.'
        );
      }
      const parts = [...cliPrefix, ...tokens.map((token) => quoteArg(token, shell))];
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms ?? 120000,
        workdir: resolveWorkdir(exec, args.workdir),
        background: args.run_in_background === true,
      });
      return result.background
        ? `started background job ${result.jobId} (read it with the job_output tool)`
        : result.text;
    },
  });
}
