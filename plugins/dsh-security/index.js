// DSH agent-preset plugin wrapping the @openai/codex-security CLI.
//
// Loaded from an agent preset composition as a relative row:
//   - id: codex-security
//     name: ./plugins/codex-security/index.js
//
// Registers model-facing tools that execute the Codex Security CLI through the
// host `shell` service (the same sandboxed executor the bash/pwsh tools use).
// Real scans require network access, Node.js >= 22.13, Python >= 3.10, and
// Codex Security authentication (`npx @openai/codex-security login`, or
// OPENAI_API_KEY / CODEX_API_KEY for noninteractive runs).
//
// Zero-dependency by design (Node builtins only): a preset subtree loads with
// ESM resolution rooted at the preset directory, which has no node_modules, so
// no @deepseek-ai/* import can resolve there. Tools are registered as raw
// ToolDefinitions with raw JSON-Schema parameters.
import { fileURLToPath } from 'node:url';

export const name = 'codex-security';

/** Quote a single CLI argument when it contains shell-significant characters. */
function quote(value) {
  const s = String(value);
  if (s.length === 0) return '""';
  return /[\s"'$`]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s;
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
  const cli = config.cliCommand ?? 'npx --yes @openai/codex-security';
  const scanTimeoutMs = config.scanTimeoutMs ?? 3600000;
  const tools = ctx.get('tools');
  if (tools === undefined) return;

  /** Resolve the working directory for a call: explicit arg, else session cwd. */
  function resolveWorkdir(exec, argWorkdir) {
    if (argWorkdir !== undefined) return argWorkdir;
    return exec.agent?.session?.header?.cwd;
  }

  /**
   * Run the CLI. Returns `{ text }` for a foreground run or
   * `{ background: true, jobId }` when started as a background job.
   */
  async function runCli(exec, parts, { timeoutMs, workdir, background = false }) {
    const shell = ctx.get('shell');
    if (shell === undefined) throw new Error('codex-security: shell service unavailable');
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
            const proc = shell.start(shell.resolve(request));
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
    const result = await shell.run(shell.resolve({ ...request, signal: exec.signal }));
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
  // `<preset>/plugins/codex-security/index.js`, so the payload is two levels up.
  const bundledDir = fileURLToPath(new URL('../../bundled/', import.meta.url));
  register({
    name: 'dsh_security_resources',
    description:
      'Return the absolute paths of the bundled Codex Security payload shipped with this preset (the upstream workflow skills, references, schemas, examples, and Python scripts). Use it to read a workflow skill\'s referenced documents or to run one of the bundled Python scripts (e.g. resolve_security_md.py) with the python tool.',
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
      if (args.detail !== true) {
        return Object.entries(paths).map(([k, v]) => `${k}: ${v}`).join('\n');
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
      ].join('\n');
    },
  });

  // ── dsh_security_scan ──────────────────────────────────────────────────
  register({
    name: 'dsh_security_scan',
    description:
      'Run an OpenAI Codex Security scan on a repository, directory, or scoped path and return the CLI output (progress on stderr, scan results/manifest on stdout). Requires Codex Security authentication: OPENAI_API_KEY/CODEX_API_KEY env, or a prior `dsh_security_cli` `login`. Long scans should be run in the background (`run_in_background: true`) and read with the job tools.',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Repository or path to scan (defaults to the current working directory).' },
        mode: { type: 'string', enum: ['standard', 'deep'], description: 'standard (default, single pass) or deep (multi-pass discovery).' },
        model: { type: 'string', description: 'Model id, e.g. gpt-5.6-terra or an OpenRouter/Fireworks/Bedrock model.' },
        provider: { type: 'string', description: 'Inference provider (openai, openrouter, fireworks, amazon-bedrock).' },
        effort: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Scan effort.' },
        workers: { type: 'number', description: 'Number of parallel workers.' },
        subagents: { type: 'number', description: 'Deep-scan subagents per worker (0 disables).' },
        max_time_hours: { type: 'number', description: 'Deep-scan discovery time cap in hours (positive, up to 96).' },
        stop_after_no_new: { type: 'number', description: 'Deep-scan stop after N discovery runs with no new findings.' },
        max_discovery_runs: { type: 'number', description: 'Deep-scan maximum discovery runs.' },
        scan_prompt_file: { type: 'string', description: 'Path to a file with shared scan instructions.' },
        post_scan_prompt_file: { type: 'string', description: 'Path to a file with post-scan follow-up instructions.' },
        knowledge_base: { type: 'array', items: { type: 'string' }, description: 'Security documents to share with the scan (files or directories); repeatable.' },
        auth: { type: 'string', enum: ['chatgpt', 'api-key'], description: 'Credential selection for interactive scans.' },
        output_dir: { type: 'string', description: 'Directory for scan results (defaults to the Codex Security scans dir).' },
        verbose: { type: 'boolean', description: 'Print scan diagnostics to stderr.' },
        workdir: { type: 'string', description: 'Working directory for the scan (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Foreground timeout in ms (default 3600000). Ignored when run_in_background is true.' },
        run_in_background: { type: 'boolean', description: 'Start the scan as a background job and return its job id.' },
      },
    },
    output,
    async execute(args, exec) {
      const parts = [cli, 'scan', quote(args.target ?? '.')];
      if (args.mode) parts.push('--mode', args.mode);
      if (args.model) parts.push('--model', quote(args.model));
      if (args.provider) parts.push('--provider', quote(args.provider));
      if (args.effort) parts.push('--effort', args.effort);
      if (args.workers !== undefined) parts.push('--workers', String(args.workers));
      if (args.subagents !== undefined) parts.push('--subagents', String(args.subagents));
      if (args.max_time_hours !== undefined) parts.push('--max-time-hours', String(args.max_time_hours));
      if (args.stop_after_no_new !== undefined) parts.push('--stop-after-no-new', String(args.stop_after_no_new));
      if (args.max_discovery_runs !== undefined) parts.push('--max-discovery-runs', String(args.max_discovery_runs));
      if (args.scan_prompt_file) parts.push('--scan-prompt-file', quote(args.scan_prompt_file));
      if (args.post_scan_prompt_file) parts.push('--post-scan-prompt-file', quote(args.post_scan_prompt_file));
      for (const kb of args.knowledge_base ?? []) parts.push('--knowledge-base', quote(kb));
      if (args.auth) parts.push('--auth', args.auth);
      if (args.output_dir) parts.push('--output-dir', quote(args.output_dir));
      if (args.verbose) parts.push('--verbose');
      const workdir = resolveWorkdir(exec, args.workdir);
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
      'List security findings for a repository from saved Codex Security scans. Equivalent to `codex-security findings list [repository]`.',
    parameters: {
      type: 'object',
      properties: {
        repository: { type: 'string', description: 'Repository path; defaults to the working directory.' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000).' },
      },
    },
    output,
    async execute(args, exec) {
      const parts = [cli, 'findings', 'list'];
      if (args.repository) parts.push(quote(args.repository));
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms ?? 120000,
        workdir: resolveWorkdir(exec, args.workdir),
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
      const parts = [cli, 'scans', 'compare', quote(args.before_scan_id), quote(args.after_scan_id)];
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
      'Run any other @openai/codex-security CLI command (e.g. `login`, `scans list`, `scans logs SCAN_ID`, `findings list`, `scans compare`, `--help`). Provide the subcommand and its arguments exactly as the CLI expects, without the leading `codex-security` binary name.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Full subcommand and arguments, e.g. `login` or `scans logs <scan-id>`.' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000).' },
        run_in_background: { type: 'boolean', description: 'Start the command as a background job and return its job id.' },
      },
      required: ['command'],
    },
    output,
    async execute(args, exec) {
      const parts = [cli, ...args.command.split(/\s+/).filter(Boolean).map(quote)];
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
