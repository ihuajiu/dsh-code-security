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
//      ever spliced into the command string unquoted. Enum-like arguments
//      (`mode`, `effort`, `auth`) are additionally runtime-whitelisted before
//      quoting — safety never depends on host-side JSON-Schema enforcement.
//   2. Path confinement. `dsh_security_scan` / `dsh_security_findings` path
//      arguments (target, prompt files, knowledge base, output dir) must
//      resolve inside the run's working directory unless the plugin config
//      explicitly sets `allowTargetsOutsideWorkdir: true`, so a scan cannot be
//      pointed at `~/.ssh`, `/etc`, or any other unrelated readable tree. The
//      `workdir` argument itself is confined the same way: it must resolve
//      inside the SESSION working directory, so a prompt-injected `workdir`
//      cannot launder an out-of-scope target past the containment check.
//      `dsh_security_cli` pass-through tokens that name local paths (absolute,
//      `~`-prefixed, or existing relative files) get the same containment.
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
import { readFileSync, readdirSync, realpathSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve as resolvePath, sep as pathSep, dirname, basename } from 'node:path';

export const name = 'dsh-security-tools';

/**
 * SHA-256 manifest of the ENTIRE bundled payload (skills, references, schemas,
 * examples, scripts, mcp), keyed by path relative to `bundled/`. Verified at
 * plugin load and again on every `dsh_security_resources` call; a mismatch
 * refuses to hand out the payload paths, so the agent never runs a tampered
 * file. Regenerate after a payload update with:
 *
 *   Get-ChildItem -Recurse -File bundled | ForEach-Object {
 *     "{0}`t{1}" -f .FullName.Substring(E:\AgentsWs\PluginBuilder\openai-code-security.Path.Length + 9).Replace('\','/'),
 *       (Get-FileHash -Algorithm SHA256 .FullName).Hash.ToLowerInvariant() }
 */
const PAYLOAD_CHECKSUMS = {
﻿  '.app.json': 'e4d5b22326ee380de5d779f7b5ba590c8d1bee9a80e8869fb2bd7f4def8e974d',
  '.mcp.json': 'd52bd48cdcc1a7081eb146a9e5c0a47bb4fa815bc625ff4c9a499c18ae9c74b4',
  '.codex-plugin/plugin.json': '3d9c9dab0f39dc8a50364c7c18ab61ff823e494d0b28f6affe3b66416058377a',
  'assets/logo.png': '9b9c2b09b2fa064611fb62307d321d5c2ea70cf0789f7ce34cdb0fc0d9190b3a',
  'examples/completed-scan/coverage.json': 'd55b9b98d48323b4659dfee6531ec83ec538f2084325412b7188bf85ad68b01b',
  'examples/completed-scan/findings.json': 'a6dc4521d6478828224fbafc33585401a47bfeb0e56e07b5d2886e8a29937f2f',
  'examples/completed-scan/scan-manifest.json': 'd245ae9fc62a676293c6821e562d1a2d7d59db12d5b8dc99b85f7c5f1462fe00',
  'mcp/server.mjs': 'c58624aa4c4bd3efbb67601c9c2e98759f167f608320a6cd342814b2f2e6a636',
  'mcp/server.mjs.br.part-000': '1f8f8420c127d3940c0d273885982a66d4e203f9400a3f4165a89624cca9e8e2',
  'mcp/server.mjs.br.part-001': 'eea083afb1fef8aba0d2c981d1894d22458f96c16e33389138ee23bafccfca1e',
  'preflight/capability-profiles.toml': '732bdb3696528d8de0698dd75a83914cd6970cfa1064b5701d7c19d6ccd2a000',
  'references/config-preflight.md': '0915a9305509e04a5c89ad768783cb558100237c7881f6b30d95f3000872038a',
  'references/desktop-config-preflight.md': 'd03e7c604a0459509a4a3238289c3ad0725811e8b11fb7d0044ce8bcee6a7a26',
  'references/final-report.md': '2dc7357a6b35638b0417a331b2223095b99483ff70c0266df416e23eee828fb4',
  'references/finding-detail-fields.md': '7790106dd9c15591c9fd889517f41ae81ed7aad99e23f74cb55ba8fc34a187b4',
  'references/sarif-adapter.md': 'cebedfc09509193f081f94a592f670a639cfe741214bf4fc3aef0d920eb6f192',
  'references/scan-artifacts.md': 'd4819f0a3d9fe1cc933d9e065c8117da5640a9ee500b7f939cbf81d4b79b0cad',
  'references/scan-contract.md': '0d99dc91bb03991e501a3e17596bd618f0f17840586f10b134d51c5f6022ffc3',
  'references/security-guidance.md': 'c1fd937f0e8547b86d649325a5676e847a16aedc5009b17b57ace2a4a5d35895',
  'references/shared-hard-rules.md': '4e46d8dc62573150ec17075772279d62efc459cc3ce6e590ff91355fd2c3d7cb',
  'references/static-finding-assessment.md': '78de933caef1c8d971dab83fbb71877602a1197a52eaa7a59d6ff7bc399d0bc7',
  'schemas/coverage.schema.json': '7964b132998ca4dcdd19c75f5d92483e1d44cb71462237709b968ec548c10652',
  'schemas/findings.schema.json': 'bd16dfe9a68c9b0485cad15b4ea3b037b0006dfb76a0549ed65a60ab8b062ac4',
  'schemas/scan-manifest.schema.json': '20d6801775ae1b056d10114c3af5e07c5edfef27468218611411231a95c7c55e',
  'schemas/definitions/artifact-common.schema.json': '8187236867a2397515571d937deac92dcbf23d3db5e330d32b1f24aced4b9abc',
  'schemas/definitions/discovery-candidate.schema.json': 'b0cf54fc1ae1947db0f6a6f73e17d1124d528226de763fb89489d05fd612331b',
  'schemas/tools/candidate-attack-paths.schema.json': 'f6fcb643b4b975466c4717356a0768b0572812cd832578d8714557f5e3d16935',
  'schemas/tools/candidate-validations.schema.json': 'c871eb3462b7873c1774e6aade62acdd570636e43c0ac3c7b41b7041ca5627e9',
  'schemas/tools/deep-reducer.schema.json': '16221f688dd061172486d75972789f6cfbb0740cd5ae0fb121c732d69cda53dd',
  'schemas/tools/discovery-candidates.schema.json': 'dcd2031d64015c69b415c66e57d6e90cbdef91152a445a6f409c14d80153afa6',
  'schemas/tools/review-items.schema.json': 'acc4f4909446a62811728dd1d6581456053da8d26f774b7af208a1856f86ac5b',
  'schemas/tools/scan-draft.schema.json': 'a3733f585f2cf10d9e243197c1997ec87d1254013adad2af4a773b914b2a5608',
  'schemas/tools/worker-threat-model.schema.json': 'a00f875918794661316a033bd2d03426d61ab1e41d4a36c548c07525dcfde478',
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
  'scripts/workbench/handoff.py': '168c25ac240f42f2c2a48506693738e629884feaf3516390af500bb3f104c45c',
  'scripts/workbench/__init__.py': '4fe54d953e899a1c5b59902f0cdbb4fe0537fa5c4e19fe243832439b8687fa74',
  'skills/attack-path-analysis/SKILL.md': 'c7499785278fcfb7905b3082175bcf267fad7c9ab1e91ed4af9757a92e618fe5',
  'skills/attack-path-analysis/agents/openai.yaml': 'd9355cbcf0bc81098c9e837d9d4e8644e598410d052a862ab11cf91ef9ccb633',
  'skills/attack-path-analysis/references/attack-path-facts.md': '8c8f1abb46ddf045d76908df78e3a273da8d61aaa0f37fc992534a3ddfe42430',
  'skills/attack-path-analysis/references/severity-policy.md': '4391c415c9270f018165f0357b10a0c47fa9f757367534690d303a9011a89ffa',
  'skills/deep-security-scan/SKILL.md': '5115259fcf4348802734fba624aa2ccaf8547b0aba561c532bc8eda9dc7be6ba',
  'skills/deep-security-scan/agents/openai.yaml': '3f8d781bf372b0d053a017eabaebf947d5d48d9be2b82cb67da211128924c3f1',
  'skills/define-security-policy/SKILL.md': '286f549d7d5b017e13e38031494723b5870949e3f82ac85b6a9c32d4718433bf',
  'skills/define-security-policy/agents/openai.yaml': '8c40b0f8bd1eb7feabdcea69f12c2a7d18e492e96893c0702507ffd808b8e2b4',
  'skills/finding-discovery/SKILL.md': '938b73329188aa124770fcdf7cf7916e2941c8fdbf20acd9df96bc1a80185fe7',
  'skills/finding-discovery/agents/openai.yaml': 'c044dd83a7624b90ed19f11adc899202685ce64e32502f1d46225f69f9a2c962',
  'skills/fix-finding/SKILL.md': '0e3ac8898a43b08c415c380fe59e8a052c17fb8264af945a66ce6b14121fd601',
  'skills/fix-finding/agents/openai.yaml': '3d7a8f4a58ae1f1eb8c748ca48ea403562489a061949454ddea693ddbdbe646a',
  'skills/propose-security-hardening/SKILL.md': 'b9d2c81ecb99e6eb4ad6424dbd297a935feb66c2658692d48caf4d9840eaf306',
  'skills/propose-security-hardening/agents/openai.yaml': '1bcab19d48eb4b768c0dc435bd2e738f1471c2345cce5865bb31bdca5be0b134',
  'skills/propose-security-hardening/references/proposal-format.md': '6c0000722629098365afbf6809c3402121f90438600fb574fbc2c77aeb649ba4',
  'skills/security-diff-scan/SKILL.md': '592935e3fe7888a1d8ba77eda89cc67c9484f020242080d99efba94093b7b836',
  'skills/security-diff-scan/agents/openai.yaml': 'f3d31e09befbb8532b53fdccb63a34c0b894a7fb96215b40e84647cd9f8e1b50',
  'skills/security-scan/SKILL.md': '5dcd941f3dc0362edf14675256e987cfe7e71f47ec8982616133101b744bc98d',
  'skills/security-scan/agents/openai.yaml': '5952ae0b0f7d378b7e6ab3fe793335a0e26e5d15bd2d7fdd14ecdd795607ceb6',
  'skills/security-scan/references/desktop-scan.md': '8138e3cb6862654c141d58dff865fb760c43f1e2b10994488b4329cfce95ebe2',
  'skills/security-scan/references/repository-wide-scan.md': '17abc3c18c05cf1f85138a4efd3bb9a63880961f5a044ae6906a8bb3a7c8fa81',
  'skills/security-scan/references/scan-artifacts-and-ledger.md': '443084c974eb80747a6dc4e092c7fca55f412ca5ab3f14e2d27dc1223cc690a4',
  'skills/threat-model/SKILL.md': '0fe044993d1a08c4aefbc9d431f6f18115f62b3dbc2e818258af01ec8924a246',
  'skills/threat-model/agents/openai.yaml': 'a3533478c2548248ef07c9afbbe0a7451f1fa1882883b4def0906d8113b7dd6c',
  'skills/threat-model/references/threat-model-guidance.md': '32b417073376523c17647a35aaf36445a2429d2708b06c29ff00119887857eb0',
  'skills/track-findings/SKILL.md': 'cb6e7625bc7c10fbc7b94d99918667c9e942bacb56d871e837a6939d20f4fd8c',
  'skills/track-findings/agents/openai.yaml': '39e73c0003afc8bd9d3cf53c027d8274e724dc41f46e3cd6863ad34bb4de4200',
  'skills/track-findings/references/github-security-advisories.md': 'f56010d265d0ce56e555dd73a92777a6d3be8f5d31bd2af7ff163423a667d10e',
  'skills/track-findings/references/jira.md': '05affbdefbfd8054d08f16e5fe15729ade440b5627a4561f8693bd97fb3a3ea2',
  'skills/triage-finding/SKILL.md': '4c3499bad13a290bcf9678e996807ca6e613557d427d9efa87f104421e33008f',
  'skills/triage-finding/agents/openai.yaml': '1d53cfba14878c05745309eec3f682f70c5e8d49ecc033628cf832a5dd27c9cb',
  'skills/triage-finding/references/github-rest-intake.md': '212d11b82ea986ba4fe074e04821b545a2c44b2a405309031e30e286d8d10b5a',
  'skills/triage-finding/references/ticket-intake.md': 'bd545655e0402f5f326f34191a67b6dd30c382914e9ae81b2e66ad745860e78a',
  'skills/triage-finding/references/triage-result-contract.md': '321027c102cf36119376ef86f0701a4a7c6fc22e46d28fd240639aae156b134a',
  'skills/validation/SKILL.md': 'f92138ea9ad6a76a533b95212694f76f399666efb30568567f7e0d0dfdd28783',
  'skills/validation/agents/openai.yaml': '7516bcd4748b55566694284d7d953a7db0c94d5a2123895fabb36d7d9d7d74e4',
  'skills/validation/references/validation-guidance.md': '42f7a9d85b78d0deb5e6eda82b8c59ed101c40d36065833b9cf39fe50699e255',
  'skills/vulnerability-writeup/SKILL.md': '6bdb62f5e625909ce5d15253ee51f866d0b6a43222100649767c524f793fad60',
  'skills/vulnerability-writeup/agents/openai.yaml': '7987566daac59e3dd6c5211fe020f71fc4c862843c231d10c28a45697d680f9e',
  'skills/vulnerability-writeup/references/report-format.md': '9172eabf753038c97fdf7eb77c9b8c9986e57224b2f9a9b8429552c28eaeec70',
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
  const expected = new Set(Object.keys(PAYLOAD_CHECKSUMS));
  const seen = new Set();
  const walk = (dirRel) => {
    for (const entry of readdirSync(new URL(dirRel, bundledDirUrl), { withFileTypes: true })) {
      const rel = dirRel + entry.name;
      if (entry.isDirectory()) {
        walk(rel + '/');
        continue;
      }
      if (!entry.isFile()) continue;
      seen.add(rel);
      const want = PAYLOAD_CHECKSUMS[rel];
      if (want === undefined) {
        failures.push(`${rel} (unexpected file)`);
        continue;
      }
      const digest = createHash('sha256').update(readFileSync(new URL(rel, bundledDirUrl))).digest('hex');
      if (digest !== want) failures.push(`${rel} (hash mismatch)`);
    }
  };
  walk('');
  for (const rel of expected) {
    if (!seen.has(rel)) failures.push(`${rel} (missing)`);
  }
  return { ok: failures.length === 0, failures };
}

/**
 * Canonicalize a path through symlinks: realpath the deepest EXISTING
 * ancestor (a scan target or output dir may not exist yet), then re-append the
 * missing suffix. Falls back to the lexical path when nothing exists or a
 * symlink loop is detected. Used so path containment cannot be bypassed by a
 * symlink inside the working directory pointing outside it (F1), and so the
 * CLI executes against the canonical location (F3).
 */
function canonicalizePath(p) {
  let probe = p;
  const missing = [];
  for (;;) {
    try {
      return realpathSync(probe) + (missing.length > 0 ? pathSep + missing.reverse().join(pathSep) : '');
    } catch {
      const parent = dirname(probe);
      if (parent === probe) return p; // filesystem root or unresolvable
      missing.push(basename(probe));
      probe = parent;
    }
  }
}

/** Validate an integer parameter into the documented range; throws otherwise. */
function toBoundedInt(value, { min, max, name }) {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max || !Number.isInteger(n)) {
    throw new Error(`dsh_security: ${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

/** Validate a fractional numeric parameter into the documented range. */
function toBoundedNumber(value, { min, max, name }) {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) {
    throw new Error(`dsh_security: ${name} must be a number between ${min} and ${max}`);
  }
  return n;
}

/** The only inference providers the CLI wrapper accepts (F5). */
const PROVIDERS = ['openai', 'openrouter', 'fireworks', 'amazon-bedrock'];

/**
 * Enum-like scan arguments the CLI accepts. Whitelisted at runtime (not just
 * via the tool's JSON-Schema enum) because the model is untrusted input and a
 * host tool-call pipeline may not hard-reject out-of-enum values (audit
 * finding 1). Together with quoteArg these values can never reach the shell
 * as syntax.
 */
const SCAN_MODES = ['standard', 'deep'];
const SCAN_EFFORTS = ['low', 'medium', 'high'];
const AUTH_SELECTIONS = ['api-key'];

/**
 * Resolve a scan/findings path argument against the run's working directory
 * and enforce containment on CANONICAL paths: the resolved path must stay
 * inside the canonical working directory unless `allowOutside` is set. Remote
 * repository references pass through — the CLI fetches those over the network
 * instead of reading local paths. Only unambiguous network URLs (https/ssh/git)
 * and scp-style refs that do NOT name an existing local path are treated as
 * remote: a file/dir that merely LOOKS scp-style (e.g. a symlink named
 * `user@host:x`) goes through normal containment (gate finding 1).
 * `file://` is deliberately NOT allowed (it denotes local files). Throws with
 * an actionable message on violation.
 */
function resolveTarget(rawTarget, workdir, allowOutside) {
  let target = String(rawTarget ?? '.');
  if (target.length === 0) target = '.';
  // `file://` denotes LOCAL files, not a remote fetch — reject it outright
  // instead of letting it slip through containment (F2).
  if (/^file:\/\//i.test(target)) {
    throw new Error('dsh_security: file:// targets are not supported; use a local path inside the working directory');
  }
  // Unambiguous network URLs are the CLI's business, not local file reads.
  if (/^(https?|ssh|git):\/\//i.test(target)) {
    return target;
  }
  // scp-style refs (user@host:path) are AMBIGUOUS: they may be a local path
  // that merely LOOKS remote. If a file/dir with that exact name exists under
  // the working directory (including a symlink), it is a LOCAL path and must
  // go through containment below — a bare regex pass-through would let a
  // symlink named e.g. `user@host:x` escape the working directory. Only
  // genuinely non-existent references are handed to the CLI as remote fetches.
  if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:/.test(target)) {
    const probeRoot = canonicalizePath(resolvePath(workdir || (typeof process !== 'undefined' ? process.cwd() : '.')));
    let localExists = false;
    try {
      realpathSync(resolvePath(probeRoot, target));
      localExists = true;
    } catch {
      /* not an existing local path -> treat as a remote fetch */
    }
    if (!localExists) return target;
  }
  // Expand a leading `~` (the shell would expand it later; we must check it).
  if (target === '~') target = homedir();
  else if (target.startsWith('~/') || target.startsWith('~\\')) target = homedir() + target.slice(1);
  const root = canonicalizePath(resolvePath(workdir || (typeof process !== 'undefined' ? process.cwd() : '.')));
  const resolved = canonicalizePath(resolvePath(root, target));
  const rootKey = typeof process !== 'undefined' && process.platform === 'win32' ? root.toLowerCase() : root;
  const resolvedKey = typeof process !== 'undefined' && process.platform === 'win32' ? resolved.toLowerCase() : resolved;
  if (!allowOutside && resolvedKey !== rootKey && !resolvedKey.startsWith(rootKey + pathSep)) {
    throw new Error(
      `dsh_security: path ${JSON.stringify(rawTarget)} resolves outside the working directory (${root}); ` +
      'only paths inside the working directory may be scanned (symlinks are resolved). Choose a path under ' +
      'the working directory (or pass a workdir that contains it), or have an administrator set the plugin ' +
      'config allowTargetsOutsideWorkdir: true to permit outside paths.'
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
  // Version-pinned (F4): npx --yes fetches the latest publish unless the
  // package name carries an exact version. Bump deliberately and re-test.
  // The prefix is admin config but is still validated: only a strict set of
  // command characters is accepted (letters/digits, `@`, `.`, `-`, `/`, space),
  // which excludes shell metacharacters AND glob characters (`*?[]{}`),
  // `~`, `#`, `!`, backslash, and all whitespace beyond plain spaces — so a
  // misconfigured cliCommand cannot become an arbitrary command or undergo
  // glob expansion (gate finding 4). Anything else falls back to the pinned
  // default.
  const configuredCliCommand = config.cliCommand ?? 'npx --yes @openai/codex-security@0.1.12';
  const cliCommand =
    typeof configuredCliCommand === 'string' && /^[\w@.\-/ ]+$/.test(configuredCliCommand)
      ? configuredCliCommand
      : (() => {
          if (ctx.logger) {
            ctx.logger.warn(
              'codex-security: cliCommand contains invalid characters — refusing it and falling back to the pinned default'
            );
          }
          return 'npx --yes @openai/codex-security@0.1.12';
        })();
  const cliPrefix = cliCommand.split(/\s+/).filter(Boolean);
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
    'info', 'logout', 'scans', 'findings',
    // `export` is intentionally NOT allowlisted by default (gate finding F6):
    // it takes arbitrary file paths with no containment, bypassing the path
    // confinement the dedicated scan/findings/compare tools enforce. An
    // administrator may re-add it via config cliAllowedVerbs.
    // `login` is intentionally NOT allowlisted by default (gate finding 2):
    // it prompts for / accepts credentials, and a prompt-injected command
    // could pass an API key as a shell argument. Authenticate via env vars
    // (OPENAI_API_KEY / CODEX_API_KEY / provider keys) instead; an
    // administrator may re-add `login` via config cliAllowedVerbs.
  ];
  const shell = detectShell(config.shell);

  const bundledDirUrl = new URL('../../bundled/', import.meta.url);
  const bundledDir = fileURLToPath(bundledDirUrl);
  // Load-time integrity check of the bundled payload scripts. FAIL-CLOSED
  // (audit finding F4): a tampered payload (hash mismatch, missing or extra
  // file) must disable the plugin rather than merely warn — otherwise a local
  // attacker could swap the bundled runtime (e.g. the MCP server payload) and
  // have the agent execute it. The tools below verify integrity again when
  // handing out payload paths, but the plugin itself must not load.
  const integrity = verifyPayloadIntegrity(bundledDirUrl);
  if (!integrity.ok) {
    if (ctx.logger) {
      ctx.logger.error(
        `codex-security: bundled payload integrity check FAILED for ${integrity.failures.length} file(s): ` +
          integrity.failures.join(', ') + ' — refusing to enable the plugin (fail-closed). Reinstall the preset to restore the pristine payloads.'
      );
    }
    return;
  }

  const tools = ctx.get('tools');
  if (tools === undefined) return;

  /**
   * Resolve the working directory for a call: explicit arg, else session cwd.
   * A model-supplied `workdir` is treated like any other path argument and
   * must resolve INSIDE the session working directory (canonicalized through
   * symlinks), so a prompt-injected `workdir` such as `~/.ssh` combined with
   * a `.` target cannot bypass target confinement and ship arbitrary host
   * files to the scan provider. file:// and remote URLs are rejected: the
   * workdir must be a local directory.
   */
  function resolveWorkdir(exec, argWorkdir) {
    const sessionCwd = exec.agent?.session?.header?.cwd ?? (typeof process !== 'undefined' ? process.cwd() : '.');
    if (argWorkdir === undefined) return sessionCwd;
    const raw = String(argWorkdir);
    if (raw.length === 0) return sessionCwd;
    if (/^file:\/\//i.test(raw) || /^(https?|ssh|git):\/\//i.test(raw) || /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:/.test(raw)) {
      throw new Error('dsh_security: workdir must be a local directory path (remote or file:// references are not valid working directories)');
    }
    let expanded = raw;
    if (expanded === '~') expanded = homedir();
    else if (expanded.startsWith('~/') || expanded.startsWith('~\\')) expanded = homedir() + expanded.slice(1);
    const sessionRoot = canonicalizePath(resolvePath(sessionCwd));
    const resolved = canonicalizePath(resolvePath(sessionRoot, expanded));
    const keyed = (p) => (typeof process !== 'undefined' && process.platform === 'win32' ? p.toLowerCase() : p);
    const rootKey = keyed(sessionRoot);
    const workdirKey = keyed(resolved);
    if (workdirKey !== rootKey && !workdirKey.startsWith(rootKey + pathSep)) {
      throw new Error(
        `dsh_security: workdir ${JSON.stringify(raw)} resolves outside the session working directory (${sessionRoot}); ` +
        'the scan must run inside the session working directory. To scan another location, pass it as the target ' +
        '(an administrator may set allowTargetsOutsideWorkdir: true to permit outside targets).'
      );
    }
    return resolved;
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
      'Return the absolute paths of the bundled Codex Security payload shipped with this preset (the upstream workflow skills, references, schemas, examples, and Python scripts). Use it to read a workflow skill\'s referenced documents or to run one of the bundled Python scripts (e.g. resolve_security_md.py) with the python tool. Payload integrity is re-verified on every call; if it fails the tool throws and no paths are returned (bundled scripts must not be run).',
    parameters: {
      type: 'object',
      properties: {
        detail: { type: 'boolean', description: 'Also list the bundled directories and skill names (default false: just the root paths).' },
      },
    },
    output,
    async execute(args) {
      // Enforcement (not just reporting): re-verify the payload NOW and refuse
      // to hand out the bundled paths (scripts/skills/references) when the
      // integrity check fails — the model cannot run a script whose path it
      // never received. Catches tampering that happened after plugin load.
      const now = verifyPayloadIntegrity(bundledDirUrl);
      if (!now.ok) {
        throw new Error(
          'codex-security: bundled payload integrity check FAILED (' +
            now.failures.length + ' problem(s): ' + now.failures.join(', ') +
            ') — the bundled scripts are untrusted and must NOT be run. Reinstall the preset to restore the pristine payload.'
        );
      }
      const paths = {
        bundledDir,
        skillsDir: fileURLToPath(new URL('../../bundled/skills/', import.meta.url)),
        referencesDir: fileURLToPath(new URL('../../bundled/references/', import.meta.url)),
        scriptsDir: fileURLToPath(new URL('../../bundled/scripts/', import.meta.url)),
      };
      if (args.detail !== true) {
        return Object.entries(paths).map(([k, v]) => `${k}: ${v}`).join('\n') + '\npayload integrity: OK (verified at call time)';
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
        'payload integrity: OK (verified at call time)',
      ].join('\n');
    },
  });

  // ── dsh_security_scan ──────────────────────────────────────────────────
  register({
    name: 'dsh_security_scan',
    description:
      'Run an OpenAI Codex Security scan on a repository, directory, or scoped path and return the CLI output (progress on stderr, scan results/manifest on stdout). Requires Codex Security authentication: OPENAI_API_KEY/CODEX_API_KEY (or provider keys) via the environment. Path arguments (including workdir) must resolve inside the session working directory (targets outside it are rejected; remote git URLs are allowed). Foreground runs are capped at 5 minutes — set run_in_background: true for anything longer and read it with the job tools.',
    parameters: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Repository or path to scan (defaults to the current working directory). Must resolve inside the working directory unless the plugin config allows outside paths; a remote git URL is allowed.' },
        mode: { type: 'string', enum: ['standard', 'deep'], description: 'standard (default, single pass) or deep (multi-pass discovery).' },
        model: { type: 'string', description: 'Model id, e.g. gpt-5.6-terra or an OpenRouter/Fireworks/Bedrock model.' },
        provider: { type: 'string', enum: ['openai', 'openrouter', 'fireworks', 'amazon-bedrock'], description: 'Inference provider (openai, openrouter, fireworks, amazon-bedrock).' },
        effort: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Scan effort.' },
        workers: { type: 'number', description: 'Number of parallel workers (1–64).' },
        subagents: { type: 'number', description: 'Deep-scan subagents per worker, 0 disables (0–64).' },
        max_time_hours: { type: 'number', description: 'Deep-scan discovery time cap in hours (0.01–96).' },
        stop_after_no_new: { type: 'number', description: 'Deep-scan stop after N discovery runs with no new findings (1–1000).' },
        max_discovery_runs: { type: 'number', description: 'Deep-scan maximum discovery runs (1–1000).' },
        scan_prompt_file: { type: 'string', description: 'Path to a file with shared scan instructions; must resolve inside the working directory.' },
        post_scan_prompt_file: { type: 'string', description: 'Path to a file with post-scan follow-up instructions; must resolve inside the working directory.' },
        knowledge_base: { type: 'array', items: { type: 'string' }, description: 'Security documents to share with the scan (files or directories inside the working directory); repeatable.' },
        auth: { type: 'string', enum: ['api-key'], description: 'Credential selection for interactive scans (only api-key is accepted; chatgpt is intentionally not offered — it would reuse stored ChatGPT credentials).' },
        output_dir: { type: 'string', description: 'Directory for scan results (defaults to the Codex Security scans dir); must resolve inside the working directory when provided.' },
        verbose: { type: 'boolean', description: 'Print scan diagnostics to stderr.' },
        workdir: { type: 'string', description: 'Working directory for the scan (defaults to the session working directory; must resolve inside it).' },
        timeout_ms: { type: 'number', description: 'Foreground timeout in ms (default 300000; integer 1000–86400000). Ignored when run_in_background is true. Values above 300000 require run_in_background: true.' },
        run_in_background: { type: 'boolean', description: 'Start the scan as a background job and return its job id (required for scans longer than 5 minutes).' },
      },
    },
    output,
    async execute(args, exec) {
      const workdir = resolveWorkdir(exec, args.workdir);
      // Runtime validation (F4/F5): the JSON schema only constrains enums; the
      // model is untrusted input, so bound numeric arguments and whitelist the
      // provider before anything is passed to the CLI.
      if (args.provider !== undefined && !PROVIDERS.includes(args.provider)) {
        throw new Error(
          `dsh_security: provider ${JSON.stringify(args.provider)} is not supported ` +
            `(allowed: ${PROVIDERS.join(', ')})`
        );
      }
      const workers = toBoundedInt(args.workers, { min: 1, max: 64, name: 'workers' });
      const subagents = toBoundedInt(args.subagents, { min: 0, max: 64, name: 'subagents' });
      const maxTimeHours = toBoundedNumber(args.max_time_hours, { min: 0.01, max: 96, name: 'max_time_hours' });
      const stopAfterNoNew = toBoundedInt(args.stop_after_no_new, { min: 1, max: 1000, name: 'stop_after_no_new' });
      const maxDiscoveryRuns = toBoundedInt(args.max_discovery_runs, { min: 1, max: 1000, name: 'max_discovery_runs' });
      // Runtime whitelist for enum-like arguments (audit finding 1): the JSON
      // schema only constrains enums, and the model is untrusted input — so
      // whitelist mode/effort/auth the same way provider is, and quote every
      // value before it reaches the shell. Never rely on host-side schema
      // enforcement.
      if (args.mode !== undefined && !SCAN_MODES.includes(args.mode)) {
        throw new Error(
          `dsh_security: mode ${JSON.stringify(args.mode)} is not supported (allowed: ${SCAN_MODES.join(', ')})`
        );
      }
      if (args.effort !== undefined && !SCAN_EFFORTS.includes(args.effort)) {
        throw new Error(
          `dsh_security: effort ${JSON.stringify(args.effort)} is not supported (allowed: ${SCAN_EFFORTS.join(', ')})`
        );
      }
      if (args.auth !== undefined && !AUTH_SELECTIONS.includes(args.auth)) {
        throw new Error(
          `dsh_security: auth ${JSON.stringify(args.auth)} is not supported (allowed: ${AUTH_SELECTIONS.join(', ')})`
        );
      }
      const parts = [...cliPrefix, 'scan'];
      parts.push(quoteArg(resolveTarget(args.target, workdir, allowTargetsOutsideWorkdir), shell));
      if (args.mode) parts.push('--mode', quoteArg(args.mode, shell));
      if (args.model) parts.push('--model', quoteArg(args.model, shell));
      if (args.provider) parts.push('--provider', quoteArg(args.provider, shell));
      if (args.effort) parts.push('--effort', quoteArg(args.effort, shell));
      if (workers !== undefined) parts.push('--workers', String(workers));
      if (subagents !== undefined) parts.push('--subagents', String(subagents));
      if (maxTimeHours !== undefined) parts.push('--max-time-hours', String(maxTimeHours));
      if (stopAfterNoNew !== undefined) parts.push('--stop-after-no-new', String(stopAfterNoNew));
      if (maxDiscoveryRuns !== undefined) parts.push('--max-discovery-runs', String(maxDiscoveryRuns));
      if (args.scan_prompt_file) parts.push('--scan-prompt-file', quoteArg(resolveTarget(args.scan_prompt_file, workdir, allowTargetsOutsideWorkdir), shell));
      if (args.post_scan_prompt_file) parts.push('--post-scan-prompt-file', quoteArg(resolveTarget(args.post_scan_prompt_file, workdir, allowTargetsOutsideWorkdir), shell));
      for (const kb of args.knowledge_base ?? []) {
        parts.push('--knowledge-base', quoteArg(resolveTarget(kb, workdir, allowTargetsOutsideWorkdir), shell));
      }
      if (args.auth) parts.push('--auth', quoteArg(args.auth, shell));
      if (args.output_dir) {
        // Close the TOCTOU window (audit finding 3): containment was checked
        // on a canonicalized path whose missing suffix components might not
        // exist yet; a symlink planted at a missing intermediate component
        // after the check could redirect the CLI's writes outside the working
        // directory. Pre-create the output directory NOW, re-canonicalize the
        // created path, and re-check containment on the canonical result
        // before the CLI ever runs. The residual race (replacing the created
        // dir with a symlink before the CLI writes) is documented in
        // README.md as an accepted limitation.
        const resolvedOut = resolveTarget(args.output_dir, workdir, allowTargetsOutsideWorkdir);
        try {
          mkdirSync(resolvedOut, { recursive: true });
        } catch (e) {
          throw new Error(
            `dsh_security: could not create output_dir ${JSON.stringify(args.output_dir)}: ${e.message}`
          );
        }
        const canonicalOut = canonicalizePath(resolvedOut);
        const outRoot = canonicalizePath(resolvePath(workdir || (typeof process !== 'undefined' ? process.cwd() : '.')));
        const outKey = typeof process !== 'undefined' && process.platform === 'win32' ? canonicalOut.toLowerCase() : canonicalOut;
        const outRootKey = typeof process !== 'undefined' && process.platform === 'win32' ? outRoot.toLowerCase() : outRoot;
        if (!allowTargetsOutsideWorkdir && outKey !== outRootKey && !outKey.startsWith(outRootKey + pathSep)) {
          throw new Error(
            `dsh_security: output_dir ${JSON.stringify(args.output_dir)} resolves outside the working directory (${outRoot}) after creation`
          );
        }
        parts.push('--output-dir', quoteArg(canonicalOut, shell));
      }
      if (args.verbose) parts.push('--verbose');
      const result = await runCli(exec, parts, {
        // Bound the model-supplied timeout (gate finding 3): reject
        // non-integer / out-of-range values instead of passing them through.
        timeoutMs: args.timeout_ms === undefined
          ? scanTimeoutMs
          : toBoundedInt(args.timeout_ms, { min: 1000, max: 86400000, name: 'timeout_ms' }),
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
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory; must resolve inside it).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000; integer 1000–86400000).' },
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
        timeoutMs: args.timeout_ms === undefined
          ? 120000
          : toBoundedInt(args.timeout_ms, { min: 1000, max: 86400000, name: 'timeout_ms' }),
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
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory; must resolve inside it).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000; integer 1000–86400000).' },
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
        timeoutMs: args.timeout_ms === undefined
          ? 120000
          : toBoundedInt(args.timeout_ms, { min: 1000, max: 86400000, name: 'timeout_ms' }),
        workdir: resolveWorkdir(exec, args.workdir),
      });
      return result.text;
    },
  });

  // ── dsh_security_cli ───────────────────────────────────────────────────
  register({
    name: 'dsh_security_cli',
    description:
      'Run an allowlisted @openai/codex-security CLI command (e.g. `logout`, `info`, `scans list`, `scans logs SCAN_ID`, `findings list`, `scans compare`, `--help`). `login` and `export` are NOT allowlisted by default — authenticate with OPENAI_API_KEY/CODEX_API_KEY (or provider keys) via the environment instead. Provide the subcommand and its arguments exactly as the CLI expects, without the leading `codex-security` binary name. Only the top-level verbs in the whitelist are accepted — use the dedicated dsh_security_scan tool for scans (it applies path and timeout policy). Arguments are passed as shell literals; separate them with spaces.',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Full subcommand and arguments, e.g. `info` or `scans logs <scan-id>`. The first token must be an allowlisted verb (`login` is not allowlisted by default).' },
        workdir: { type: 'string', description: 'Working directory (defaults to the session working directory; must resolve inside it).' },
        timeout_ms: { type: 'number', description: 'Timeout in ms (default 120000; integer 1000–86400000); values above 300000 require run_in_background: true.' },
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
      const workdir = resolveWorkdir(exec, args.workdir);
      // Path containment for pass-through tokens (audit finding 2): a token
      // that names a local path (absolute, `~`-prefixed, contains a path
      // separator, or resolves to an existing file/dir under the workdir)
      // must pass the same resolveTarget check as the dedicated tools, so a
      // prompt-injected `findings list /home/user/.ssh` cannot read outside
      // the working directory. Flags and bare identifiers (scan ids, repo
      // names) pass through as shell literals.
      // Flags that TAKE A PATH VALUE (audit finding 3): the token right after
      // a known path-taking flag must go through resolveTarget too — otherwise
      // `scans logs --output-dir out` would pass a bare `out` unchecked, and
      // the CLI could create/write it relative to a base outside the workdir.
      const PATH_VALUE_FLAGS = new Set([
        '--output-dir', '-o', '--scans-dir', '--export-dir', '--knowledge-base', '--scan-prompt-file',
      ]);
      const containToken = (token, nextIsPathValue) => {
        if (nextIsPathValue) return quoteArg(resolveTarget(token, workdir, allowTargetsOutsideWorkdir), shell);
        if (token.startsWith('-')) return quoteArg(token, shell);
        const pathLike =
          token.startsWith('/') ||
          token.startsWith('\\') ||
          token.startsWith('~') ||
          token.includes('/') ||
          token.includes('\\') ||
          /^[A-Za-z]:[\\/]/.test(token) ||
          (() => {
            try {
              realpathSync(resolvePath(workdir, token));
              return true;
            } catch {
              return false;
            }
          })();
        if (!pathLike) return quoteArg(token, shell);
        return quoteArg(resolveTarget(token, workdir, allowTargetsOutsideWorkdir), shell);
      };
      const rest = tokens.slice(1);
      const parts = [...cliPrefix, verb];
      for (let i = 0; i < rest.length; i++) {
        const tok = rest[i];
        const next = rest[i + 1];
        const nextIsPathValue = next !== undefined && PATH_VALUE_FLAGS.has(tok);
        parts.push(containToken(tok, nextIsPathValue));
      }
      const result = await runCli(exec, parts, {
        timeoutMs: args.timeout_ms === undefined
          ? 120000
          : toBoundedInt(args.timeout_ms, { min: 1000, max: 86400000, name: 'timeout_ms' }),
        workdir,
        background: args.run_in_background === true,
      });
      return result.background
        ? `started background job ${result.jobId} (read it with the job_output tool)`
        : result.text;
    },
  });
}
