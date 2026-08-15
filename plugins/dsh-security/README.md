# @dsh.so/dsh-security-tools

DSH agent-preset plugin wrapping the [@openai/codex-security](https://www.npmjs.com/package/@openai/codex-security)
CLI. Registers five `dsh_security_*` model tools:

- `dsh_security_resources` — integrity-verified paths of the bundled Codex Security payload
- `dsh_security_scan` — run a repository security scan (path/timeout policy enforced)
- `dsh_security_findings` — list findings from saved scans
- `dsh_security_scans_compare` — compare two scans by id
- `dsh_security_cli` — allowlisted passthrough to the CLI (scans excluded; `login`/`export` not allowlisted by default)

## Security properties

- Shell-literal argument quoting (no injection).
- Path confinement: scan/findings paths must resolve inside the session working directory (canonicalized through symlinks).
- `cliCommand` allowlisted and version-pinned; invalid values fall back to the pinned default.
- Bundled payload (skills/references/schemas/examples/scripts/MCP runtime) is SHA-256 integrity-checked at load time (fail-closed) and re-verified when paths are handed out.

## Layout

The bundled payload ships inside this package under `bundled/` and is also resolved
from `<preset>/bundled/` for the agent-preset installation layout.

## License

Apache-2.0 · © 2026 dsh.so
