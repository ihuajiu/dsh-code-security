#!/usr/bin/env bash
# Install the openai-code-security DSH plugin project:
#   1. agent preset  -> ~/.dsh/.agent-presets/dsh-security (skills + scan tools)
#   2. security gate -> <profile> as a pnpm dependency + a cordis.patch.yml row
# Idempotent: re-running replaces the previous copies.
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
dsh="${DSH_HOME:-$HOME/.dsh}"
profile="${1:-web}"

# ── 1. agent preset ─────────────────────────────────────────────────────────
preset_dest="$dsh/.agent-presets/dsh-security"
echo "Installing dsh-security preset to $preset_dest"
mkdir -p "$preset_dest"
for item in "$src"/*; do
  case "$(basename "$item")" in
    gate|install.sh|install.ps1) ;;
    *) cp -R "$item" "$preset_dest"/ ;;
  esac
done

# ── 2. security gate into the profile ───────────────────────────────────────
profile_dir="$dsh/profiles/$profile"
if [ -f "$profile_dir/package.json" ]; then
  echo "Installing dsh-security-gate into profile $profile_dir"
  (cd "$profile_dir" && dsh plugin --profile "$profile" add "$src/gate")
  patch="$profile_dir/cordis.patch.yml"
  if grep -q 'dsh-security-gate' "$patch" 2>/dev/null; then
    echo "gate row already present in cordis.patch.yml"
  elif [ "$(tr -d '[:space:]' < "$patch" 2>/dev/null)" = "[]" ] || [ ! -s "$patch" ]; then
    printf '%s\n' \
      '- insert:' \
      '    - id: dsh-security-gate' \
      '      name: dsh-security-gate' \
      '      config:' \
      '        scanTimeoutMs: 900000' > "$patch"
    echo "wrote gate row to $patch"
  else
    printf '%s\n' \
      '- insert:' \
      '    - id: dsh-security-gate' \
      '      name: dsh-security-gate' \
      '      config:' \
      '        scanTimeoutMs: 900000' >> "$patch"
    echo "appended gate row to $patch"
  fi
else
  echo "profile '$profile' not found — gate install skipped (preset installed only)."
fi

echo
echo 'Done. Next steps:'
echo '  1. Restart dsh web so the gate loads (composition changes apply at boot).'
echo '  2. New DSH session -> pick the "安全审计模式" preset (id: dsh-security) for skills + model-based audits.'
echo "  3. The gate auto-audits newly installed plugins with the harness model (no auth); watch $dsh/dsh-security/summary.json."
echo '  4. Optional: for OpenAI Codex Security CLI scans, run `npx @openai/codex-security login` (or set OPENAI_API_KEY).'
