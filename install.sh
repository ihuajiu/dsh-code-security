#!/usr/bin/env bash
# Install the openai-code-security DSH plugin project:
#   1. agent preset  -> ~/.dsh/.agent-presets/dsh-security (skills + scan tools)
#   2. security gate -> <profile> as a pnpm dependency; `dsh.bundle.patch` in
#      gate/package.json makes `dsh plugin add` activate it as a profile bundle
#      layer automatically (no manual cordis.patch.yml row needed).
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
  # Since gate/package.json declares `dsh.bundle.patch`, `dsh plugin add` above
  # already activates the gate as a profile bundle layer — no manual patch row
  # is written anymore. Migrate an existing install: remove the obsolete
  # script-written insert row (exact match only, so a customized row is never
  # silently deleted), because the loader rejects duplicate entry ids and the
  # bundle row would collide with it.
  if [ -f "$patch" ]; then
    expected=$'- insert:\n    - id: dsh-security-gate\n      name: dsh-security-gate\n      config:\n        scanTimeoutMs: 900000'
    matches=$(mktemp)
    grep -n '^- insert:$' "$patch" 2>/dev/null > "$matches" || true
    start=""
    while IFS= read -r line <&3; do
      num=${line%%:*}
      rest=${line#*:}
      [ "$rest" = "- insert:" ] || continue
      next=$((num + 1))
      nextline=$(sed -n "${next}p" "$patch")
      case "$nextline" in
        '    - id: dsh-security-gate'*) start="$num"; break ;;
      esac
    done 3< "$matches"
    rm -f "$matches"
    if [ -n "$start" ]; then
      end=$((start + 1))
      total=$(wc -l < "$patch")
      while [ "$end" -le "$total" ]; do
        line=$(sed -n "${end}p" "$patch")
        case "$line" in
          '    '*) end=$((end + 1)) ;;
          *) break ;;
        esac
      done
      end=$((end - 1))
      block=$(sed -n "${start},${end}p" "$patch" | sed 's/[[:space:]]*$//')
      if [ "$block" = "$expected" ]; then
        sed -i.bak "${start},${end}d" "$patch"
        rm -f "$patch.bak"
        # If only comments and/or a stale `[]` remain, normalize to a bare
        # `[]` (preserving any template comments).
        comments=$(sed -n '/^[[:space:]]*#/p' "$patch")
        body=$(sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$patch" | tr -d '[:space:]')
        if [ -z "$body" ] || [ "$body" = "[]" ]; then
          if [ -n "$comments" ]; then
            printf '%s\n' "$comments" '[]' > "$patch"
          else
            printf '[]\n' > "$patch"
          fi
        fi
        echo "removed obsolete dsh-security-gate row from $patch (the bundle now activates it)"
      else
        echo "cordis.patch.yml has a customized dsh-security-gate row — remove it manually; the bundle now activates the gate. Re-express custom config as an id-targeted override (see gate/README.md)." >&2
      fi
    fi
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
