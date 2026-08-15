#!/usr/bin/env bash
# Uninstall the openai-code-security DSH plugin project (dsh-code-security):
#   1. dsh-security-gate — removed from EVERY profile: `dsh plugin remove` for
#      the current scoped name plus legacy names, orphan node_modules symlinks,
#      any stale manual cordis.patch.yml row, and a defensive strip from the
#      profile bundle list.
#   2. dsh-security agent preset  -> $DSH_HOME/.agent-presets/dsh-security
#   3. gate state/reports         -> $DSH_HOME/dsh-security
#   4. online-install cache clone -> $DSH_HOME/cache/dsh-code-security
# Idempotent: re-running is safe; anything already gone is skipped. Cleanup
# continues past errors (no set -e).
set -u

dsh="${DSH_HOME:-$HOME/.dsh}"
names='@dsh.so/dsh-security-gate dsh-security-gate openai-code-security-gate'

# node is always present (DSH runs on it) — use it for exact manifest reads.
has_dep() { node -e 'const fs=require("fs"),j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write((j.dependencies&&j.dependencies[process.argv[2]])?"1":"0")' "$1" "$2" 2>/dev/null; }

# ── 1. gate plugin from every profile ───────────────────────────────────────
if [ -d "$dsh/profiles" ]; then
  for profile_dir in "$dsh"/profiles/*/; do
    [ -d "$profile_dir" ] || continue
    manifest="$profile_dir/package.json"
    [ -f "$manifest" ] || continue
    profile_name="$(basename "$profile_dir")"

    for name in $names; do
      if [ "$(has_dep "$manifest" "$name")" = "1" ]; then
        echo "Removing $name from profile $profile_name"
        ( cd "$profile_dir" && dsh plugin --profile "$profile_name" remove "$name" ) \
          || echo "  dsh plugin remove failed — continuing with direct cleanup" >&2
      fi
      # orphan symlink/junction in node_modules (leftovers from earlier installs)
      if [ -e "$profile_dir/node_modules/$name" ] || [ -L "$profile_dir/node_modules/$name" ]; then
        rm -rf "$profile_dir/node_modules/$name"
        echo "  removed orphan $profile_dir/node_modules/$name"
      fi
    done

    # defensive pass: `dsh plugin remove` may have failed (e.g. pnpm missing) —
    # drop any of our names still lingering in dependencies or bundles.
    node -e '
      const fs=require("fs"), p=process.argv[1], names=process.argv.slice(2);
      const j=JSON.parse(fs.readFileSync(p,"utf8")); let changed=false;
      if(j.dependencies){ for(const n of names){ if(j.dependencies[n]!==undefined){ delete j.dependencies[n]; changed=true; } }
        if(Object.keys(j.dependencies).length===0){ delete j.dependencies; changed=true; } }
      if(Array.isArray(j.dsh&&j.dsh.profile&&j.dsh.profile.bundles)){
        const b=j.dsh.profile.bundles.filter(x=>!names.includes(x));
        if(b.length!==j.dsh.profile.bundles.length){ j.dsh.profile.bundles=b; changed=true; } }
      if(changed) fs.writeFileSync(p, JSON.stringify(j,null,2)+"\n");
    ' "$manifest" $names 2>/dev/null || true

    # remove the legacy manual insert row from cordis.patch.yml, if present
    patch="$profile_dir/cordis.patch.yml"
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
          comments=$(sed -n '/^[[:space:]]*#/p' "$patch")
          body=$(sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$patch" | tr -d '[:space:]')
          if [ -z "$body" ] || [ "$body" = "[]" ]; then
            if [ -n "$comments" ]; then printf '%s\n' "$comments" '[]' > "$patch"; else printf '[]\n' > "$patch"; fi
          fi
          echo "  removed legacy dsh-security-gate row from $patch"
        else
          echo "  cordis.patch.yml has a customized dsh-security-gate row — remove it manually" >&2
        fi
      fi
    fi
  done
else
  echo "no profiles directory — nothing to clean for the gate plugin"
fi

# ── 2. agent preset ─────────────────────────────────────────────────────────
if [ -d "$dsh/.agent-presets/dsh-security" ]; then
  rm -rf "$dsh/.agent-presets/dsh-security"
  echo "Removed agent preset $dsh/.agent-presets/dsh-security"
fi

# ── 3. gate state/reports + online-install cache ────────────────────────────
for p in "$dsh/dsh-security" "$dsh/cache/dsh-code-security"; do
  if [ -e "$p" ]; then
    rm -rf "$p"
    echo "Removed $p"
  fi
done

echo
echo 'Done. dsh-code-security (preset + gate + state/cache) is uninstalled.'
echo 'Restart dsh web for the changes to take effect.'
