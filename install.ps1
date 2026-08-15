# Install the openai-code-security DSH plugin project:
#   1. agent preset  -> ~/.dsh/.agent-presets/dsh-security (skills + scan tools)
#   2. security gate -> web profile as a pnpm dependency; `dsh.bundle.patch` in
#      gate/package.json makes `dsh plugin add` activate it as a profile bundle
#      layer automatically (no manual cordis.patch.yml row needed).
# Idempotent: re-running replaces the previous copies.
$ErrorActionPreference = 'Stop'

$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$dsh = Join-Path $env:USERPROFILE '.dsh'

# ── 1. agent preset ─────────────────────────────────────────────────────────
$presetDest = Join-Path $dsh '.agent-presets\dsh-security'
Write-Host "Installing dsh-security preset to $presetDest" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $presetDest -Force | Out-Null
Get-ChildItem $src -Force | Where-Object { $_.Name -ne 'gate' -and $_.Name -ne 'install.ps1' -and $_.Name -ne 'install.sh' } |
  ForEach-Object { Copy-Item -Path $_.FullName -Destination $presetDest -Recurse -Force }

# ── 2. security gate into the web profile ───────────────────────────────────
$profileDir = Join-Path $dsh 'profiles\web'
if (Test-Path (Join-Path $profileDir 'package.json')) {
  Write-Host "Installing dsh-security-gate into profile $profileDir" -ForegroundColor Cyan
  Push-Location $profileDir
  try {
    & 'dsh' plugin --profile web add (Join-Path $src 'gate')
    if ($LASTEXITCODE -ne 0) { throw "dsh plugin add failed with exit code $LASTEXITCODE" }
  } finally {
    Pop-Location
  }

  $patch = Join-Path $profileDir 'cordis.patch.yml'
  # Since gate/package.json declares `dsh.bundle.patch`, `dsh plugin add` above
  # already activates the gate as a profile bundle layer — no manual patch row
  # is written anymore. Migrate an existing install: remove the obsolete
  # script-written insert row (exact match only, so a customized row is never
  # silently deleted), because the loader rejects duplicate entry ids and the
  # bundle row would collide with it.
  $content = ''
  if (Test-Path $patch) { $content = Get-Content $patch -Raw -ErrorAction SilentlyContinue }
  if ($null -eq $content) { $content = '' }
  $lines = @($content -split "`r?`n")
  $start = -1
  for ($i = 0; $i -lt $lines.Count - 1; $i++) {
    if ($lines[$i].TrimEnd() -eq '- insert:' -and $lines[$i + 1].TrimEnd() -eq '    - id: dsh-security-gate') {
      $start = $i
      break
    }
  }
  if ($start -ge 0) {
    $end = $start + 1
    while ($end -lt $lines.Count -and $lines[$end].StartsWith('    ')) { $end++ }
    $expected = @(
      '- insert:',
      '    - id: dsh-security-gate',
      '      name: dsh-security-gate',
      '      config:',
      '        scanTimeoutMs: 900000'
    ) -join "`n"
    $block = ($lines[$start..($end - 1)] | ForEach-Object { $_.TrimEnd() }) -join "`n"
    if ($block -eq $expected) {
      $before = if ($start -gt 0) { $lines[0..($start - 1)] } else { @() }
      $after = if ($end -lt $lines.Count) { $lines[$end..($lines.Count - 1)] } else { @() }
      $result = (($before + $after) -join "`n").TrimEnd()
      # If only comments and/or a stale `[]` remain, normalize to a bare `[]`.
      $nonComment = ($result -split "`n" | Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') }) -join "`n"
      if ($nonComment.Trim() -eq '' -or $nonComment.Trim() -eq '[]') {
        $comments = ($result -split "`n" | Where-Object { $_.TrimStart().StartsWith('#') }) -join "`n"
        $value = if ($comments.Trim() -ne '') { $comments + "`n[]" } else { '[]' }
        Set-Content -Path $patch -Value $value -Encoding UTF8
      } else {
        Set-Content -Path $patch -Value ($result + "`n") -Encoding UTF8
      }
      Write-Host "removed obsolete dsh-security-gate row from $patch (the bundle now activates it)" -ForegroundColor Green
    } else {
      Write-Host "cordis.patch.yml has a customized dsh-security-gate row — remove it manually; the bundle now activates the gate. Re-express any custom config as an id-targeted override (see gate/README.md)." -ForegroundColor Yellow
    }
  }
} else {
  Write-Host 'web profile not found — skip gate install (preset installed only).' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Done. Next steps:' -ForegroundColor Green
Write-Host '  1. Restart dsh web so the gate loads (composition changes apply at boot).'
Write-Host '  2. New DSH session -> pick the "安全审计模式" preset (id: dsh-security) for skills + model-based audits.'
Write-Host '  3. The gate auto-audits newly installed plugins with the harness model (no auth); watch <DSH_HOME>/dsh-security/summary.json.'
Write-Host '  4. Optional: for OpenAI Codex Security CLI scans, run `npx @openai/codex-security login` (or set OPENAI_API_KEY).'
