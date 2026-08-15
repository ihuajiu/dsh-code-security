# Uninstall the openai-code-security DSH plugin project (dsh-code-security):
#   1. dsh-security-gate — removed from EVERY profile: `dsh plugin remove` for
#      the current scoped name plus legacy names, orphan node_modules junctions,
#      any stale manual cordis.patch.yml row, and a defensive strip from the
#      profile bundle list.
#   2. dsh-security agent preset  -> ~/.dsh/.agent-presets/dsh-security
#   3. gate state/reports         -> ~/.dsh/dsh-security
#   4. online-install cache clone -> ~/.dsh/cache/dsh-code-security
# Idempotent: re-running is safe; anything already gone is skipped. Never fails
# on a missing piece (cleanup continues past errors).
$ErrorActionPreference = 'Continue'

$dsh = Join-Path $env:USERPROFILE '.dsh'
$names = @('@dsh.so/dsh-security-gate', 'dsh-security-gate', 'openai-code-security-gate')

# ── 1. gate plugin from every profile ───────────────────────────────────────
$profilesDir = Join-Path $dsh 'profiles'
if (Test-Path $profilesDir) {
  foreach ($profile in (Get-ChildItem $profilesDir -Directory)) {
    $profileDir = $profile.FullName
    $manifest = Join-Path $profileDir 'package.json'
    if (-not (Test-Path $manifest)) { continue }
    $j = $null
    try { $j = Get-Content $manifest -Raw | ConvertFrom-Json } catch { $j = $null }
    if ($null -eq $j) { continue }
    $deps = @($j.dependencies.PSObject.Properties.Name)
    $bundles = @($j.dsh.profile.bundles)

    foreach ($name in $names) {
      if ($deps -contains $name) {
        Write-Host "Removing $name from profile $($profile.Name)" -ForegroundColor Cyan
        Push-Location $profileDir
        try {
          & 'dsh' plugin --profile $profile.Name remove $name
          if ($LASTEXITCODE -ne 0) {
            Write-Host "  dsh plugin remove exited $LASTEXITCODE — continuing with direct cleanup" -ForegroundColor Yellow
          }
        } catch {
          Write-Host "  dsh plugin remove failed: $($_.Exception.Message)" -ForegroundColor Yellow
        } finally {
          Pop-Location
        }
      }
      # orphan junction in node_modules (leftovers from earlier installs)
      $nm = Join-Path $profileDir ("node_modules\" + $name)
      if (Test-Path $nm) {
        Remove-Item $nm -Recurse -Force
        Write-Host "  removed orphan $nm" -ForegroundColor Gray
      }
    }

    # defensive pass: `dsh plugin remove` may have failed (e.g. pnpm missing) —
    # re-read the manifest and drop any of our names still lingering in
    # dependencies or bundles directly.
    $j = $null
    try { $j = Get-Content $manifest -Raw | ConvertFrom-Json } catch { $j = $null }
    if ($null -ne $j) {
      $changed = $false
      if ($null -ne $j.dependencies) {
        foreach ($n in $names) {
          if (@($j.dependencies.PSObject.Properties.Name) -contains $n) {
            $j.dependencies.PSObject.Properties.Remove($n)
            $changed = $true
          }
        }
        if (@($j.dependencies.PSObject.Properties.Name).Count -eq 0 -and $j.PSObject.Properties['dependencies']) {
          $j.PSObject.Properties.Remove('dependencies')
          $changed = $true
        }
      }
      $bundles = @($j.dsh.profile.bundles)
      $still = @($bundles | Where-Object { $names -contains $_ })
      if ($still.Count -gt 0) {
        $j.dsh.profile.bundles = @($bundles | Where-Object { $names -notcontains $_ })
        $changed = $true
      }
      if ($changed) {
        try {
          Set-Content -Path $manifest -Value ($j | ConvertTo-Json -Depth 20) -Encoding UTF8
          Write-Host "  cleaned $manifest (leftover dsh-security-gate dependency/bundle entries removed)" -ForegroundColor Gray
        } catch {
          Write-Host "  could not update $manifest — remove the leftover entries manually" -ForegroundColor Yellow
        }
      }
    }

    # remove the legacy manual insert row from cordis.patch.yml, if present
    $patch = Join-Path $profileDir 'cordis.patch.yml'
    if (Test-Path $patch) {
      $content = Get-Content $patch -Raw -ErrorAction SilentlyContinue
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
          if ($result -eq '' -or $result -eq '[]') {
            Set-Content -Path $patch -Value '[]' -Encoding UTF8
          } else {
            Set-Content -Path $patch -Value ($result + "`n") -Encoding UTF8
          }
          Write-Host "  removed legacy dsh-security-gate row from $patch" -ForegroundColor Gray
        } else {
          Write-Host "  cordis.patch.yml has a customized dsh-security-gate row — remove it manually" -ForegroundColor Yellow
        }
      }
    }
  }
} else {
  Write-Host 'no profiles directory — nothing to clean for the gate plugin' -ForegroundColor Gray
}

# ── 2. agent preset ─────────────────────────────────────────────────────────
$preset = Join-Path $dsh '.agent-presets\dsh-security'
if (Test-Path $preset) {
  Remove-Item $preset -Recurse -Force
  Write-Host "Removed agent preset $preset" -ForegroundColor Green
}

# ── 3. gate state/reports + online-install cache ────────────────────────────
foreach ($p in @((Join-Path $dsh 'dsh-security'), (Join-Path $dsh 'cache\dsh-code-security'))) {
  if (Test-Path $p) {
    Remove-Item $p -Recurse -Force
    Write-Host "Removed $p" -ForegroundColor Green
  }
}

Write-Host ''
Write-Host 'Done. dsh-code-security (preset + gate + state/cache) is uninstalled.'
Write-Host 'Restart dsh web for the changes to take effect.'
