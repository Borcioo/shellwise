<#
.SYNOPSIS
  The repo gate: every leg must pass. Last line: `GATE PASS <n> tests` or `GATE FAIL <leg>`.

.DESCRIPTION
  Legs, in order: fmt, clippy, test-windows (cargo test --features oracle,testhooks),
  test-wsl (cargo test --features testhooks in WSL Ubuntu through the login shell from getent passwd, run as `<shell> -lic`, target dir under
  the WSL home, one per worktree; installs rustup with its official installer when cargo is missing there), deny,
  leak (python -I scripts/leak_check.py; needs SHELLWISE_CORPUS and SHELLWISE_DENYLIST).
  A test leg passes only with a count above 0. Logs go to target/gate/<leg>.log.

  The `testhooks` feature (test-only rules that panic or sleep) is on in both test legs and clippy
  runs with --all-features, so the fail-closed tests always run in the gate; plain `cargo test`
  skips them. The leak leg's corpus match checks only tests/cases commands of 40+ characters or
  with a path separator.
#>
param(
    [string]$Distro = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root 'target/gate'
New-Item -ItemType Directory -Force $logDir | Out-Null
Set-Location $root

function Invoke-Leg {
    param([string]$Name, [scriptblock]$Run)
    $log = Join-Path $logDir "$Name.log"
    $ErrorActionPreference = 'Continue'
    $out = & $Run 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    [IO.File]::WriteAllText($log, (($out | Out-String) -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{ Name = $Name; Code = $code; Out = @($out); Log = $log }
}

function Get-TestCount {
    param([string[]]$Lines)
    $passed = 0
    $failed = 0
    foreach ($l in $Lines) {
        if ($l -match 'test result: \w+\. (\d+) passed; (\d+) failed') {
            $passed += [int]$Matches[1]
            $failed += [int]$Matches[2]
        }
    }
    return [pscustomobject]@{ Passed = $passed; Failed = $failed }
}

function Stop-Gate {
    param([string]$Leg, [object]$Result)
    if ($Result) {
        $Result.Out | Select-Object -Last 40 | ForEach-Object { Write-Host $_ }
        Write-Host "log: $($Result.Log)"
    }
    Write-Host "GATE FAIL $Leg"
    exit 1
}

function Assert-Leg {
    param([object]$Result)
    if ($Result.Code -ne 0) { Stop-Gate $Result.Name $Result }
    Write-Host "LEG $($Result.Name) PASS"
}

function Assert-TestLeg {
    param([object]$Result)
    $count = Get-TestCount $Result.Out
    if ($Result.Code -ne 0 -or $count.Failed -ne 0 -or $count.Passed -eq 0) { Stop-Gate $Result.Name $Result }
    Write-Host "LEG $($Result.Name) PASS $($count.Passed) tests"
    return $count.Passed
}

$total = 0

Assert-Leg (Invoke-Leg 'fmt' { cargo fmt --check })
Assert-Leg (Invoke-Leg 'clippy' { cargo clippy --all-targets --all-features -- -D warnings })
$total += Assert-TestLeg (Invoke-Leg 'test-windows' { cargo test --features oracle,testhooks })

$drive = $root.Substring(0, 1).ToLower()
$wslRoot = "/mnt/$drive/" + ($root.Substring(3) -replace '\\', '/')
$wslScript = @'
set -e
# zsh does not load ~/.cargo/env; source it whatever the login shell is.
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "gate: cargo missing in WSL; installing rustup with its official installer"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  . "$HOME/.cargo/env"
  echo "gate: installed $(cargo --version)"
fi
if [ -z "$1" ] || [ ! -f "$1/Cargo.toml" ]; then echo "gate: no crate root at $1"; exit 2; fi
cd "$1"
# One target dir per worktree: in a shared one cargo reuses the build of a sibling worktree as fresh.
tree=$(basename "$PWD")
export CARGO_TARGET_DIR="$HOME/.cache/shellwise-gate/$tree/target"
cargo --version
cargo test --features testhooks
'@ -replace "`r`n", "`n"
# The user's login shell, as `getent passwd` names it (bash, zsh, ...), interactive so its rc runs.
$wslShell = (wsl.exe -d $Distro -- sh -c 'getent passwd "$(id -un)" | cut -d: -f7' | Out-String).Trim()
if (-not $wslShell) { Stop-Gate 'test-wsl (no login shell from getent)' $null }
Write-Host "LEG test-wsl shell $wslShell"
$total += Assert-TestLeg (Invoke-Leg 'test-wsl' { wsl.exe -d $Distro --exec $wslShell -lic $wslScript gate $wslRoot })

Assert-Leg (Invoke-Leg 'deny' { cargo deny check })

$leak = Invoke-Leg 'leak' { python -I scripts/leak_check.py }
if ($leak.Code -ne 0 -or -not ($leak.Out -match '^leak_check: PASS files=[1-9]')) { Stop-Gate 'leak' $leak }
Write-Host "LEG leak $(($leak.Out -match '^leak_check: PASS') -replace '^leak_check: ', '')"

Write-Host "GATE PASS $total tests"
exit 0
