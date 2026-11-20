<#
.SYNOPSIS
Regenerate the vendored PowerShell grammar and record its hashes.

.DESCRIPTION
Runs the pinned `tree-sitter generate` (QuickJS runtime, no Node needed) in
vendor/tree-sitter-powershell, then writes vendor/tree-sitter-powershell/GENERATED with the
SHA-256 of grammar.js and src/grammar.json and the CLI version. With -Check it only compares the
recorded hashes with the files and exits 1 when they differ (grammar.js edited without a
regeneration). Install the CLI with:
    cargo install tree-sitter-cli --version 0.27.2 --locked
#>
param([switch]$Check)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$cliVersion = '0.27.2'
$fork = Join-Path $PSScriptRoot '..\vendor\tree-sitter-powershell' | Resolve-Path | Select-Object -ExpandProperty Path
$generated = Join-Path $fork 'GENERATED'

function Get-Sha256([string]$relative) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $fork $relative)).Hash.ToLowerInvariant()
}

function Get-Record {
    "grammar.js sha256 $(Get-Sha256 'grammar.js')`nsrc/grammar.json sha256 $(Get-Sha256 'src/grammar.json')`ntree-sitter-cli $cliVersion`n"
}

if ($Check) {
    $want = [IO.File]::ReadAllText($generated)
    $have = Get-Record
    if ($want -ne $have) {
        [Console]::Error.WriteLine("GENERATED is stale:`n--- recorded`n$want--- files`n$have")
        exit 1
    }
    'GENERATED matches'
    exit 0
}

$version = (& tree-sitter --version) -replace '^tree-sitter\s+', ''
if ($version.Trim() -ne $cliVersion) {
    throw "tree-sitter-cli $cliVersion is pinned, found '$version'"
}
Push-Location -LiteralPath $fork
try {
    & tree-sitter generate --js-runtime native
    if ($LASTEXITCODE -ne 0) { throw "tree-sitter generate exited $LASTEXITCODE" }
} finally {
    Pop-Location
}
[IO.File]::WriteAllText($generated, (Get-Record), [Text.UTF8Encoding]::new($false))
Get-Content -LiteralPath $generated
