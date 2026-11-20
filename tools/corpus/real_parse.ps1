<#
.SYNOPSIS
What the real shells' parsers say of each corpus row: the oracle behind `shellwise bench --real-parse`.

.DESCRIPTION
PowerShell rows go through pwsh's own parser ([Parser]::ParseInput, in process); Bash rows through
`bash -n` of Git Bash (bin\bash.exe, never the WSL bash.exe on PATH), one process per row. Nothing
is run. Writes a TSV with a header: id, refused (yes or no), the first error id (pwsh's ErrorId,
which is not localised; for bash the first stderr line without its "<file>: line <n>: " prefix).

Known-answer controls run first, as synthetic text, and any wrong answer stops the script: a pwsh
unterminated string (refused, TerminatorExpectedAtEndOfString), a pwsh empty pipe element (refused,
EmptyPipeElement), a plain git command in pwsh (accepted), a bash backtick left open (refused) and a
plain bash echo (accepted). Exits 1 on a failed control, on 0 rows read or on 0 rows written.

.PARAMETER Corpus
The corpus.jsonl extract.py writes.

.PARAMETER Out
The TSV to write.

.PARAMETER Ids
Optional: only these rows. A file whose first column is a row id; a `shellwise bench --dump` file
(header `id<TAB>level...`) gives only its rows at break, danger or critical.

.PARAMETER Bash
Git Bash's bash.exe; default: bin\bash.exe under Git's install folder.

.PARAMETER SelfTest
Run the controls only.

.EXAMPLE
pwsh -NoProfile -File tools/corpus/real_parse.ps1 -Corpus "$env:SHELLWISE_CORPUS/corpus.jsonl" -Ids <dump.tsv> -Out <real_parse.tsv>
#>
[CmdletBinding()]
param(
    [string]$Corpus,
    [string]$Out,
    [string]$Ids,
    [string]$Bash = (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$utf8 = [Text.UTF8Encoding]::new($false)

if (-not (Test-Path -LiteralPath $Bash -PathType Leaf)) {
    Write-Output "FAIL: Git Bash not found at $Bash (pass -Bash)"
    exit 1
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('shellwise-real-parse-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$script = Join-Path $work 'row.sh'

function Test-Pwsh([string]$text) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        return [pscustomobject]@{ Refused = $true; ErrorId = [string]$errors[0].ErrorId }
    }
    return [pscustomobject]@{ Refused = $false; ErrorId = '' }
}

function Test-Bash([string]$text) {
    [IO.File]::WriteAllText($script, $text, $utf8)
    $lines = @(& $Bash -n $script 2>&1 | ForEach-Object { [string]$_ })
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        return [pscustomobject]@{ Refused = $false; ErrorId = '' }
    }
    $first = if ($lines.Count -gt 0) { $lines[0] } else { "exit $code" }
    $first = $first -replace '^.*?: line \d+: ', ''
    return [pscustomobject]@{ Refused = $true; ErrorId = $first }
}

function Get-Answer([string]$tool, [string]$text) {
    switch ($tool) {
        'PowerShell' { return Test-Pwsh $text }
        'Bash' { return Test-Bash $text }
        default { return $null }
    }
}

function Invoke-Controls {
    $dq = [string][char]0x22
    $bt = [string][char]0x60
    $controls = @(
        @{ Tool = 'PowerShell'; Text = 'Write-Output ' + $dq + 'abc'; Refused = $true; ErrorId = 'TerminatorExpectedAtEndOfString' },
        @{ Tool = 'PowerShell'; Text = 'Get-Date | | Out-Host'; Refused = $true; ErrorId = 'EmptyPipeElement' },
        @{ Tool = 'PowerShell'; Text = 'git status'; Refused = $false; ErrorId = '' },
        @{ Tool = 'Bash'; Text = 'echo ' + $bt + 'date'; Refused = $true; ErrorId = $null },
        @{ Tool = 'Bash'; Text = 'echo hi'; Refused = $false; ErrorId = '' }
    )
    $wrong = 0
    foreach ($c in $controls) {
        $a = Get-Answer $c.Tool $c.Text
        $idOk = ($null -eq $c.ErrorId) -or ($a.ErrorId -eq $c.ErrorId)
        if ($a.Refused -ne $c.Refused -or -not $idOk) {
            Write-Host ("FAIL: control {0} {1}: refused {2} ({3}), want {4} ({5})" -f $c.Tool, $c.Text, $a.Refused, $a.ErrorId, $c.Refused, $c.ErrorId)
            $wrong++
        }
    }
    Write-Host ("controls: {0} of {1} right" -f ($controls.Count - $wrong), $controls.Count)
    return $wrong
}

try {
    $wrong = Invoke-Controls
    if ($wrong -ne 0) { exit 1 }
    if ($SelfTest) { exit 0 }
    if (-not $Corpus -or -not $Out) {
        Write-Output 'FAIL: pass -Corpus and -Out (or -SelfTest)'
        exit 1
    }
    $Corpus = [IO.Path]::GetFullPath($Corpus, (Get-Location).Path)
    $Out = [IO.Path]::GetFullPath($Out, (Get-Location).Path)

    $only = $null
    if ($Ids) {
        $Ids = [IO.Path]::GetFullPath($Ids, (Get-Location).Path)
        $only = [Collections.Generic.HashSet[string]]::new()
        $isDump = $false
        $n = 0
        foreach ($line in [IO.File]::ReadLines($Ids, $utf8)) {
            $n++
            $cols = $line.TrimEnd("`r").Split("`t")
            if ($n -eq 1 -and $cols[0] -eq 'id') {
                $isDump = $cols.Count -ge 2 -and $cols[1] -eq 'level'
                continue
            }
            if ($cols[0] -eq '') { continue }
            if ($isDump -and $cols[1] -notin @('break', 'danger', 'critical')) { continue }
            [void]$only.Add($cols[0])
        }
    }

    $tsv = [Text.StringBuilder]::new()
    [void]$tsv.Append("id`trefused`terror_id`n")
    $read = 0
    $written = 0
    $other = 0
    foreach ($line in [IO.File]::ReadLines($Corpus, $utf8)) {
        if ($line.Trim() -eq '') { continue }
        $row = $line | ConvertFrom-Json
        $read++
        if ($null -ne $only -and -not $only.Contains([string]$row.id)) { continue }
        $a = Get-Answer ([string]$row.tool) ([string]$row.command)
        if ($null -eq $a) { $other++; continue }
        $id = ($a.ErrorId -replace '[\t\r\n]', ' ')
        $refused = if ($a.Refused) { 'yes' } else { 'no' }
        [void]$tsv.Append("$($row.id)`t$refused`t$id`n")
        $written++
    }
    if ($read -eq 0) {
        Write-Output "FAIL: 0 rows read from $Corpus"
        exit 1
    }
    if ($written -eq 0) {
        Write-Output "FAIL: 0 rows written ($read read; -Ids kept none)"
        exit 1
    }
    [IO.File]::WriteAllText($Out, $tsv.ToString(), $utf8)
    Write-Output ("rows: {0} read, {1} written, {2} of another tool" -f $read, $written, $other)
    exit 0
}
finally {
    [IO.Directory]::Delete($work, $true)
}
