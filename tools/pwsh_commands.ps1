# Regenerates data/pwsh_commands.tsv: run `pwsh -NoProfile -File tools/pwsh_commands.ps1` from the
# repo root on Windows with PowerShell 7.x and Windows PowerShell 5.1 installed. Read-only apart from
# that one file.
#
# The table follows the shape of Specter's command database (https://github.com/rjmholt/Specter,
# MIT, Specter/CommandDatabase/Sqlite/CommandDatabaseSchema.cs: Platform, Command, Parameter,
# ParameterSetMembership, Alias), flattened into tab-separated rows and generated from this
# machine's shells instead of compatibility profiles, which stop at 7.0. Parameter aliases are kept
# as well, because binding `-ea` or `-lp` needs them.
#
# Each shell runs this file with -Dump, started with -NoProfile from a FileSystem location (so the
# FileSystem provider's dynamic parameters are listed), and reports:
# - every cmdlet and function of the fixed module list below (the modules pwsh 7 ships, plus
#   Microsoft.PowerShell.Core), and the functions it defines at start;
# - every alias;
# - every global variable a fresh session holds, with its ReadOnly/Constant options, and the
#   automatic variables PowerShell overwrites (Specter's list);
# - every approved verb (Get-Verb);
# - the System.IO.File and System.IO.Directory methods that take a path, with its positions.
# Modules this machine added are never read: the list is fixed.
#
# Copyright notice for the derived shape: Copyright (c) Specter Contributors, MIT License.
param([switch]$Dump)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modules = @('Microsoft.PowerShell.Core', 'CimCmdlets', 'Microsoft.PowerShell.Archive',
    'Microsoft.PowerShell.Diagnostics', 'Microsoft.PowerShell.Host', 'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.PSResourceGet', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.ThreadJob',
    'Microsoft.PowerShell.Utility', 'Microsoft.WSMan.Management', 'PackageManagement', 'PowerShellGet',
    'PSDiagnostics', 'PSReadLine')

# Parameters every cmdlet and advanced function binds; listed once per shell, not per command.
$cmdletNames = @([System.Management.Automation.Internal.CommonParameters].GetProperties().Name)
$shouldNames = @([System.Management.Automation.Internal.ShouldProcessParameters].GetProperties().Name)
$commonNames = $cmdletNames + $shouldNames

function Get-TypeName($t) {
    if ($null -eq $t) { return '' }
    if ($t -eq [switch]) { return 'switch' }
    # The short name: a full name carries the runtime's assembly versions, which differ per shell.
    return $t.Name
}

function Get-Sets($p) {
    # set:position:mandatory:pipeline, position -1 for a named-only parameter
    $sets = foreach ($s in $p.ParameterSets.GetEnumerator() | Sort-Object Key) {
        $pos = if ($s.Value.Position -eq [int]::MinValue) { -1 } else { $s.Value.Position }
        $pipe = [int]($s.Value.ValueFromPipeline -or $s.Value.ValueFromPipelineByPropertyName)
        '{0}:{1}:{2}:{3}' -f $s.Key, $pos, [int]$s.Value.IsMandatory, $pipe
    }
    return ($sets -join ';')
}

if ($Dump) {
    Set-Location $env:SystemRoot
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("platform`t$($PSVersionTable.PSEdition)`t$($PSVersionTable.PSVersion)`twindows")
    $seen = @{}
    $add = {
        param($c)
        $name = $c.Name.ToLowerInvariant()
        if ($seen.ContainsKey($name)) { return }
        $seen[$name] = 1
        $module = if ($c.ModuleName) { $c.ModuleName } else { '' }
        $flags = ''
        $params = @()
        if ($null -ne $c.Parameters) {
            $params = @($c.Parameters.Values)
            if (@($params | Where-Object { $cmdletNames -contains $_.Name }).Count -gt 0) { $flags += 'B' }
            if (@($params | Where-Object { $shouldNames -contains $_.Name }).Count -gt 0) { $flags += 'P' }
            if (@($params | Where-Object { $_.Attributes | Where-Object { $_ -is [Parameter] -and $_.ValueFromRemainingArguments } }).Count -gt 0) { $flags += 'R' }
        }
        if ($c.CommandType -eq 'Function' -and -not $c.CmdletBinding) { $flags += 'S' }
        $default = if ($c.PSObject.Properties['DefaultParameterSet'] -and $c.DefaultParameterSet) { $c.DefaultParameterSet } else { '' }
        $out.Add("cmdlet`t$name`t$module`t$($c.CommandType)`t$default`t$flags")
        foreach ($p in $params) {
            if ($commonNames -contains $p.Name) { continue }
            $aliases = (@($p.Aliases) | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ','
            $out.Add("param`t$name`t$($p.Name.ToLowerInvariant())`t$(Get-TypeName $p.ParameterType)`t$([int]$p.IsDynamic)`t$aliases`t$(Get-Sets $p)")
        }
    }
    foreach ($m in $modules) {
        try { Import-Module $m -ErrorAction Stop } catch { }
        foreach ($c in @(Get-Command -Module $m -CommandType Cmdlet, Function -ErrorAction SilentlyContinue)) { & $add $c }
    }
    foreach ($f in @(Get-ChildItem Function:)) { & $add (Get-Command $f.Name) }
    # The common parameters, from one cmdlet that binds them all (Remove-Item supports ShouldProcess).
    $ri = Get-Command Remove-Item
    foreach ($n in $commonNames) {
        $p = $ri.Parameters[$n]
        if ($null -eq $p) { continue }
        $aliases = (@($p.Aliases) | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ','
        $group = if ($shouldNames -contains $n) { 'P' } else { 'B' }
        $out.Add("common`t$($n.ToLowerInvariant())`t$(Get-TypeName $p.ParameterType)`t$aliases`t$group")
    }
    foreach ($a in @(Get-Alias)) {
        $out.Add("aka`t$($a.Name.ToLowerInvariant())`t$($a.ResolvedCommandName.ToLowerInvariant())")
    }
    # Variables PowerShell sets itself and silently overwrites, from Specter's
    # AvoidAssignmentToAutomaticVariable (s_writableAutomaticVariables); most exist only inside a
    # script, a function or an event, so a fresh session does not list them.
    $automatic = @('_', 'AllNodes', 'Args', 'ConsoleFilename', 'Event', 'EventArgs', 'EventSubscriber',
        'ForEach', 'Input', 'Matches', 'MyInvocation', 'NestedPromptLevel', 'Profile',
        'PSBoundParameters', 'PsCmdlet', 'PSCommandPath', 'PSDebugContext', 'PSItem',
        'PSScriptRoot', 'PSSenderInfo', 'Pwd', 'ReportErrorShowExceptionClass',
        'ReportErrorShowInnerException', 'ReportErrorShowSource', 'ReportErrorShowStackTrace',
        'Sender', 'StackTrace', 'This') | ForEach-Object { $_.ToLowerInvariant() }
    $kinds = @{}
    # From a fresh runspace: a script started by -File shares the global scope, so this session
    # would also list the script's own variables.
    $fresh = [powershell]::Create()
    $vars = @($fresh.AddCommand('Get-Variable').Invoke())
    $fresh.Dispose()
    foreach ($v in $vars) {
        $o = [string]$v.Options
        $kinds[$v.Name.ToLowerInvariant()] = if ($o -match 'Constant') { 'constant' } elseif ($o -match 'ReadOnly') { 'readonly' } else { 'writable' }
    }
    foreach ($n in $automatic) {
        if (-not $kinds.ContainsKey($n) -or $kinds[$n] -eq 'writable') { $kinds[$n] = 'automatic' }
    }
    # Variables the session creates on first use, which Get-Variable does not list.
    foreach ($n in 'null', 'lastexitcode') { if (-not $kinds.ContainsKey($n)) { $kinds[$n] = 'writable' } }
    foreach ($k in $kinds.Keys) {
        $kind = if ($kinds[$k] -eq 'writable') { 'session' } else { $kinds[$k] }
        $out.Add("variable`t$k`t$kind")
    }
    foreach ($v in @(Get-Verb)) { $out.Add("verb`t$($v.Verb.ToLowerInvariant())") }
    # .NET calls that resolve a relative path against the process directory: File's whole-file
    # readers and writers and every Directory method, with the argument positions of their path
    # parameters (union over the overloads).
    $pathParam = '^(path|path1|path2|sourceDirName|destDirName|sourceFileName|destFileName)$'
    foreach ($ty in @([System.IO.File], [System.IO.Directory])) {
        $short = "io.$($ty.Name.ToLowerInvariant())"
        foreach ($g in @($ty.GetMethods([System.Reflection.BindingFlags]'Public,Static') | Group-Object Name)) {
            if ($ty -eq [System.IO.File] -and $g.Name -notmatch '^(ReadAll|WriteAll|AppendAll)') { continue }
            $idx = @(@(foreach ($m in $g.Group) {
                $ps = $m.GetParameters()
                for ($i = 0; $i -lt $ps.Count; $i++) {
                    if ($ps[$i].ParameterType -eq [string] -and $ps[$i].Name -match $pathParam) { $i }
                }
            }) | Sort-Object -Unique)
            if ($idx.Count -gt 0) { $out.Add("dotnet`t$short`t$($g.Name.ToLowerInvariant())`t$($idx -join ',')") }
        }
    }
    $out
    return
}

function Read-Dump([string[]]$lines, [string]$tag) {
    $platform = @($lines | Where-Object { $_ -like "platform`t*" })
    $commands = @($lines | Where-Object { $_ -like "cmdlet`t*" })
    $aliases = @($lines | Where-Object { $_ -like "aka`t*" })
    $parameters = @($lines | Where-Object { $_ -like "param`t*" })
    $common = @($lines | Where-Object { $_ -like "common`t*" })
    if ($platform.Count -ne 1 -or $commands.Count -lt 200 -or $aliases.Count -lt 100 -or
        $parameters.Count -lt 1500 -or $common.Count -lt 10) {
        throw "bad dump from $tag ($($commands.Count) commands, $($aliases.Count) aliases, $($parameters.Count) parameters, $($common.Count) common)"
    }
    return $lines
}

# Every row of one shell, keyed by the row without its edition, so a fact both shells hold becomes
# one row with both editions.
function Merge-Rows($core, $desktop) {
    $rows = [System.Collections.Generic.SortedDictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($pair in @(@($core, '7'), @($desktop, '5'))) {
        foreach ($l in $pair[0]) {
            if ($l -like "platform`t*") { continue }
            $kind, $rest = $l -split "`t", 2
            $key = "$kind`t$rest"
            if ($rows.ContainsKey($key)) { $rows[$key] = '75' } else { $rows[$key] = $pair[1] }
        }
    }
    return $rows
}

$self = $MyInvocation.MyCommand.Path
$root = Split-Path (Split-Path $self)
$core = Read-Dump @(& pwsh -NoProfile -File $self -Dump) 'pwsh'
$desktop = Read-Dump @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $self -Dump) 'powershell.exe'
$corePlatform = ($core | Where-Object { $_ -like "platform`t*" }) -replace "^platform`t", ''
$desktopPlatform = ($desktop | Where-Object { $_ -like "platform`t*" }) -replace "^platform`t", ''
$merged = Merge-Rows $core $desktop

$text = New-Object System.Collections.Generic.List[string]
$text.Add('# Generated by `pwsh -NoProfile -File tools/pwsh_commands.ps1`; do not edit.')
$text.Add('# Shape: Specter''s command database (https://github.com/rjmholt/Specter, MIT,')
$text.Add('# Copyright (c) Specter Contributors), flattened; the facts come from this machine''s shells.')
$text.Add('# Row kinds: cmdlet (a cmdlet or function), param, common, aka (an alias), variable, verb, dotnet.')
$text.Add('# Columns are tab-separated; the second column of every fact row is the editions holding it')
$text.Add('# (7 = pwsh, 5 = Windows PowerShell 5.1, 75 = both). Rows sort by kind, then command.')
$text.Add('#   platform <edition key> <PSEdition> <version> <os>')
$text.Add('#   cmdlet <eds> <name> <module> <type> <default set> <flags: B binds the common parameters, P also -WhatIf and -Confirm, R takes remaining arguments, S simple function>')
$text.Add('#   param <eds> <command> <name> <type> <dynamic> <aliases> <set:position:mandatory:pipeline;...>')
$text.Add('#   common <eds> <name> <type> <aliases> <B: every cmdlet, P: only with flag P>')
$text.Add('#   aka <eds> <alias> <command>')
$text.Add('#   variable <eds> <name> <constant|readonly: assigning it fails; automatic: PowerShell overwrites it; session: set by the session>')
$text.Add('#   verb <eds> <verb>')
$text.Add('#   dotnet <eds> <type, io.file or io.directory> <method> <path argument positions>')
$text.Add("platform`t7`t$corePlatform")
$text.Add("platform`t5`t$desktopPlatform")
foreach ($k in $merged.Keys) {
    $kind, $rest = $k -split "`t", 2
    $text.Add("$kind`t$($merged[$k])`t$rest")
}
$target = Join-Path $root 'data/pwsh_commands.tsv'
[IO.File]::WriteAllText($target, (($text -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
$counts = $text | Group-Object { ($_ -split "`t")[0] } | Where-Object Name -notlike '#*' | ForEach-Object { "$($_.Name) $($_.Count)" }
"wrote $target ($($text.Count) lines: $($counts -join ', '))"
