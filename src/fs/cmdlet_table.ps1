# Regenerates cmdlet_table.rs: run `pwsh -NoProfile -File src/fs/cmdlet_table.ps1` from the repo
# root on Windows with pwsh 7.7 and Windows PowerShell 5.1 installed. Each shell, started with
# -NoProfile, lists every cmdlet and function of Microsoft.PowerShell.Core and of the modules
# pwsh 7.7 ships in $PSHOME\Modules, the functions it defines at start, and every alias.
param([switch]$Dump)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modules = @('Microsoft.PowerShell.Core', 'CimCmdlets', 'Microsoft.PowerShell.Archive',
    'Microsoft.PowerShell.Diagnostics', 'Microsoft.PowerShell.Host', 'Microsoft.PowerShell.Management',
    'Microsoft.PowerShell.PSResourceGet', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.ThreadJob',
    'Microsoft.PowerShell.Utility', 'Microsoft.WSMan.Management', 'PackageManagement', 'PowerShellGet',
    'PSDiagnostics', 'PSReadLine')

if ($Dump) {
    # One line per command (`C<TAB>name<TAB>1` when it has a ScriptBlock-typed parameter, else 0)
    # and per alias (`A<TAB>alias<TAB>command`), after a version line.
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("V`t$($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)")
    $seen = @{}
    $add = {
        param($c)
        if ($seen.ContainsKey($c.Name)) { return }
        $seen[$c.Name] = 1
        $sb = 0
        if ($null -ne $c.Parameters) {
            foreach ($p in $c.Parameters.Values) {
                if ($p.ParameterType -eq [scriptblock] -or $p.ParameterType -eq [scriptblock[]]) { $sb = 1 }
            }
        }
        $out.Add("C`t$($c.Name.ToLowerInvariant())`t$sb")
    }
    foreach ($m in $modules) {
        try { Import-Module $m -ErrorAction Stop } catch { }
        foreach ($c in @(Get-Command -Module $m -CommandType Cmdlet, Function -ErrorAction SilentlyContinue)) { & $add $c }
    }
    foreach ($f in @(Get-ChildItem Function:)) { & $add (Get-Command $f.Name) }
    foreach ($a in @(Get-Alias)) { $out.Add("A`t$($a.Name.ToLowerInvariant())`t$($a.ResolvedCommandName.ToLowerInvariant())") }
    $out
    return
}

function Read-Dump([string[]]$lines) {
    $version = ($lines | Where-Object { $_ -like "V`t*" } | Select-Object -First 1)
    $cmds = [System.Collections.Generic.SortedDictionary[string, string]]::new([System.StringComparer]::Ordinal)
    $aliases = [System.Collections.Generic.SortedDictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($l in $lines) {
        $p = $l -split "`t"
        if ($p[0] -eq 'C') { $cmds[$p[1]] = $p[2] }
        if ($p[0] -eq 'A') { $aliases[$p[1]] = $p[2] }
    }
    if (-not $version -or $cmds.Count -lt 100 -or $aliases.Count -lt 50) { throw 'bad dump' }
    [pscustomobject]@{ Version = ($version -split "`t")[1]; Commands = $cmds; Aliases = $aliases }
}

function Format-RustTable([string]$name, $dump) {
    $q = { param($s) '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"' }
    $rows = @("/// $($dump.Version).", "pub(super) const ${name}: Table = Table {", '    commands: &[')
    foreach ($k in $dump.Commands.Keys) { $rows += "        ($(& $q $k), $($dump.Commands[$k]))," }
    $rows += '    ],'
    $rows += '    aliases: &['
    foreach ($k in $dump.Aliases.Keys) { $rows += "        ($(& $q $k), $(& $q $dump.Aliases[$k]))," }
    $rows += '    ],'
    $rows += '};'
    $rows
}

$self = $MyInvocation.MyCommand.Path
$pwsh = Read-Dump @(& pwsh -NoProfile -File $self -Dump)
$ps5 = Read-Dump @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $self -Dump)
$text = @(
    "//! Generated from $($pwsh.Version) and $($ps5.Version) by ``pwsh -NoProfile -File src/fs/cmdlet_table.ps1``; do not edit."
    '//! Per shell: every cmdlet and function it ships (Microsoft.PowerShell.Core and the modules pwsh 7.7'
    '//! ships), lowercased and sorted, with 1 when it has a `ScriptBlock`-typed parameter; every alias'
    '//! with the command it names.'
    ''
    'pub(super) struct Table {'
    '    pub commands: &''static [(&''static str, u8)],'
    '    pub aliases: &''static [(&''static str, &''static str)],'
    '}'
    ''
) + (Format-RustTable 'PWSH' $pwsh) + @('') + (Format-RustTable 'POWERSHELL5' $ps5)
$target = Join-Path (Split-Path $self) 'cmdlet_table.rs'
[IO.File]::WriteAllText($target, (($text -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
"wrote $target ($($pwsh.Commands.Count)/$($pwsh.Aliases.Count) pwsh, $($ps5.Commands.Count)/$($ps5.Aliases.Count) 5.1)"
