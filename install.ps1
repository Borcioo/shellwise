# Installs or updates shellwise on Windows (Windows PowerShell 5.1 and PowerShell 7):
#
#   irm https://raw.githubusercontent.com/Borcioo/shellwise/main/install.ps1 | iex
#
# It downloads the release archive and SHA256SUMS, refuses unless the archive's SHA-256 matches its
# line, and swaps the binary in by rename. Running it again is the update. Settings come only from
# the environment:
#
#   SHELLWISE_VERSION      1.2.3 or v1.2.3; unset installs the latest release
#   SHELLWISE_INSTALL_DIR  the install folder; default %LOCALAPPDATA%\Programs\shellwise
#   SHELLWISE_BASE_URL     the release URL, or a local folder with the same layout
#   SHELLWISE_MODE         install (default), or check: print the latest version and install nothing
#   SHELLWISE_NO_PATH      1 leaves the user PATH alone
#   SHELLWISE_TARGET       overrides the detected target (tests and troubleshooting)
#
# The whole body runs in a script block so StrictMode and the error preference stay out of the
# caller's session under iex; there a refusal is a throw, and with -File it is exit code 1.

& {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $fromFile = [bool]$PSCommandPath
    $supported = 'x86_64-pc-windows-msvc'
    $versionPattern = '[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?'

    function Stop-Install([string]$Message) {
        throw "shellwise install: $Message"
    }

    function Get-ReleaseFile([string]$RelPath, [string]$Dest, [int]$TimeoutSec) {
        if ($remote) {
            $url = "$base/$RelPath"
            try {
                Invoke-WebRequest -Uri $url -OutFile $Dest -UseBasicParsing -TimeoutSec $TimeoutSec
            } catch {
                Stop-Install "could not download ${url}: $($_.Exception.Message)"
            }
        } else {
            $src = Join-Path $base ($RelPath -replace '/', '\')
            if (-not [IO.File]::Exists($src)) {
                Stop-Install "could not read $src"
            }
            [IO.File]::Copy($src, $Dest, $true)
        }
    }

    function Get-LatestVersion([string]$Tmp, [int]$TimeoutSec) {
        $sums = Join-Path $Tmp 'latest-SHA256SUMS'
        Get-ReleaseFile 'latest/download/SHA256SUMS' $sums $TimeoutSec
        $text = [IO.File]::ReadAllText($sums)
        $m = [regex]::Match($text, "(?m)^[0-9a-fA-F]{64} [ *]shellwise-v($versionPattern)-(?:x86_64|aarch64)-")
        if (-not $m.Success) {
            Stop-Install "could not read the latest version from $base/latest/download/SHA256SUMS"
        }
        return $m.Groups[1].Value
    }

    $base = $env:SHELLWISE_BASE_URL
    if (-not $base) {
        $base = 'https://github.com/Borcioo/shellwise/releases'
    }
    $base = $base.TrimEnd('/', '\')
    $remote = $base -match '^https?://'

    $savedEncoding = $null
    $tmp = $null
    $failed = $false
    try {
        if ([Console]::IsOutputRedirected) {
            # A program reading the output gets UTF-8 whatever the console code page is.
            $savedEncoding = [Console]::OutputEncoding
            [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        }
        if ($remote) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('shellwise-install-' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($tmp)

        $mode = $env:SHELLWISE_MODE
        if ($mode -eq 'check') {
            Write-Output (Get-LatestVersion $tmp 3)
            return
        }
        if ($mode -and $mode -ne 'install') {
            Stop-Install "unknown SHELLWISE_MODE $mode; use install or check"
        }

        $target = $env:SHELLWISE_TARGET
        if (-not $target) {
            $arch = $env:PROCESSOR_ARCHITEW6432
            if (-not $arch) {
                $arch = $env:PROCESSOR_ARCHITECTURE
            }
            if ($arch -ne 'AMD64') {
                Stop-Install "no release for Windows on $arch; supported targets: $supported"
            }
            $target = $supported
        }
        if ($target -ne $supported) {
            Stop-Install "unsupported target $target; supported targets: $supported (on Linux and macOS use install.sh)"
        }

        $version = $env:SHELLWISE_VERSION
        if ($version) {
            $version = $version -replace '^v', ''
            if ($version -notmatch "^$versionPattern$") {
                Stop-Install "SHELLWISE_VERSION $env:SHELLWISE_VERSION is not a version like 1.2.3"
            }
            $sums = Join-Path $tmp 'SHA256SUMS'
            Get-ReleaseFile "download/v$version/SHA256SUMS" $sums 120
        } else {
            $version = Get-LatestVersion $tmp 120
            $sums = Join-Path $tmp 'latest-SHA256SUMS'
        }

        $file = "shellwise-v$version-$target.zip"
        $expected = @()
        foreach ($line in ([IO.File]::ReadAllText($sums) -split "`r?`n")) {
            $m = [regex]::Match($line, '^([0-9a-fA-F]{64}) [ *](.+?)\s*$')
            if ($m.Success -and $m.Groups[2].Value -ceq $file) {
                $expected += $m.Groups[1].Value.ToLowerInvariant()
            }
        }
        if ($expected.Count -eq 0) {
            Stop-Install "SHA256SUMS of v$version has no line for $file; nothing was installed"
        }
        if ($expected.Count -gt 1) {
            Stop-Install "SHA256SUMS of v$version has more than one line for $file; nothing was installed"
        }

        $archive = Join-Path $tmp $file
        Get-ReleaseFile "download/v$version/$file" $archive 120
        # .NET, not Get-FileHash or Expand-Archive: Windows PowerShell 5.1 started with a PowerShell 7
        # PSModulePath (as from a pwsh session) cannot load those module commands.
        $stream = [IO.File]::OpenRead($archive)
        try {
            $digest = [Security.Cryptography.SHA256]::Create().ComputeHash($stream)
        } finally {
            $stream.Dispose()
        }
        $actual = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
        if ($actual -cne $expected[0]) {
            Stop-Install "checksum mismatch for $file (SHA256SUMS has $($expected[0]), the download has $actual); nothing was installed"
        }

        $unpack = Join-Path $tmp 'unpack'
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($archive, $unpack)
        } catch {
            Stop-Install "could not unpack ${file}: $($_.Exception.Message)"
        }
        $bin = Join-Path $unpack "shellwise-v$version-$target\shellwise.exe"
        if (-not [IO.File]::Exists($bin)) {
            Stop-Install "$file holds no shellwise-v$version-$target\shellwise.exe"
        }

        $dir = $env:SHELLWISE_INSTALL_DIR
        if (-not $dir) {
            if (-not $env:LOCALAPPDATA) {
                Stop-Install 'LOCALAPPDATA is not set; set SHELLWISE_INSTALL_DIR'
            }
            $dir = Join-Path $env:LOCALAPPDATA 'Programs\shellwise'
        }
        if (-not [IO.Path]::IsPathRooted($dir)) {
            $dir = Join-Path (Get-Location).ProviderPath $dir
        }
        $dir = [IO.Path]::GetFullPath($dir).TrimEnd('\')
        [void][IO.Directory]::CreateDirectory($dir)

        # The copy lands in the install folder first, so each swap step is a rename on one volume.
        # A running binary cannot be overwritten but can be renamed.
        $dest = Join-Path $dir 'shellwise.exe'
        $new = "$dest.new"
        $old = "$dest.old"
        if ([IO.Directory]::Exists($dest)) {
            Stop-Install "$dest is a folder; nothing was installed"
        }
        [IO.File]::Copy($bin, $new, $true)
        if ([IO.File]::Exists($dest)) {
            if ([IO.File]::Exists($old)) {
                try { [IO.File]::Delete($old) } catch { }
            }
            try {
                [IO.File]::Move($dest, $old)
            } catch {
                [IO.File]::Delete($new)
                Stop-Install "could not move $dest aside ($($_.Exception.Message)); close the programs running $old and run again"
            }
            try {
                [IO.File]::Move($new, $dest)
            } catch {
                $why = $_.Exception.Message
                try {
                    [IO.File]::Move($old, $dest)
                } catch {
                    Stop-Install "could not put the new binary in place ($why) nor restore the old one, which is at $old"
                }
                [IO.File]::Delete($new)
                Stop-Install "could not put the new binary in place ($why); the old one is back"
            }
            # Locked while the old binary still runs; the next run deletes it.
            try { [IO.File]::Delete($old) } catch { }
        } else {
            try {
                [IO.File]::Move($new, $dest)
            } catch {
                [IO.File]::Delete($new)
                Stop-Install "could not put the new binary in place ($($_.Exception.Message))"
            }
        }
        Write-Host "Installed shellwise $version at $dest"

        if ($env:SHELLWISE_NO_PATH -ne '1') {
            $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
            try {
                $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $present = $false
                foreach ($entry in ($userPath -split ';')) {
                    if ($entry -and [Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\') -ieq $dir) {
                        $present = $true
                    }
                }
                if (-not $present) {
                    if ($userPath -and -not $userPath.EndsWith(';')) {
                        $userPath += ';'
                    }
                    $key.SetValue('Path', "$userPath$dir", [Microsoft.Win32.RegistryValueKind]::ExpandString)
                    Write-Host "Added $dir to your user PATH; open a new terminal to use it there."
                }
            } finally {
                $key.Close()
            }
        }
        Write-Host 'Next: shellwise agent-setup'
    } catch {
        $message = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if (-not $message.StartsWith('shellwise install: ')) {
            $message = "shellwise install: $message"
        }
        if (-not $fromFile) {
            throw $message
        }
        if ([Console]::IsErrorRedirected) {
            # UTF-8 here too: Windows PowerShell 5.1 keeps the code page on stderr.
            $err = New-Object IO.StreamWriter([Console]::OpenStandardError(), (New-Object System.Text.UTF8Encoding($false)))
            $err.WriteLine($message)
            $err.Flush()
        } else {
            [Console]::Error.WriteLine($message)
        }
        $failed = $true
    } finally {
        if ($tmp -and [IO.Directory]::Exists($tmp)) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($savedEncoding) {
            [Console]::OutputEncoding = $savedEncoding
        }
    }
    if ($failed) {
        exit 1
    }
}
