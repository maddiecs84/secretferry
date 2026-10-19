<#
.SYNOPSIS
Installs secretferry on Windows from a GitHub release.

.DESCRIPTION
  irm https://github.com/maddiecs84/secretferry/releases/latest/download/install.ps1 | iex

To install a particular version, or somewhere else, save the script and run it with parameters:

  .\install.ps1 -Version v0.1.0 -InstallDir C:\tools

The archive is checked against the release's checksums.txt before anything is installed.
No administrator rights are needed: the default directory is under your own profile.

.PARAMETER Version
A release such as v0.1.0. The latest release when left out.

.PARAMETER InstallDir
Where secretferry.exe goes. %LOCALAPPDATA%\Programs\secretferry by default.

.PARAMETER NoPath
Do not add the directory to your user PATH.
#>
[CmdletBinding()]
param(
    [string]$Version = $env:SECRETFERRY_VERSION,
    [string]$InstallDir = $(if ($env:SECRETFERRY_INSTALL_DIR) { $env:SECRETFERRY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\secretferry' }),
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads far slower in Windows PowerShell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$repo = 'maddiecs84/secretferry'
$base = if ($env:SECRETFERRY_BASE_URL) { $env:SECRETFERRY_BASE_URL } else { "https://github.com/$repo/releases" }

$arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    default { throw "There is no build for the $_ processor." }
}

if (-not $Version) {
    # /releases/latest redirects to /releases/tag/<version>; the API says the same without parsing a redirect.
    $latest = if ($env:SECRETFERRY_BASE_URL) { throw 'Pass -Version when SECRETFERRY_BASE_URL is set.' } else {
        Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'secretferry-install' }
    }
    $Version = $latest.tag_name
}
if ($Version -notmatch '^v\d') { throw 'The version should look like v1.2.3.' }

$name = "secretferry_${Version}_windows_${arch}"
$archive = "$name.zip"
$work = Join-Path ([IO.Path]::GetTempPath()) ("secretferry-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

try {
    Write-Host "Downloading secretferry $Version for windows/$arch"
    Invoke-WebRequest "$base/download/$Version/$archive" -OutFile (Join-Path $work $archive) -UseBasicParsing
    Invoke-WebRequest "$base/download/$Version/checksums.txt" -OutFile (Join-Path $work 'checksums.txt') -UseBasicParsing

    $line = Get-Content (Join-Path $work 'checksums.txt') | Where-Object { ($_ -split '\s+')[1] -eq $archive } | Select-Object -First 1
    if (-not $line) { throw "checksums.txt has no entry for $archive." }
    $want = ($line -split '\s+')[0]
    $got = (Get-FileHash (Join-Path $work $archive) -Algorithm SHA256).Hash
    if ($got -ne $want) { throw 'The download does not match its checksum; nothing was installed.' }

    Expand-Archive (Join-Path $work $archive) -DestinationPath $work -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $work "$name\secretferry.exe") (Join-Path $InstallDir 'secretferry.exe') -Force
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Installed $(Join-Path $InstallDir 'secretferry.exe')"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$onPath = ($userPath -split ';') | Where-Object { $_.TrimEnd('\') -eq $InstallDir.TrimEnd('\') }
if (-not $onPath) {
    if ($NoPath) {
        Write-Host "Note: $InstallDir is not on your PATH."
    }
    else {
        [Environment]::SetEnvironmentVariable('Path', (($userPath, $InstallDir) | Where-Object { $_ }) -join ';', 'User')
        Write-Host "Added $InstallDir to your user PATH; open a new terminal to use it."
    }
}
