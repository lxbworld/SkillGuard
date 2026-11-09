<#
.SYNOPSIS
    Install SkillGuard on Windows.

.DESCRIPTION
    Two paths, the same two as action/install.sh:

      1. With -Version, download the prebuilt skillguard-windows-x86_64.tar.gz
         release asset and verify its SHA-256 before installing anything.
      2. Without -Version, build the checkout this script lives in.

    A checksum mismatch is fatal and never falls back to a source build: a
    security tool that installs an unverified binary is not a security tool.

.PARAMETER Version
    Release tag, e.g. v0.1.1. Empty (the default) builds from source.

.PARAMETER Dest
    Install root. The binary goes to "$Dest\bin\skillguard.exe".

.PARAMETER Repo
    GitHub repository, default lxbworld/SkillGuard.

.PARAMETER AddToPath
    Add "$Dest\bin" to the current user's PATH. Off by default: installing a
    tool should not silently change the user's environment.

.EXAMPLE
    .\install.ps1 -Version v0.1.1 -AddToPath

.EXAMPLE
    .\install.ps1
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$Dest = (Join-Path $env:LOCALAPPDATA "SkillGuard"),
    [string]$Repo = "lxbworld/SkillGuard",
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$asset = "skillguard-windows-x86_64.tar.gz"
$base = if ($env:SKILLGUARD_RELEASE_BASE) {
    $env:SKILLGUARD_RELEASE_BASE
} else {
    "https://github.com/$Repo/releases/download"
}

function Write-Step([string]$Message) {
    Write-Host $Message
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Install-FromRelease {
    $url = "$base/$Version/$asset"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("skillguard-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Step "downloading $url"
        Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp $asset) -UseBasicParsing

        $checksumUrl = "$url.sha256"
        Invoke-WebRequest -Uri $checksumUrl -OutFile (Join-Path $tmp "$asset.sha256") -UseBasicParsing

        $expected = ((Get-Content (Join-Path $tmp "$asset.sha256") -Raw) -split "\s+")[0].ToLowerInvariant()
        $actual = Get-Sha256 (Join-Path $tmp $asset)
        if ($expected -ne $actual) {
            throw "checksum mismatch for $asset`: expected $expected, got $actual"
        }
        Write-Step "checksum verified: $actual"

        $binDir = Join-Path $Dest "bin"
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        tar -xzf (Join-Path $tmp $asset) -C $tmp
        $exe = Join-Path $tmp "skillguard.exe"
        if (-not (Test-Path $exe)) {
            throw "the archive did not contain skillguard.exe"
        }
        Copy-Item -Force $exe (Join-Path $binDir "skillguard.exe")
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "cargo is not available and no -Version was given; pass -Version vX.Y.Z to use a prebuilt release"
    }
    $root = $here
    while ($root -and -not (Test-Path (Join-Path $root "Cargo.toml"))) {
        $parent = Split-Path -Parent $root
        if ($parent -eq $root) { break }
        $root = $parent
    }
    if (-not (Test-Path (Join-Path $root "Cargo.toml"))) {
        throw "no Cargo.toml found above this script; pass -Version vX.Y.Z to use a prebuilt release"
    }
    Write-Step "building SkillGuard from $root"
    cargo install --path $root --locked --root $Dest
}

if ($Version -eq "") {
    Install-FromSource
} else {
    Install-FromRelease
}

$binDir = Join-Path $Dest "bin"
$exe = Join-Path $binDir "skillguard.exe"
if (-not (Test-Path $exe)) {
    throw "install finished but $exe is missing"
}

& $exe --version
Write-Step "installed to $exe"

if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$binDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
        Write-Step "added $binDir to the user PATH (open a new terminal)"
    }
} else {
    Write-Step "add it to your PATH with: `$env:Path += `";$binDir`""
}
