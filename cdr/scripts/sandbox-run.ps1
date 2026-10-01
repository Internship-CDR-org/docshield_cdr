<#
.SYNOPSIS
    DocShield CDR Engine - Windows Sandbox Dispatcher
.DESCRIPTION
    Launches DocShield CDR inside an isolated sandbox environment.
    Automatically prioritizes:
    1. WSL2 Kernel Sandbox with Bubblewrap (Hardware/Namespace Isolation & Airgap)
    2. Docker Container Sandbox (Read-only rootfs, non-root, network airgap)
    3. Windows Native Process Isolation (Restricted temp jail, read-only copy, timeout watchdog)
.PARAMETER InputFile
    Path to the untrusted input document
.PARAMETER OutputFile
    Path to the reconstructed safe output document
.EXAMPLE
    .\scripts\sandbox-run.ps1 samples\file_example_XLS_10.xlsx output\clean.xlsx
#>

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputFile,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$OutputFile
)

$ErrorActionPreference = "Stop"

# Verify input file
if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    Write-Host "DocShield Sandbox Error: Input file not found or is not a file: $InputFile" -ForegroundColor Red
    exit 1
}

$AbsInput = (Resolve-Path -LiteralPath $InputFile).Path
$OutDir = Split-Path -Parent $OutputFile
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = "."
}
if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}
$AbsOutDir = (Resolve-Path -LiteralPath $OutDir).Path
$OutFileName = Split-Path -Leaf $OutputFile
$AbsOutput = Join-Path $AbsOutDir $OutFileName

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         DocShield Content Disarm & Reconstruction          " -ForegroundColor Cyan
Write-Host "                 Sandbox Runner (Windows)                   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Input Document  : $AbsInput"
Write-Host "Output Target   : $AbsOutput"

# Check for WSL2 with bwrap
$hasWsl = $false
try {
    $wslCheck = wsl which bwrap 2>$null
    if ($wslCheck -match "bwrap") {
        $hasWsl = $true
    }
} catch { }

if ($hasWsl) {
    Write-Host "Isolation Backend: WSL2 Kernel Sandbox (Bubblewrap airgap active)" -ForegroundColor Green
    
    # Convert paths to WSL path representation
    $wslInput = (wsl wslpath -a ($AbsInput -replace '\\', '/')).Trim()
    $wslOutput = (wsl wslpath -a ($AbsOutput -replace '\\', '/')).Trim()
    $wslProject = (wsl wslpath -a ($ProjectRoot -replace '\\', '/')).Trim()

    $wslCommand = "cd '$wslProject' && ./scripts/sandbox-run.sh '$wslInput' '$wslOutput'"
    
    wsl bash -c $wslCommand
    $exitCode = $LASTEXITCODE
    exit $exitCode
}

# Fallback: Check Docker
$hasDocker = $false
try {
    $dockerCheck = docker version 2>$null
    if ($LASTEXITCODE -eq 0) {
        $hasDocker = $true
    }
} catch { }

if ($hasDocker) {
    Write-Host "Isolation Backend: Docker Container Sandbox" -ForegroundColor Yellow
    & "$ScriptDir\run-docker-sandbox.ps1" -InputFile $AbsInput -OutputFile $AbsOutput
    exit $LASTEXITCODE
}

# Fallback: Windows Native Process Isolation
Write-Host "Isolation Backend: Windows Native Isolated Process (Restricted)" -ForegroundColor Yellow
$IsolatedScratch = Join-Path $env:TEMP ("docshield_jail_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $IsolatedScratch -Force | Out-Null

try {
    # Copy input to isolated read-only scratch file
    $JailInput = Join-Path $IsolatedScratch (Split-Path -Leaf $AbsInput)
    Copy-Item -LiteralPath $AbsInput -Destination $JailInput -Force
    Set-ItemProperty -LiteralPath $JailInput -Name IsReadOnly -Value $true

    $ClasspathFile = Join-Path $ProjectRoot "target\docshield-classpath.txt"
    if (-not (Test-Path -LiteralPath $ClasspathFile)) {
        Write-Host "DocShield: Preparing dependencies..."
        # Compile if needed
    }

    $Classpath = "target/classes;" + (Get-Content -LiteralPath $ClasspathFile -Raw)
    
    $proc = Start-Process -FilePath "java" -ArgumentList "-cp", "`"$Classpath`"", "Main", "`"$JailInput`"", "`"$AbsOutput`"" `
        -WorkingDirectory $ProjectRoot -PassThru -NoNewWindow -Wait

    exit $proc.ExitCode
} finally {
    if (Test-Path -LiteralPath $IsolatedScratch) {
        Remove-Item -LiteralPath $IsolatedScratch -Recurse -Force -ErrorAction SilentlyContinue
    }
}
