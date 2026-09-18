param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputFile,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$OutputFile
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    Write-Host "Error: Input file not found: $InputFile" -ForegroundColor Red
    exit 1
}

$AbsInput = (Resolve-Path -LiteralPath $InputFile).Path
$InputFileName = Split-Path -Leaf $AbsInput

$OutDir = Split-Path -Parent $OutputFile
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = "." }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$AbsOutDir = (Resolve-Path -LiteralPath $OutDir).Path
$OutputFileName = Split-Path -Leaf $OutputFile

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$ImageName = "docshield-cdr:latest"

$imgCheck = docker images -q $ImageName 2>$null
if (-not $imgCheck) {
    Write-Host "Building DocShield Docker sandbox image..."
    docker build -t $ImageName $ProjectRoot
}

Write-Host "Executing DocShield CDR inside Hardened Docker Sandbox..." -ForegroundColor Cyan

docker run --rm `
    --network none `
    --read-only `
    --user 10001:10001 `
    --cap-drop ALL `
    --security-opt no-new-privileges:true `
    --memory 1024m `
    --memory-swap 1024m `
    --cpus 2.0 `
    --pids-limit 150 `
    --tmpfs /tmp:rw,noexec,nosuid,size=256m `
    --tmpfs /sandbox/scratch:rw,noexec,nosuid,size=256m `
    -v "${AbsInput}:/sandbox/input/${InputFileName}:ro" `
    -v "${AbsOutDir}:/sandbox/output:rw" `
    -v "${ProjectRoot}\output\reports:/app/output/reports:rw" `
    -v "${ProjectRoot}\output\quarantine:/app/output/quarantine:rw" `
    $ImageName `
    "/sandbox/input/$InputFileName" "/sandbox/output/$OutputFileName"

exit $LASTEXITCODE
