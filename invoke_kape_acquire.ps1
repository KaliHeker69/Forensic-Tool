#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Improved KAPE Automated Triage, Parse, and Archive Script

.DESCRIPTION
    - Downloads KAPE, runs a triage collection, parses artefacts using the
      built-in !EZParser module, and compresses the output into a ZIP archive.
    - Adds parameterisation, retries for downloads, logging/transcript,
      optional VSS inclusion, and cleanup behavior.

.NOTES
    - Must be run as Administrator
    - Requires internet access to download KAPE
    - Tested on Windows 10/11 and Windows Server 2016+
.AUTHOR
    Updated script (improvements applied)
#>

param(
    [string]$BaseDir = "$env:SystemDrive\KAPE_Triage",
    [string]$KapeZipUrl = 'https://transfer.whalebone.io/get/wpfHY6DXfg/KAPE.zip',
    [string]$TargetDrive = $env:SystemDrive,
    [string]$KapeTarget = '!SANS_Triage',
    [string]$KapeModule = '!EZParser',
    [switch]$IncludeVSS,
    [switch]$KeepKAPE,
    [switch]$VerboseLogging,
    [int]$Retries = 3
)

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$Config = @{
    BaseDir     = $BaseDir
    KapeZipUrl  = $KapeZipUrl
    TargetDrive = $TargetDrive
    KapeTarget  = $KapeTarget
    KapeModule  = $KapeModule
    ZipDest     = Join-Path $env:TEMP "KAPE_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    Retries     = [int]$Retries
}

# Start logging transcript when verbose requested
if ($VerboseLogging) {
    $transcript = Join-Path $env:TEMP "kape_run_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $transcript -Force | Out-Null
    Write-OK "Transcript: $transcript"
}

## Using a direct ZIP URL; no Google Drive conversion logic required.

# ─────────────────────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Banner {
    param([string]$Message, [string]$Color = "Cyan")
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor $Color
    Write-Host "  $Message" -ForegroundColor $Color
    Write-Host "$line`n" -ForegroundColor $Color
}

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Err {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

function Assert-ExitCode {
    param([int]$Code, [string]$Label)
    if ($Code -ne 0) {
        Write-Err "$Label failed with exit code $Code. Halting."
        exit $Code
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 0 – PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "KAPE Automated Triage Script – Pre-flight Checks"

# Confirm elevation
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator. Re-launch in an elevated prompt."
    exit 1
}
Write-OK "Running as Administrator."

# Ensure TLS 1.2 for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-OK "TLS 1.2 enforced."

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 – PREPARE DIRECTORY STRUCTURE
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Step 1 – Creating Directory Structure"

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Dirs = @{
    Root       = $Config.BaseDir
    KapeRoot   = Join-Path $Config.BaseDir "KAPE"
    Collection = Join-Path $Config.BaseDir "Collection"
    Parsed     = Join-Path $Config.BaseDir "Parsed"
    TempDl     = Join-Path $env:TEMP "KAPE_Downloads_$timestamp"
}

foreach ($key in $Dirs.Keys) {
    if (-not (Test-Path $Dirs[$key])) {
        New-Item -ItemType Directory -Path $Dirs[$key] -Force | Out-Null
        Write-OK "Created: $($Dirs[$key])"
    } else {
        Write-Step "Exists:  $($Dirs[$key])"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 – DOWNLOAD & EXTRACT KAPE
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Step 2 - Downloading KAPE"

$kapeZipName = [System.IO.Path]::GetFileName(($Config.KapeZipUrl.Split('?')[0]))
$kapeZip    = Join-Path $Dirs.TempDl $kapeZipName
$kapeScript = Join-Path $Dirs.TempDl "Get-KAPEUpdate.ps1"

Write-Step "Downloading KAPE update package from $($Config.KapeZipUrl) ..."
$downloadOk = $false
for ($i=1; $i -le $Config.Retries; $i++) {
    try {
        Invoke-WebRequest -Uri $Config.KapeZipUrl -OutFile $kapeZip -ErrorAction Stop
        Write-OK "Downloaded: $kapeZip"
        $downloadOk = $true
        break
    } catch {
        Write-Err "Attempt $i/$($Config.Retries) failed: $($_.Exception.Message)"
        Start-Sleep -Seconds (5 * $i)
    }
}
if (-not $downloadOk) {
    Write-Err "All download attempts failed. Halting."
    exit 1
}

Write-Step "Extracting package to $($Dirs.TempDl)..."
Expand-Archive -Path $kapeZip -DestinationPath $Dirs.TempDl -Force
Write-OK "Extracted."

# Deploy extracted contents into KAPE root
Write-Step "Deploying extracted files to $($Dirs.KapeRoot)"
try {
    Copy-Item -Path (Join-Path $Dirs.TempDl '*') -Destination $Dirs.KapeRoot -Recurse -Force -ErrorAction Stop
} catch {
    Write-Err "Failed to copy extracted files: $($_.Exception.Message)"
}

# Locate kape.exe in the deployed files
$foundExe = Get-ChildItem -Path $Dirs.KapeRoot -Filter 'kape.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($foundExe) {
    $KapeExe = $foundExe.FullName
    Write-OK "Found kape.exe at: $KapeExe"
} elseif (Test-Path $kapeScript) {
    Write-Step "Get-KAPEUpdate.ps1 present; running it to ensure proper install..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $kapeScript -KapePath $Dirs.KapeRoot
    Assert-ExitCode $LASTEXITCODE "KAPE update script"
    $KapeExe = Get-ChildItem -Path $Dirs.KapeRoot -Filter 'kape.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $KapeExe) {
        Write-Err "kape.exe not found after running installer. Halting."
        exit 1
    }
    $KapeExe = $KapeExe.FullName
    Write-OK "kape.exe confirmed at: $KapeExe"
} else {
    Write-Err "kape.exe not found and no installer script present. Check the ZIP contents."
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 – TRIAGE COLLECTION  (kape.exe --tsource ... --tdest ...)
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Step 3 – Running KAPE Triage Collection (Target: $($Config.KapeTarget))"

<#
  Key KAPE CLI flags used:
    --tsource   Source drive/path to collect from
    --target    Target configuration name (e.g. !SANS_Triage)
    --tdest     Destination for raw collected files
    --tflush    Delete tdest before collecting (clean run)
    --vss       Include Volume Shadow Copies (remove if not needed)
    --zv false  Do not compress during collection (we zip at the end ourselves)
#>

$CollectionArgs = @(
    '--tsource', $Config.TargetDrive,
    '--target',  $Config.KapeTarget,
    '--tdest',   $Dirs.Collection,
    '--tflush',
    '--zv', 'false',
    '--debug'
)
if ($IncludeVSS) { $CollectionArgs += '--vss' }

Write-Step "Launching: kape.exe $CollectionArgs"
$proc = Start-Process -FilePath $KapeExe `
    -ArgumentList $CollectionArgs `
    -Wait -PassThru -NoNewWindow

Assert-ExitCode $proc.ExitCode "KAPE triage collection"
Write-OK "Triage collection complete. Artefacts at: $($Dirs.Collection)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 – PARSING  (kape.exe --msource ... --module !EZParser)
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Step 4 – Parsing Artefacts with !EZParser (built-in module)"

<#
  Key KAPE CLI flags used:
    --msource   Directory containing collected artefacts (from Step 4)
    --module    Module configuration to run (e.g. !EZParser)
    --mdest     Destination for parsed/processed output
    --mflush    Delete mdest before parsing (clean run)
#>

$ParseArgs = @(
    '--msource', $Dirs.Collection,
    '--module',  $Config.KapeModule,
    '--mdest',   $Dirs.Parsed,
    '--mflush',
    '--debug'
)

Write-Step "Launching: kape.exe $ParseArgs"
$proc2 = Start-Process -FilePath $KapeExe `
    -ArgumentList $ParseArgs `
    -Wait -PassThru -NoNewWindow

Assert-ExitCode $proc2.ExitCode "KAPE EZParser module"
Write-OK "Parsing complete. Results at: $($Dirs.Parsed)"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 – COMPRESS OUTPUT
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Step 5 – Compressing Results"

Write-Step "Zipping contents of $($Config.BaseDir) → $($Config.ZipDest)"
try {
    $pathToZip = Join-Path $Config.BaseDir '*'
    Compress-Archive -Path $pathToZip -DestinationPath $Config.ZipDest -CompressionLevel Optimal -Force
    Write-OK "Archive created: $($Config.ZipDest)"
} catch {
    Write-Err "Compression failed: $_"
    exit 1
}

# Report size
$zipSize = (Get-Item $Config.ZipDest).Length / 1MB
Write-OK "Archive size: $([math]::Round($zipSize, 2)) MB"

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 – SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
Write-Banner "Triage Complete – Summary" -Color "Green"

[PSCustomObject]@{
    "Raw Artefacts"   = $Dirs.Collection
    "Parsed Output"   = $Dirs.Parsed
    "Archive (ZIP)"   = $Config.ZipDest
    "Archive Size MB" = [math]::Round($zipSize, 2)
    "Timestamp"       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
} | Format-List

Write-Host "Done. Transfer the ZIP to your analysis workstation.`n" -ForegroundColor Green
if (-not $KeepKAPE) {
    Write-Step "Cleaning temporary download folder: $($Dirs.TempDl)"
    try { Remove-Item -LiteralPath $Dirs.TempDl -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

if ($VerboseLogging) { Stop-Transcript | Out-Null }