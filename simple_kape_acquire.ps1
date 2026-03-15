#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Simple KAPE Triage Acquisition Script

.DESCRIPTION
    Downloads KAPE from the provided URL, extracts it, and runs a triage acquisition.
    Results are stored in a temporary directory and zipped for easy transfer.

.NOTES
    - Run as Administrator
    - Requires internet connection
#>

# Configuration
$KapeZipUrl = 'https://transfer.whalebone.io/get/wpfHY6DXfg/KAPE.zip'
$WorkingDir = Join-Path $env:TEMP "KAPE_Work_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$OutputZip = Join-Path $env:TEMP "KAPE_Triage_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"

# Color output helpers
function Write-OK { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Err { Write-Host "[!] $args" -ForegroundColor Red; exit 1 }
function Write-Step { Write-Host "[*] $args" -ForegroundColor Yellow }

# Step 1: Create working directory
Write-Step "Creating working directory: $WorkingDir"
New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null

# Step 2: Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Step 3: Download ZIP
Write-Step "Downloading KAPE from $KapeZipUrl"
$zipFile = Join-Path $WorkingDir "KAPE.zip"
try {
    Invoke-WebRequest -Uri $KapeZipUrl -OutFile $zipFile -ErrorAction Stop
    Write-OK "Downloaded: $zipFile"
} catch {
    Write-Err "Download failed: $_"
}

# Step 4: Extract ZIP
Write-Step "Extracting KAPE..."
Expand-Archive -Path $zipFile -DestinationPath $WorkingDir -Force
Write-OK "Extracted to: $WorkingDir"

# Step 5: Find KAPE executable
Write-Step "Locating kape.exe..."
$kapeExe = Get-ChildItem -Path $WorkingDir -Filter 'kape.exe' -Recurse -File | Select-Object -First 1
if (-not $kapeExe) {
    Write-Err "kape.exe not found in extracted files"
}
Write-OK "Found: $($kapeExe.FullName)"

# Step 6: Set up collection output
$collectionDir = Join-Path $WorkingDir "Collection"
New-Item -ItemType Directory -Path $collectionDir -Force | Out-Null

# Step 7: Run KAPE triage acquisition
Write-Step "Running KAPE triage acquisition..."
Write-Step "Command: $($kapeExe.FullName) --tsource C: --target !SANS_Triage --tdest $collectionDir --tflush --zv false"

& $kapeExe.FullName `
    --tsource C: `
    --target '!SANS_Triage' `
    --tdest $collectionDir `
    --tflush `
    --zv false

if ($LASTEXITCODE -eq 0) {
    Write-OK "Triage acquisition complete!"
} else {
    Write-Err "KAPE acquisition failed with exit code $LASTEXITCODE"
}

# Step 8: Compress results
Write-Step "Compressing results to: $OutputZip"
Compress-Archive -Path (Join-Path $collectionDir '*') -DestinationPath $OutputZip -CompressionLevel Optimal -Force
$zipSize = (Get-Item $OutputZip).Length / 1MB
Write-OK "Archive created: $([math]::Round($zipSize, 2)) MB"

# Summary
Write-Host "`n" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Acquisition Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Output ZIP: $OutputZip" -ForegroundColor Cyan
Write-Host "Working Dir: $WorkingDir (cleanup with: Remove-Item -Recurse -Force '$WorkingDir')" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Green
