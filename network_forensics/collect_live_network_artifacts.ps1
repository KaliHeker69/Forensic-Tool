#Requires -Version 5.1
<#
.SYNOPSIS
    Collect volatile live Windows network forensic artifacts and store outputs to disk.

.DESCRIPTION
    Executes live/volatile network forensics commands and writes results to
    timestamped JSON/TXT files.

.NOTES
    Run as Administrator for best coverage.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\forensics\network_live",
    [switch]$SkipModuleDump
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

function Save-Json {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Data,
        [int]$Depth = 8
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $Data | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8
}

function Save-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $Text | Out-File -FilePath $Path -Encoding UTF8
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [ValidateSet("json", "txt")][string]$Format = "json"
    )

    try {
        Write-Step "Collecting $Name"
        $result = & $Script

        if ($null -eq $result) {
            # Some cmdlets (e.g., Get-DnsClientCache) return $null when the feature
            # is unavailable or no records exist; write an empty array to keep the
            # file consistent and avoid parameter binding errors.
            $result = @()
        }

        switch ($Format) {
            "json" { Save-Json -Path $OutFile -Data $result }
            "txt"  { Save-Text -Path $OutFile -Text ($result | Out-String) }
        }

        Write-OK "Saved $Name -> $OutFile"
    }
    catch {
        Write-Warn "Failed ${Name}: $($_.Exception.Message)"
    }
}

# ---- Setup ------------------------------------------------------------------
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$caseDir = Join-Path $OutputRoot "live_$timestamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$meta = [ordered]@{
    collected_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    hostname = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    is_admin = $isAdmin
    script = "collect_live_network_artifacts.ps1"
}
Save-Json -Path (Join-Path $caseDir "collection_metadata.json") -Data $meta

if (-not $isAdmin) {
    Write-Warn "Script is not running as Administrator. Some outputs may be incomplete."
}

# ---- Active connections and sockets ----------------------------------------
Invoke-Safe -Name "netstat_ano" -OutFile (Join-Path $caseDir "netstat_ano.txt") -Format txt -Script {
    cmd /c "netstat -ano"
}

Invoke-Safe -Name "netstat_anob" -OutFile (Join-Path $caseDir "netstat_anob.txt") -Format txt -Script {
    cmd /c "netstat -anob"
}

Invoke-Safe -Name "established_only" -OutFile (Join-Path $caseDir "established_connections.txt") -Format txt -Script {
    cmd /c "netstat -ano" | Select-String "ESTABLISHED"
}

Invoke-Safe -Name "get_net_tcp_connection" -OutFile (Join-Path $caseDir "tcp_connections.json") -Format json -Script {
    Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
        Sort-Object State
}

Invoke-Safe -Name "get_net_udp_endpoint" -OutFile (Join-Path $caseDir "udp_endpoints.json") -Format json -Script {
    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
}

# ---- Process <-> network correlation ---------------------------------------
Invoke-Safe -Name "pid_process_correlation" -OutFile (Join-Path $caseDir "pid_process_correlation.json") -Format json -Script {
    Get-NetTCPConnection | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            PID           = $_.OwningProcess
            ProcessName   = $proc.Name
            Path          = $proc.Path
        }
    }
}

Invoke-Safe -Name "process_inventory" -OutFile (Join-Path $caseDir "process_inventory.json") -Format json -Script {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
}

if (-not $SkipModuleDump) {
    Invoke-Safe -Name "network_process_modules" -OutFile (Join-Path $caseDir "network_process_modules.json") -Format json -Script {
        $owningPids = Get-NetTCPConnection | Select-Object -ExpandProperty OwningProcess -Unique
        $output = @()
        foreach ($owningPid in $owningPids) {
            try {
                $p = Get-Process -Id $owningPid -ErrorAction Stop
                $mods = @()
                try {
                    $mods = $p.Modules | Select-Object ModuleName, FileName
                } catch {
                    $mods = @([PSCustomObject]@{ ModuleName = "<access_denied>"; FileName = "" })
                }
                $output += [PSCustomObject]@{
                    PID = $owningPid
                    ProcessName = $p.Name
                    Path = $p.Path
                    Modules = $mods
                }
            } catch {
                $output += [PSCustomObject]@{
                    PID = $owningPid
                    ProcessName = "<not_found>"
                    Path = ""
                    Modules = @()
                }
            }
        }
        $output
    }
}

Invoke-Safe -Name "unsigned_network_binaries" -OutFile (Join-Path $caseDir "unsigned_network_binaries.json") -Format json -Script {
    $procs = Get-NetTCPConnection -State Established | Select-Object -ExpandProperty OwningProcess -Unique
    $rows = @()
    foreach ($owningPid in $procs) {
        $p = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
        if ($p -and $p.Path) {
            $sig = Get-AuthenticodeSignature $p.Path
            if ($sig.Status -ne "Valid") {
                $rows += [PSCustomObject]@{
                    PID = $p.Id
                    Name = $p.Name
                    Path = $p.Path
                    SignatureStatus = $sig.Status
                    Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                }
            }
        }
    }
    $rows
}

# ---- DNS, ARP, routing ------------------------------------------------------
Invoke-Safe -Name "dns_client_cache" -OutFile (Join-Path $caseDir "dns_cache.json") -Format json -Script {
    Get-DnsClientCache | Select-Object Entry, RecordName, Data, TimeToLive
}

Invoke-Safe -Name "ipconfig_displaydns" -OutFile (Join-Path $caseDir "ipconfig_displaydns.txt") -Format txt -Script {
    cmd /c "ipconfig /displaydns"
}

Invoke-Safe -Name "arp_table" -OutFile (Join-Path $caseDir "arp_a.txt") -Format txt -Script {
    cmd /c "arp -a"
}

Invoke-Safe -Name "net_neighbor" -OutFile (Join-Path $caseDir "net_neighbors.json") -Format json -Script {
    Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex
}

Invoke-Safe -Name "route_print" -OutFile (Join-Path $caseDir "route_print.txt") -Format txt -Script {
    cmd /c "route print"
}

Invoke-Safe -Name "net_routes" -OutFile (Join-Path $caseDir "net_routes.json") -Format json -Script {
    Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceIndex
}

Invoke-Safe -Name "nbtstat_cache" -OutFile (Join-Path $caseDir "nbtstat_cache.txt") -Format txt -Script {
    cmd /c "nbtstat -c"
}

# ---- Firewall and proxy -----------------------------------------------------
Invoke-Safe -Name "firewall_profiles_text" -OutFile (Join-Path $caseDir "firewall_profiles.txt") -Format txt -Script {
    cmd /c "netsh advfirewall show allprofiles"
}

Invoke-Safe -Name "firewall_profiles_json" -OutFile (Join-Path $caseDir "firewall_profiles.json") -Format json -Script {
    Get-NetFirewallProfile | Select-Object Name, Enabled, LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes
}

Invoke-Safe -Name "firewall_rules_enabled" -OutFile (Join-Path $caseDir "firewall_rules_enabled.json") -Format json -Script {
    Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } |
        Select-Object DisplayName, Direction, Action, Profile
}

Invoke-Safe -Name "firewall_port_filters" -OutFile (Join-Path $caseDir "firewall_port_filters.json") -Format json -Script {
    Get-NetFirewallRule -Enabled True | Get-NetFirewallPortFilter |
        Select-Object Protocol, LocalPort, RemotePort
}

Invoke-Safe -Name "winhttp_proxy" -OutFile (Join-Path $caseDir "winhttp_proxy.txt") -Format txt -Script {
    cmd /c "netsh winhttp show proxy"
}

# ---- Network interfaces and SMB --------------------------------------------
Invoke-Safe -Name "ipconfig_all" -OutFile (Join-Path $caseDir "ipconfig_all.txt") -Format txt -Script {
    cmd /c "ipconfig /all"
}

Invoke-Safe -Name "net_ip_configuration" -OutFile (Join-Path $caseDir "net_ip_configuration.json") -Format json -Script {
    Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, DNSServer
}

Invoke-Safe -Name "net_adapters" -OutFile (Join-Path $caseDir "net_adapters.json") -Format json -Script {
    Get-NetAdapter | Select-Object Name, MacAddress, Status, LinkSpeed, InterfaceDescription
}

Invoke-Safe -Name "smb_share" -OutFile (Join-Path $caseDir "smb_shares.json") -Format json -Script {
    Get-SmbShare
}

Invoke-Safe -Name "smb_connection" -OutFile (Join-Path $caseDir "smb_connections.json") -Format json -Script {
    Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect, NumOpens
}

Invoke-Safe -Name "smb_session" -OutFile (Join-Path $caseDir "smb_sessions.json") -Format json -Script {
    Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect, SessionId
}

Invoke-Safe -Name "net_session" -OutFile (Join-Path $caseDir "net_session.txt") -Format txt -Script {
    cmd /c "net session"
}

Invoke-Safe -Name "net_use" -OutFile (Join-Path $caseDir "net_use.txt") -Format txt -Script {
    cmd /c "net use"
}

# ---- Listening ports and named pipes ---------------------------------------
Invoke-Safe -Name "listening_ports" -OutFile (Join-Path $caseDir "listening_ports.txt") -Format txt -Script {
    cmd /c "netstat -anob" | Select-String "LISTENING"
}

Invoke-Safe -Name "named_pipes" -OutFile (Join-Path $caseDir "named_pipes.txt") -Format txt -Script {
    Get-ChildItem "\\.\pipe\" | Select-Object Name, Length, CreationTime
}

# ---- Quick triage one-liner outputs ----------------------------------------
Invoke-Safe -Name "external_established_connections" -OutFile (Join-Path $caseDir "external_established_connections.txt") -Format txt -Script {
    Get-NetTCPConnection -State Established | Where-Object {
        $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)"
    } | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -EA 0
        "$($p.Name) [$($_.OwningProcess)] -> $($_.RemoteAddress):$($_.RemotePort)"
    }
}

# ---- Manifest ---------------------------------------------------------------
Invoke-Safe -Name "collection_manifest" -OutFile (Join-Path $caseDir "manifest.json") -Format json -Script {
    Get-ChildItem -Path $caseDir -File | Select-Object Name, Length, LastWriteTimeUtc
}

Write-OK "Collection complete. Output directory: $caseDir"
