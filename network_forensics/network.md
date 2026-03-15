---
noteId: "275495b0208511f18691671a91c5ffce"
tags: []

---

# Live Windows Network Forensics — Commands for Correlation & Analysis

Here's a structured breakdown of the most valuable commands, grouped by forensic category:

---

## 🔌 Active Connections & Sockets

```powershell
# Full TCP/UDP state with PID — your primary triage command
netstat -ano

# Same but resolves hostnames (slower, but useful)
netstat -anob

# Correlate PIDs to process names directly
netstat -ano | Select-String "ESTABLISHED"

# PowerShell equivalent with richer object output
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Sort-Object State
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
```

> **Correlate with:** Process list (PID → process name → parent → binary path)

---

## 🧠 Process ↔ Network Correlation

```powershell
# Map every network-connected PID to its process details
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = $_.State
        PID           = $_.OwningProcess
        ProcessName   = $proc.Name
        Path          = $proc.Path
    }
} | Format-Table -AutoSize

# Check what DLLs a suspicious process has loaded (DLL injection check)
Get-Process -Id <PID> | Select-Object -ExpandProperty Modules
```

---

## 🗺️ DNS & Name Resolution Cache

```powershell
# Full DNS resolver cache — reveals all recently resolved domains
Get-DnsClientCache | Select-Object Entry, RecordName, Data, TimeToLive | Sort-Object Entry

# CMD equivalent
ipconfig /displaydns
```

> **Why it matters:** Malware C2 domains show up here even if the connection is already closed.

---

## 🚦 Routing & ARP — Network Positioning

```powershell
# ARP table — maps IP ↔ MAC, detect ARP poisoning or rogue hosts
arp -a
Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex

# Routing table — detect rogue routes or traffic redirection
route print
Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceIndex
```

---

## 🔥 Firewall State & Rules

```powershell
# Current firewall profile states
netsh advfirewall show allprofiles

# All active rules (look for unusual allow rules on high ports)
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } |
    Select-Object DisplayName, Direction, Action, Profile |
    Sort-Object Direction

# Rules with port details
Get-NetFirewallRule -Enabled True | Get-NetFirewallPortFilter |
    Select-Object Protocol, LocalPort, RemotePort
```

---

## 📡 Network Interfaces & Config

```powershell
# Full interface config — IPs, MACs, DNS servers
ipconfig /all
Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, DNSServer

# Detect promiscuous mode (sniffing indicator)
Get-NetAdapter | Select-Object Name, MacAddress, Status, PromiscuousMode

# SMB shares — lateral movement vector
Get-SmbShare
Get-SmbConnection        # Active SMB sessions TO other hosts
Get-SmbSession           # Inbound SMB sessions FROM other hosts
net session
net use
```

---

## 🕵️ Listening Services & Named Pipes

```powershell
# All listening ports with owning service
netstat -anob | findstr "LISTENING"

# Named pipes — used by malware for local C2 / lateral movement
[System.IO.Directory]::GetFiles("\\.\pipe\") 

# PowerShell alternative
Get-ChildItem \\.\pipe\
```

---

## 📋 Recently Used Connections (Historical)

```powershell
# Recently accessed network paths (from registry)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"

# RDP connection history (targets this machine connected TO)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s

# Network profile history
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*" |
    Select-Object ProfileName, DateCreated, DateLastConnected
```

---

## ⚡ Quick Triage One-Liners

```powershell
# Find processes with ESTABLISHED connections to non-RFC1918 IPs
Get-NetTCPConnection -State Established | Where-Object {
    $_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)"
} | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -EA 0
    "$($p.Name) [$($_.OwningProcess)] → $($_.RemoteAddress):$($_.RemotePort)"
}

# Spot unsigned network-connected binaries
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -EA 0
    if ($proc.Path) {
        $sig = Get-AuthenticodeSignature $proc.Path
        if ($sig.Status -ne "Valid") {
            "$($proc.Name) | $($_.RemoteAddress):$($_.RemotePort) | Sig: $($sig.Status)"
        }
    }
}
```

---

## 🔗 Correlation Workflow

```
netstat / Get-NetTCPConnection
        ↓
   Suspicious IP:Port
        ↓
   Owning PID  ──→  Get-Process (name, path, parent PID)
        ↓                    ↓
  DNS Cache             Authenticode Signature check
  (what domain?)        (is the binary signed?)
        ↓                    ↓
  VirusTotal / Threat Intel   Loaded DLLs / Modules
        ↓
  Firewall rules / SMB sessions / Registry artifacts
```

---

## 💾 Saving Output for Analysis

```powershell
# Export everything to a timestamped file
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
Get-NetTCPConnection | Export-Csv "C:\forensics\tcp_$ts.csv" -NoTypeInformation
netstat -ano | Out-File "C:\forensics\netstat_$ts.txt"
Get-DnsClientCache | Export-Csv "C:\forensics\dns_$ts.csv" -NoTypeInformation
```

The key forensic principle here is **cross-referencing**: a connection alone isn't suspicious — it becomes suspicious when the owning process has no valid signature, lives in `%TEMP%`, has a spoofed parent, or resolves to a known bad domain. Always correlate across layers.