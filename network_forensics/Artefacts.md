---
noteId: "b420b3d0208411f1a5821968337e5e78"
tags: []

---

# **Artifact Reference - Windows Network Forensics Tool**

_All artifacts required for past and present network connection analysis. Organized by source type._

**Tag legend: PAST** = historical connections **PRESENT** = live/current connections **PAST + PRESENT** = both

## **1\. Registry Hives**

Parsed from KAPE output. Provides long-term network configuration history, persistence mechanisms, and prior connection records.

| **Artifact** | **Location / Registry Path** | **Network Forensic Value** | **Timeline** |
| --- | --- | --- | --- |
| SYSTEM Hive | C:\\Windows\\System32\\config\\SYSTEM | NIC configuration, DNS server assignments, TCP/IP parameters, service bindings, VPN adapters | **PAST + PRESENT** |
| SOFTWARE Hive | C:\\Windows\\System32\\config\\SOFTWARE | Installed network software, VPN clients, firewall products, remote access tools, browser settings | **PAST** |
| NTUSER.DAT | C:\\Users\\&lt;username&gt;\\NTUSER.DAT | TypedURLs (IE/Edge), mapped network drives MRU, RDP connection MRU, recent UNC paths | **PAST** |
| RDP MRU | NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Servers | All RDP servers ever connected to, per user | **PAST** |
| Network Profiles | SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles | Every network ever connected to - SSID, first/last connect time, network type | **PAST** |
| Network Signatures | SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures | DNS suffix and default gateway MAC for each network profile | **PAST** |
| Firewall Rules | SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy | Windows Firewall allow/block rules - attackers may add persistent rules here | **PAST + PRESENT** |
| WinSock LSP | SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters | Layered Service Providers - malware injection point into the network stack | **PAST** |
| Run / RunOnce Keys | SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run | Persistence - check for entries fetching URLs or pointing to network tools | **PAST** |
| BITS Jobs (Registry) | SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS | Registered Background Intelligent Transfer Service jobs with URLs | **PAST** |

## **2\. Windows Event Logs**

All logs are located under C:\\Windows\\System32\\winevt\\Logs\\. KAPE will collect and preserve these. The system must have had the relevant audit policies enabled for events to be present.

_⚠ If WFP auditing was not enabled, Event IDs 5156/5157 will be absent. Check SYSTEM hive: SECURITY\\Policy\\PolAdtEv for audit config._

| **Log File** | **Full Path** | **Key Event IDs & Network Relevance** | **Timeline** |
| --- | --- | --- | --- |
| Security.evtx | C:\\Windows\\System32\\winevt\\Logs\\Security.evtx | 4624/4625 (logon/fail), 4648 (explicit creds), 4776 (NTLM), 4768/4769 (Kerberos TGT/TGS), 5156/5157/5158 (WFP connections) | **PAST + PRESENT** |
| System.evtx | C:\\Windows\\System32\\winevt\\Logs\\System.evtx | 7045 (new service install), WLAN events (10000-10002), NIC plug/unplug events | **PAST** |
| Application.evtx | C:\\Windows\\System32\\winevt\\Logs\\Application.evtx | Application-level network errors, DNS failures, BITS errors | **PAST** |
| NetworkProfile.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-NetworkProfile%4Operational.evtx | Network connect/disconnect, network category changes (Public → Domain) | **PAST** |
| RDP-RCM.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx | 1149 (RDP auth attempt + source IP), 261 (listener connected) | **PAST** |
| RDP LocalSession.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx | 21 (logon), 22 (shell start), 24 (disconnect), 25 (reconnect), 40 (disconnect reason) | **PAST** |
| SMBClient.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-SmbClient%4Connectivity.evtx | SMB connections to remote shares - lateral movement detection | **PAST** |
| SMBServer.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-SMBServer%4Audit.evtx | Incoming SMB connections accepted on this host | **PAST** |
| BITS-Client.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Bits-Client%4Operational.evtx | BITS job creation (59), completion (60) with full URL - common C2 staging mechanism | **PAST** |
| DNS-Client.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DNS-Client%4Operational.evtx | 3006 (query), 3008 (NXDOMAIN failure) - reveals domains queried even if connection failed | **PAST** |
| WinRM.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WinRM%4Operational.evtx | PowerShell remoting and WinRM session initiations - lateral movement via PSRemoting | **PAST** |
| PowerShell.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx | 4103/4104 (script block logging) - captures Invoke-WebRequest, New-Object Net.WebClient etc. | **PAST** |
| Firewall.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx | 2004/2006 (rule added/deleted) - attacker-added firewall rule persistence | **PAST** |
| TaskScheduler.evtx | C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx | 106 (task registered), 200 (action started) - network-fetching scheduled tasks | **PAST** |

## **3\. KAPE Parsed Artifacts**

Filesystem and application artifacts collected and pre-parsed by KAPE. These are the richest source of historical network activity.

_⚠ SRUDB.dat is often the single most important artifact - it records per-process network byte counts for up to 30 days even without audit logging._

| **Artifact** | **Source Location on Disk** | **Network Forensic Value** | **Timeline** |
| --- | --- | --- | --- |
| SRUM Database | C:\\Windows\\System32\\sru\\SRUDB.dat | Per-process bytes sent/received timestamped up to 30 days back - most reliable network usage history on Windows | **PAST** |
| Prefetch Files | C:\\Windows\\Prefetch\\\*.pf | Execution evidence for netstat.exe, curl.exe, psexec.exe, nmap.exe, nc.exe, mshta.exe, wscript.exe | **PAST** |
| MFT (\$MFT) | C:\\ (volume root) - \$MFT | Filesystem timeline - dropped network tools, temp files from downloads, staging directories | **PAST** |
| USN Journal (\$J) | C:\\\$Extend\\\$UsnJrnl:\$J | Fine-grained file creation/deletion - detect tool drops and cleanup operations | **PAST** |
| LNK Files | C:\\Users\\&lt;user&gt;\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\\*.lnk | Recent file access including UNC paths (\\\\server\\share) - reveals accessed network shares | **PAST** |
| JumpLists | C:\\Users\\&lt;user&gt;\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations | Per-application access history - network share paths accessed via Explorer, file managers | **PAST** |
| Chrome History | C:\\Users\\&lt;user&gt;\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History | SQLite - visited URLs, download URLs, download timestamps and file paths | **PAST** |
| Firefox History | C:\\Users\\&lt;user&gt;\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\\*.default\\places.sqlite | SQLite - visited URLs, bookmark URLs, favicon requests | **PAST** |
| Edge History | C:\\Users\\&lt;user&gt;\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History | SQLite - same schema as Chrome (Chromium-based) | **PAST** |
| IE/Edge WebCache | C:\\Users\\&lt;user&gt;\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat | ESE database - IE/legacy Edge URL history, cookie hosts, download history | **PAST** |
| WFP ETL Logs | C:\\Windows\\System32\\LogFiles\\WMI\\\*.etl | Windows Filtering Platform traces - detailed connection allow/block log at kernel level | **PAST** |
| Hosts File | C:\\Windows\\System32\\drivers\\etc\\hosts | Manual DNS overrides - attackers modify this to redirect C2 domains or block security tools | **PAST + PRESENT** |
| BITS Database | C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr\*.dat | BITS job queue - pending/completed download jobs with full URLs | **PAST + PRESENT** |
| Scheduled Tasks XML | C:\\Windows\\System32\\Tasks\\\* | XML task definitions - look for tasks with http/ftp/UNC paths in command arguments | **PAST + PRESENT** |
| PowerShell History | C:\\Users\\&lt;user&gt;\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt | Command history - Invoke-WebRequest, Start-BitsTransfer, Net.WebClient commands | **PAST** |
| Amcache.hve | C:\\Windows\\AppCompat\\Programs\\Amcache.hve | Application compatibility cache - execution evidence for network tools with file hashes | **PAST** |

## **4\. Live Collection (PowerShell / CMD)**

Run once at triage time and serialize output to JSON. Since the system is in isolation, outbound noise is minimal - any live connection is highly significant.

_⚠ Run ALL live collection commands as Administrator. Serialize each to a separate JSON file immediately - these are volatile and will change or disappear on reboot._

| **Data Point** | **Command** | **Network Forensic Value** | **Timeline** |
| --- | --- | --- | --- |
| Active TCP/UDP Connections | netstat -ano | All current ESTABLISHED, LISTENING, TIME_WAIT connections with PIDs | **PRESENT** |
| Detailed TCP State | Get-NetTCPConnection \| Select-Object \* | Richer than netstat - includes OwningProcess, State, timestamps | **PRESENT** |
| ARP Cache | arp -a | Recently communicated LAN hosts - reveals internal pivot targets | **PRESENT** |
| DNS Resolver Cache | ipconfig /displaydns | Currently cached DNS resolutions - what hostnames were resolved recently | **PRESENT** |
| DNS Cache (PS) | Get-DnsClientCache | Structured PowerShell equivalent - includes TTL, record type, data | **PRESENT** |
| Routing Table | route print | Routing anomalies - attacker-added routes to redirect traffic through rogue gateway | **PRESENT** |
| Network Adapters | ipconfig /all | Full NIC details - MAC addresses, DHCP lease info, DNS servers currently assigned | **PRESENT** |
| NetBIOS Cache | nbtstat -c | Recently resolved NetBIOS names - lateral movement target names | **PRESENT** |
| Firewall Rules | Get-NetFirewallRule \| Where-Object {\$\_.Enabled -eq 'True'} | All active firewall rules - detect attacker-added allow rules for backdoor ports | **PRESENT** |
| Listening Ports + Process | Get-NetTCPConnection -State Listen \| Select LocalPort, OwningProcess | Map every open port to a process - identify rogue listeners/backdoors | **PRESENT** |
| Running Process Network | Get-Process \| Select Id, Name, Path | Cross-reference with netstat PIDs - identify process behind suspicious connection | **PRESENT** |
| SMB Sessions | Get-SmbSession | Currently active inbound SMB sessions - active lateral movement | **PRESENT** |
| SMB Open Files | Get-SmbOpenFile | Files currently open over SMB - what an attacker may be actively reading/staging | **PRESENT** |
| Proxy Settings | netsh winhttp show proxy | System-wide proxy config - attacker may redirect all traffic through controlled proxy | **PRESENT** |
| Hosts File (live) | type C:\\Windows\\System32\\drivers\\etc\\hosts | Live read of hosts file - confirm no tampering vs KAPE copy | **PRESENT** |

## **5\. Recommended KAPE Targets**

Use the following KAPE targets/modules to ensure all required artifacts above are collected:

- **!SANS_Triage** - Broad collection - registry, event logs, prefetch, browser history, SRUM
- **EventLogs** - All .evtx files under winevt\\Logs
- **RegistryHives** - SYSTEM, SOFTWARE, NTUSER.DAT, Amcache
- **SRUM** - SRUDB.dat - network usage history
- **Prefetch** - C:\\Windows\\Prefetch\\\*.pf
- **BrowserHistory** - Chrome, Firefox, Edge SQLite databases
- **FileSystem** - \$MFT, \$UsnJrnl, LNK files, JumpLists
- **ScheduledTasks** - C:\\Windows\\System32\\Tasks\\\*
- **BITSFiles** - BITS database and event log

## **6\. Artifact Priority Matrix**

Triage order when time is limited. P1 artifacts yield the highest signal with the least analysis effort.

| **Priority** | **Artifact** | **Reason** |
| --- | --- | --- |
| **P1** | SRUDB.dat | 30-day per-process network bytes - works even with no audit logging |
| **P1** | Security.evtx (5156/5157) | WFP connection log with process, IP, port, direction - most complete network log |
| **P1** | netstat -ano + Get-NetTCPConnection | Snapshot of all live connections at triage time |
| **P1** | ipconfig /displaydns + Get-DnsClientCache | Reveals recently resolved hostnames - volatile, gone on reboot |
| **P2** | Security.evtx (4624/4648) | Network logon events - lateral movement and remote access |
| **P2** | RDP-RCM.evtx (1149) | RDP source IPs - attackers often enter via RDP |
| **P2** | BITS-Client.evtx + qmgr\*.dat | Download jobs with URLs - used for stealthy C2 staging |
| **P2** | Prefetch (network tool binaries) | Proves execution of netcat, nmap, psexec, curl, etc. |
| **P3** | Browser SQLite DBs | User-context HTTP activity - phishing click, malicious download origin |
| **P3** | NTUSER.DAT (RDP MRU, TypedURLs) | Targets and URLs the user manually typed |
| **P3** | Network Profiles (SOFTWARE hive) | Every network ever joined - establishes location/context history |
| **P3** | \$MFT + USN Journal | Timeline of tool drops and staged files - corroborates connection events |