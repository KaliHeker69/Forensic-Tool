# Browser Forensics Analysis & Correlation Checklist

### System Information Collection
- [ ] Document Windows version and build number
- [ ] Record installed browsers and versions:
  - [ ] Chrome: Version _______
  - [ ] Edge: Version _______
  - [ ] Firefox: Version _______
  - [ ] Internet Explorer: Version _______
  - [ ] Other: _______
- [ ] Identify all user accounts on system
- [ ] Map user account names to SIDs
- [ ] Document system locale and keyboard layout
- [ ] Check if system clock was accurate (compare with reliable source)
- [ ] Note any time discrepancies or clock tampering

### Profile Identification
- [ ] Identify Chrome profiles in `\AppData\Local\Google\Chrome\User Data\`
  - [ ] Default profile
  - [ ] Profile 1, 2, 3... (if multiple)
  - [ ] Note profile names from Preferences files
- [ ] Identify Edge profiles in `\AppData\Local\Microsoft\Edge\User Data\`
- [ ] Identify Firefox profiles from profiles.ini
  - [ ] Profile path: ___________________
  - [ ] Profile name: ___________________
- [ ] Check for portable browser installations
- [ ] Document sync status (Chrome Sync, Firefox Sync, Edge Sync)

### Investigation Scope Definition
- [ ] Define time window of interest: From _______ To _______
- [ ] Identify specific activities or indicators to search for
- [ ] List keywords or domains of interest
- [ ] Define investigation goals:
  - [ ] Malware infection vector
  - [ ] Data exfiltration
  - [ ] Unauthorized access
  - [ ] Insider threat
  - [ ] Credential theft
  - [ ] Phishing investigation
  - [ ] Timeline reconstruction
  - [ ] Other: ___________________

---

## Phase 2: Artifact Collection & Extraction

### Chrome/Edge (Chromium) Artifacts

#### History Database Analysis
**File:** `History` (SQLite database)

- [ ] Extract History database to working directory
- [ ] Check for Write-Ahead Log (History-wal, History-journal)
- [ ] Open database in SQLite browser
- [ ] Document database schema version

**URLs Table Analysis:**
- [ ] Query all URLs in date range of interest
- [ ] Document total number of unique URLs visited
- [ ] Export URLs table to CSV for analysis
- [ ] Identify suspicious domains (check against threat intel)
- [ ] Flag typosquatting domains
- [ ] Note URLs with IP addresses instead of domains
- [ ] Check for URLs with unusual ports
- [ ] Identify data exfiltration sites (file sharing, cloud storage)
- [ ] Look for job search/recruitment sites (insider threat)
- [ ] Check for competitor websites
- [ ] Identify remote access tool download sites
- [ ] Note cryptocurrency/dark web related URLs
- [ ] Check for webmail access (Gmail, Outlook, ProtonMail)

**Visits Table Analysis:**
- [ ] Query visit patterns by time of day
- [ ] Identify unusual access times (outside work hours)
- [ ] Count visits to each URL
- [ ] Analyze visit_source field:
  - [ ] Type 0 (link) - Most visits
  - [ ] Type 1 (typed) - Manually entered
  - [ ] Type 2 (bookmark) - From bookmarks
  - [ ] Type 3 (auto_subframe) - Embedded content
- [ ] Trace referrer chains to identify how user arrived at sites
- [ ] Look for broken referrer chains (potential manual URL entry)
- [ ] Identify rapid succession visits (automated activity?)

**Downloads Table Analysis:**
- [ ] Extract all downloads in investigation timeframe
- [ ] Document download paths and verify file existence
- [ ] List all downloaded files:
  - Filename: _______ | Source URL: _______ | Timestamp: _______
  - Filename: _______ | Source URL: _______ | Timestamp: _______
  - Filename: _______ | Source URL: _______ | Timestamp: _______
- [ ] Check download states (interrupted, completed, cancelled)
- [ ] Note dangerous file types (.exe, .dll, .bat, .ps1, .vbs, .jar)
- [ ] Identify archives that may contain malware (.zip, .rar, .7z)
- [ ] Check for document exploits (.doc, .xls, .pdf with macros)
- [ ] Document MIME types vs. file extensions (mismatch = suspicious)
- [ ] Note downloads from suspicious domains
- [ ] Check for renamed downloads (original name vs. saved name)
- [ ] Identify tool downloads (putty, remote desktop, password crackers)

**Search Queries Analysis:**
- [ ] Extract search queries from URL parameters
  - Google: `q=` parameter
  - Bing: `q=` parameter
  - DuckDuckGo: `q=` parameter
- [ ] Document all search queries related to:
  - [ ] How to disable security software
  - [ ] Data destruction methods
  - [ ] Encryption tools
  - [ ] Anonymous browsing
  - [ ] Competitor information
  - [ ] Job searching
  - [ ] Personal problems/grievances
  - [ ] Technical how-to queries related to incident

**Keyword Search in History:**
- [ ] Search for specific keywords across all URLs:
  - Keyword: _______ | Hits: _______ | Review: [ ]
  - Keyword: _______ | Hits: _______ | Review: [ ]
  - Keyword: _______ | Hits: _______ | Review: [ ]

#### Cookie Database Analysis
**File:** `Cookies` or `Network\Cookies` (SQLite, encrypted)

- [ ] Extract Cookies database
- [ ] Note encryption status (DPAPI encrypted)
- [ ] Attempt decryption with user credentials
- [ ] If encrypted, document inability to decrypt
- [ ] Use ChromeCookiesView or Hindsight for extraction

**Cookie Analysis:**
- [ ] Extract all cookies in timeframe
- [ ] Identify authentication cookies (session tokens)
- [ ] Look for persistent vs. session cookies
- [ ] Check cookie expiration dates
- [ ] Identify tracking cookies (Google Analytics, Facebook, etc.)
- [ ] Note cookies from suspicious domains
- [ ] Check for stolen/reused session tokens (compare with logs)
- [ ] Document last access times for critical site cookies
- [ ] Identify cookies with "Secure" and "HttpOnly" flags
- [ ] Look for cookies set by known malicious domains

**Key Site Cookies to Document:**
- [ ] Banking/financial sites: ___________________
- [ ] Email services: ___________________
- [ ] Cloud storage: ___________________
- [ ] Corporate portals: ___________________
- [ ] Social media: ___________________
- [ ] E-commerce: ___________________

#### Cache Analysis
**Location:** `Cache\Cache_Data\` or `Code Cache\`

- [ ] Extract cache entries using ChromeCacheView
- [ ] Sort cache by last accessed time
- [ ] Filter cache for investigation timeframe
- [ ] Document total cache size and entry count

**Cache Content Analysis:**
- [ ] Extract images from cache
  - [ ] Review for sensitive content
  - [ ] Document suspicious images
  - [ ] Note screenshots or internal documents
- [ ] Extract HTML pages from cache
  - [ ] Review for phishing pages
  - [ ] Check for credential entry forms
  - [ ] Look for malicious scripts
- [ ] Extract JavaScript files
  - [ ] Check for obfuscated code
  - [ ] Look for data exfiltration scripts
  - [ ] Note exploit code
- [ ] Extract CSS and other resources
- [ ] Check for executables or archives in cache (unusual)
- [ ] Document URLs of cached resources
- [ ] Correlate cache access times with History database

**Specific Cache Searches:**
- [ ] Search cache for "password"
- [ ] Search cache for "admin"
- [ ] Search cache for "confidential"
- [ ] Search cache for company-specific terms
- [ ] Search cache for PII (SSN patterns, credit cards)

#### Login Data Analysis
**File:** `Login Data` (SQLite, encrypted)

- [ ] Extract Login Data database
- [ ] Use ChromePass or Hindsight for decryption
- [ ] Document decryption success/failure

**Credential Analysis:**
- [ ] List all stored credentials:
  - Site: _______ | Username: _______ | Date Created: _______
  - Site: _______ | Username: _______ | Date Created: _______
  - Site: _______ | Username: _______ | Date Created: _______
- [ ] Identify credentials to sensitive sites
- [ ] Check for password reuse across sites
- [ ] Note recently added credentials (around incident time)
- [ ] Look for credentials to suspicious sites
- [ ] Document corporate credential exposure
- [ ] Check for credentials to competitor sites
- [ ] Note remote access credentials (VPN, RDP)
- [ ] Identify cloud storage service credentials

**Password Security Analysis:**
- [ ] Check date_last_used field for credential access
- [ ] Look for credentials never used (pre-loaded by malware?)
- [ ] Document times_used field for frequency analysis
- [ ] Note any credential modifications during investigation period

#### Web Data (Autofill) Analysis
**File:** `Web Data` (SQLite)

- [ ] Extract Web Data database
- [ ] Open in DB Browser for SQLite

**Autofill Table Analysis:**
- [ ] Extract all autofill entries
- [ ] Document PII collected:
  - [ ] Full names
  - [ ] Email addresses
  - [ ] Phone numbers
  - [ ] Physical addresses
  - [ ] Credit card numbers (last 4 digits visible)
  - [ ] SSN or tax ID
- [ ] Check count field for usage frequency
- [ ] Review date_created and date_last_used
- [ ] Identify forms submitted with sensitive data

**Autofill_profiles Table:**
- [ ] Extract saved address information
- [ ] Document complete profiles stored
- [ ] Note multiple profiles (work vs. personal)

**Credit_cards Table:**
- [ ] Document stored payment methods (encrypted)
- [ ] Note card brands and expiration dates
- [ ] Check use_count and use_date

**Keywords Table:**
- [ ] Extract custom search engine entries
- [ ] Look for unusual search engines added
- [ ] Note search shortcuts

#### Bookmarks Analysis
**File:** `Bookmarks` (JSON)

- [ ] Extract Bookmarks file
- [ ] Parse JSON structure
- [ ] Document bookmark organization

**Bookmark Content Analysis:**
- [ ] List all bookmarked URLs
- [ ] Note bookmark creation dates (date_added)
- [ ] Check last modification times (date_last_used, if available)
- [ ] Organize bookmarks by folder:
  - Work-related: ___________________
  - Personal: ___________________
  - Suspicious: ___________________
- [ ] Identify bookmarks to:
  - [ ] File sharing services
  - [ ] Remote access tools
  - [ ] Job search sites
  - [ ] Competitor sites
  - [ ] Dark web links (.onion)
  - [ ] Anonymous browsing tools
  - [ ] Security tool documentation

#### Preferences Analysis
**File:** `Preferences` (JSON)

- [ ] Extract Preferences file
- [ ] Parse JSON and review settings

**Key Settings to Document:**
- [ ] Default download location
- [ ] Download prompting (enabled/disabled)
- [ ] Safe browsing status (enabled/disabled)
- [ ] Pop-up blocking status
- [ ] JavaScript enabled/disabled
- [ ] DNS-over-HTTPS settings
- [ ] Proxy configuration
- [ ] Default search engine
- [ ] Homepage and startup pages
- [ ] Extensions enabled/disabled globally

**Security Indicators:**
- [ ] Check for security setting changes during investigation period
- [ ] Note any disabled security features
- [ ] Document unusual proxy configurations
- [ ] Check for VPN or Tor settings

**Profile Preferences:**
- [ ] User name associated with profile
- [ ] Sync status and last sync time
- [ ] Profile avatar and customization

#### Extensions Analysis
**Location:** `Extensions\[Extension_ID]\`

- [ ] List all installed extensions:
  - Extension Name: _______ | ID: _______ | Version: _______
  - Extension Name: _______ | ID: _______ | Version: _______
  - Extension Name: _______ | ID: _______ | Version: _______
- [ ] For each extension, extract manifest.json

**Per-Extension Analysis:**
Extension: ___________________
- [ ] Document installation date (folder creation time)
- [ ] Review manifest.json permissions requested:
  - [ ] `<all_urls>` - Access to all websites
  - [ ] `webRequest` - Intercept web traffic
  - [ ] `cookies` - Access cookies
  - [ ] `tabs` - Access tab information
  - [ ] `history` - Access browsing history
  - [ ] `downloads` - Manage downloads
  - [ ] `clipboardWrite` - Write to clipboard
  - [ ] `storage` - Store data locally
  - [ ] `webRequestBlocking` - Block requests
  - [ ] Other dangerous permissions: ___________________
- [ ] Check if sideloaded (not from Chrome Web Store)
- [ ] Note if extension has native messaging permission
- [ ] Review background scripts for malicious behavior
- [ ] Check content scripts for data exfiltration
- [ ] Document network connections in extension code
- [ ] Search for obfuscated JavaScript
- [ ] Check extension against Chrome Web Store:
  - [ ] Still available in store
  - [ ] Reviews/ratings
  - [ ] User count
  - [ ] Last updated
  - [ ] Developer information
- [ ] VirusTotal scan of extension folder

**Extension Red Flags:**
- [ ] Extension installed around time of incident
- [ ] Extension from unknown developer
- [ ] Extension with very few users
- [ ] Extension with excessive permissions
- [ ] Extension not found in official store
- [ ] Obfuscated code in extension
- [ ] External network connections to suspicious domains

#### Top Sites Analysis
**File:** `Top Sites` (SQLite)

- [ ] Extract Top Sites database
- [ ] Query top_sites table
- [ ] List most frequently visited sites
- [ ] Note URL ranking by frequency
- [ ] Check for suspicious sites in top visits
- [ ] Document visit patterns

#### Session Data Analysis
**Files:** `Current Session`, `Current Tabs`, `Last Session`, `Last Tabs`

- [ ] Extract session files if browser was open during incident
- [ ] Parse session data (binary format)
- [ ] Document open tabs at time of acquisition
- [ ] List recently closed tabs
- [ ] Check for tabs opened to suspicious sites
- [ ] Note private/incognito indicators in process

#### Favicons
**File:** `Favicons` (SQLite)

- [ ] Extract Favicons database
- [ ] Match favicons to visited sites
- [ ] Extract favicon images for visual confirmation
- [ ] Use for additional site identification

### Firefox Artifacts

#### Places Database Analysis
**File:** `places.sqlite`

- [ ] Extract places.sqlite
- [ ] Check for -wal and -journal files
- [ ] Document database version

**moz_places Table:**
- [ ] Extract all URLs in investigation timeframe
- [ ] Query URL visit counts
- [ ] Check hidden field (hidden=1 for embedded content)
- [ ] Note typed field (manually typed URLs)
- [ ] Document foreign visits from downloads
- [ ] List all URLs: ___________________

**moz_historyvisits Table:**
- [ ] Extract visit timestamps
- [ ] Map visits to URLs via place_id
- [ ] Analyze visit_type:
  - Type 1: Link
  - Type 2: Typed URL
  - Type 3: Bookmark
  - Type 4: Embed
  - Type 5: Permanent redirect
  - Type 6: Temporary redirect
  - Type 7: Download
  - Type 8: Framed link
- [ ] Document from_visit (referrer tracking)
- [ ] Build visit chains

**moz_bookmarks Table:**
- [ ] Extract all bookmarks
- [ ] Build folder hierarchy
- [ ] Note bookmark creation dates (dateAdded)
- [ ] Check last modification (lastModified)
- [ ] List bookmarked URLs

**moz_inputhistory Table:**
- [ ] Extract form input history
- [ ] Link inputs to specific URLs (place_id)
- [ ] Document use_count for each input

**moz_annos Table (Annotations):**
- [ ] Extract download metadata
- [ ] Check for additional URL metadata

#### Cookies Database
**File:** `cookies.sqlite`

- [ ] Extract cookies.sqlite
- [ ] Query moz_cookies table
- [ ] Extract all cookies in timeframe
- [ ] Document cookie domains, names, values
- [ ] Check expiry timestamps
- [ ] Note creation and last access times
- [ ] Analyze same as Chrome cookies (see above)

#### Form History
**File:** `formhistory.sqlite`

- [ ] Extract formhistory.sqlite
- [ ] Query moz_formhistory table
- [ ] List all field names and values entered:
  - Field: _______ | Value: _______ | Count: _______
  - Field: _______ | Value: _______ | Count: _______
- [ ] Check timesUsed for frequency
- [ ] Review firstUsed and lastUsed timestamps
- [ ] Document sensitive information in forms
- [ ] Note search queries

#### Login Data
**File:** `logins.json` (encrypted)

- [ ] Extract logins.json
- [ ] Check for key4.db (encryption key database)
- [ ] Use PasswordFox or firefox_decrypt.py
- [ ] Document master password status
- [ ] If decrypted, list all credentials:
  - Site: _______ | Username: _______ | Created: _______
- [ ] Analyze same as Chrome Login Data

#### Session Store
**File:** `sessionstore.jsonlz4` or `sessionstore-backups\recovery.jsonlz4`

- [ ] Extract session files
- [ ] Decompress LZ4 format:
  ```python
  import lz4.block
  with open('sessionstore.jsonlz4', 'rb') as f:
      f.read(8)  # Skip magic bytes
      data = lz4.block.decompress(f.read())
  ```
- [ ] Parse JSON structure
- [ ] Document open tabs and windows
- [ ] Extract tab URLs
- [ ] Check for form data in session
- [ ] Note private browsing windows (if any)

#### Cache Analysis
**Location:** `cache2\entries\`

- [ ] Use MozillaCacheView to parse cache
- [ ] Extract cache entries from timeframe
- [ ] Analyze same as Chrome cache (see above)
- [ ] Check cache2\doomed\ for deleted entries

#### Addons/Extensions
**Location:** `extensions\`

- [ ] List all installed addons from extensions folder
- [ ] Check addons.json for metadata
- [ ] For each addon:
  - [ ] Name: _______ | ID: _______ | Version: _______
  - [ ] Installation date: _______
  - [ ] Enabled status: _______
  - [ ] Source: _______ (AMO, sideloaded)
- [ ] Extract and review manifest.json
- [ ] Check permissions requested
- [ ] Analyze addon code for malicious behavior
- [ ] Cross-reference with Mozilla addons site
- [ ] Document any sideloaded addons

#### Permissions
**File:** `permissions.sqlite`

- [ ] Extract permissions.sqlite
- [ ] Query moz_perms table
- [ ] Document site-specific permissions granted:
  - Site: _______ | Permission: _______ | Capability: _______
- [ ] Note camera, microphone, location permissions
- [ ] Check for unusual permission grants

#### Downloads
**File:** `downloads.json`

- [ ] Extract downloads.json
- [ ] Parse JSON structure
- [ ] List all downloads
- [ ] Document same information as Chrome downloads
- [ ] Cross-reference with places.sqlite downloads

### Internet Explorer Artifacts

#### WebCacheV*.dat Analysis
**File:** `WebCacheV01.dat` or `WebCacheV24.dat` (ESE database)

- [ ] Locate WebCache database (usually in `\AppData\Local\Microsoft\Windows\WebCache\`)
- [ ] Use ESEDatabaseView to open
- [ ] Export all containers

**Container_1 (History):**
- [ ] Export history records
- [ ] Document URLs visited
- [ ] Note access times and counts
- [ ] Analyze similar to Chrome history

**Container_2 (Cookies):**
- [ ] Export cookie records
- [ ] Document cookie domains and values
- [ ] Check timestamps

**Container_3 (Cache):**
- [ ] Export cache entries
- [ ] Document cached resources
- [ ] Extract files of interest

**Additional Containers:**
- [ ] Review all containers for relevant data
- [ ] Document container purposes

#### Typed URLs (Registry)
**Location:** Registry

- [ ] Extract from Registry:
  ```
  HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs
  ```
- [ ] List all manually typed URLs:
  - url1: ___________________
  - url2: ___________________
  - url3: ___________________
- [ ] Document up to 50 most recent URLs

#### Browser Helper Objects (BHOs)
**Location:** Registry

- [ ] Check installed BHOs:
  ```
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
  ```
- [ ] Document each BHO CLSID
- [ ] Identify BHO purpose
- [ ] Check for malicious BHOs
- [ ] Note BHO installation dates (folder timestamps)

---

## Phase 3: System-Wide Correlation

### DNS Cache Correlation

- [ ] Extract DNS cache (if live system):
  ```
  ipconfig /displaydns > dns_cache.txt
  ```
- [ ] Extract DNS cache from registry (dead system):
  ```
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
  ```
- [ ] List all DNS entries with TTL
- [ ] Match DNS queries with browser history
- [ ] Identify DNS queries without corresponding browser history:
  - Query: _______ | Timestamp: _______ | No browser match: [ ]
  - Query: _______ | Timestamp: _______ | No browser match: [ ]
- [ ] Document malware C2 domains in DNS cache
- [ ] Check for DNS tunneling indicators (long subdomain names)
- [ ] Note any DGA (Domain Generation Algorithm) patterns

### Prefetch Analysis

**Location:** `C:\Windows\Prefetch\`

- [ ] Extract all browser-related prefetch files:
  - [ ] CHROME.EXE-*.pf
  - [ ] MSEDGE.EXE-*.pf
  - [ ] FIREFOX.EXE-*.pf
  - [ ] IEXPLORE.EXE-*.pf
- [ ] Use PECmd to parse prefetch files
- [ ] Document browser execution counts
- [ ] Note first execution times (malware downloaded?)
- [ ] Check last execution times
- [ ] Review files and directories referenced in prefetch
- [ ] Identify unusual file access patterns

### Windows Event Logs

**Security.evtx:**
- [ ] Extract Security event log
- [ ] Filter for investigation timeframe
- [ ] Document user logon events (EID 4624):
  - Time: _______ | User: _______ | Logon Type: _______
- [ ] Note logoff events (EID 4634)
- [ ] Check for failed logons (EID 4625)
- [ ] Correlate logon times with browser activity
- [ ] Identify remote logons (Type 10)
- [ ] Check for network logons (Type 3)

**System.evtx:**
- [ ] Document system boot times (EID 6005, 6006)
- [ ] Note shutdown times (EID 6008 for unexpected)
- [ ] Correlate with browser activity timeline

**Application Logs:**
- [ ] Check for browser crash events
- [ ] Note application errors related to browsers

**Microsoft-Windows-WebCache/Operational.evtx:**
- [ ] Extract if available
- [ ] Review cache operations
- [ ] Note any corruption or clearing events

### Jump Lists

**Location:** `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`

- [ ] Identify browser jump list files:
  - Chrome: `d64a5813-e2f8-5e4f-b75e-0b26e2a2a6de.automaticDestinations-ms`
  - Firefox: `6ae5d4e8-d5db-59a8-b6c1-c46f4e8a50a7.automaticDestinations-ms`
  - Edge: `e39e6a1f-e3b8-5607-8e4e-7dcf7e388e39.automaticDestinations-ms`
  - IE: `9c04802e-c5e0-4ca4-8e0f-7f366c4e8a4f.automaticDestinations-ms`
- [ ] Parse jump lists with JLECmd
- [ ] Extract recent URLs accessed via jump lists
- [ ] Document access times
- [ ] Compare with browser history for consistency
- [ ] Note any missing entries (history clearing?)

### NTFS Filesystem Metadata

**$MFT (Master File Table):**
- [ ] Parse $MFT with MFTECmd
- [ ] Extract file entries for browser folders
- [ ] Document file creation times:
  - History database created: _______
  - Login Data created: _______
  - Extension folders created: _______
- [ ] Note file modification times
- [ ] Check MFT record number changes (file replacements)
- [ ] Identify deleted files in browser directories

**$UsnJrnl (Update Sequence Number Journal):**
- [ ] Parse $UsnJrnl
- [ ] Track file system changes to browser artifacts
- [ ] Document file operations:
  - [ ] File creation events
  - [ ] File deletion events
  - [ ] File rename events
  - [ ] File overwrite events
- [ ] Identify browser database clearing operations
- [ ] Note timestamp of privacy-mode activities

**Zone.Identifier ADS:**
- [ ] Check downloaded files for Zone.Identifier stream:
  ```powershell
  Get-Item -Path "C:\Path\To\File" -Stream Zone.Identifier
  ```
- [ ] For each download, document:
  - ZoneId: _______ (3 = Internet)
  - HostUrl: _______ (download URL)
  - ReferrerUrl: _______ (source page)
- [ ] Correlate with browser download history
- [ ] Identify downloads missing ZoneId (manual copy?)

### Windows Registry Artifacts

**UserAssist:**
- [ ] Extract UserAssist keys:
  ```
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
  ```
- [ ] Decode ROT13-encoded values
- [ ] Document browser executable runs
- [ ] Note run counts and last run times
- [ ] Correlate with other timeline data

**MUICache:**
- [ ] Extract:
  ```
  HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
  ```
- [ ] Document browser-related entries
- [ ] Check for portable browser paths

**RecentDocs:**
- [ ] Extract:
  ```
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
  ```
- [ ] Check for recently accessed browser-related files
- [ ] Document downloaded files opened

**File Extensions:**
- [ ] Check default browser association:
  ```
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
  ```
- [ ] Note .html, .htm associations
- [ ] Document any changes to defaults

### ShimCache (AppCompatCache)

- [ ] Extract ShimCache from Registry:
  ```
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
  ```
- [ ] Parse with AppCompatCacheParser
- [ ] Look for browser executable entries
- [ ] Document execution indicators
- [ ] Note file paths (portable browsers, suspicious locations)

### BAM/DAM (Background Activity Moderator)

- [ ] Extract BAM data:
  ```
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
  ```
- [ ] Parse browser execution timestamps
- [ ] Correlate with UserAssist and ShimCache
- [ ] Document full execution paths

### Recycle Bin

- [ ] Check Recycle Bin for deleted browser artifacts:
  - [ ] Database files (.db, .sqlite)
  - [ ] Downloaded files
  - [ ] Browser installers
  - [ ] Extension files
- [ ] Document deletion timestamps ($I files)
- [ ] Note original file paths
- [ ] Recover deleted files for analysis

### File Carving

- [ ] Carve unallocated space for deleted browser databases
- [ ] Use Photorec/Scalpel for SQLite databases
- [ ] Search for deleted downloads
- [ ] Recover deleted cache files
- [ ] Document all recovered artifacts

### Memory Analysis (if memory dump available)

- [ ] Use Volatility Framework on memory image
- [ ] Identify browser processes:
  ```
  volatility -f memory.raw --profile=Win10x64 pslist | grep chrome/firefox/msedge
  ```
- [ ] Dump browser process memory:
  ```
  volatility -f memory.raw --profile=Win10x64 memdump -p [PID] -D output/
  ```
- [ ] Extract strings from process memory
- [ ] Search for URLs in memory:
  ```
  strings -a process_dump.dmp | grep -E "http://|https://"
  ```
- [ ] Look for credentials in memory
- [ ] Extract private browsing session data
- [ ] Document JavaScript code in memory
- [ ] Identify injected code or malware

### Network Artifacts (if available)

**Packet Captures:**
- [ ] Analyze PCAP files for browser traffic
- [ ] Filter HTTP/HTTPS traffic
- [ ] Document visited domains from SNI (TLS)
- [ ] Check for unencrypted HTTP traffic
- [ ] Identify data exfiltration (large POST requests)
- [ ] Note C2 communications

**Firewall Logs:**
- [ ] Extract Windows Firewall logs
- [ ] Filter for browser processes
- [ ] Document outbound connections
- [ ] Note blocked connections
- [ ] Correlate with browser history

**Proxy Logs:**
- [ ] Obtain proxy logs if environment uses proxy
- [ ] Match logged URLs with browser history
- [ ] Identify discrepancies (malware bypassing browser?)
- [ ] Document user-agent strings

---

## Phase 4: Timeline Construction

### Timeline Data Sources

- [ ] Compile all timestamp data from:
  - [ ] Chrome History (visit timestamps)
  - [ ] Chrome Downloads (download timestamps)
  - [ ] Edge History (visit timestamps)
  - [ ] Firefox places.sqlite (visit timestamps)
  - [ ] IE WebCache (access timestamps)
  - [ ] File system timestamps (MFT)
  - [ ] Prefetch execution times
  - [ ] Event Logs (logon/logoff)
  - [ ] Registry keys (last write times)
  - [ ] Jump Lists (access times)
  - [ ] USN Journal (file operations)

### Timeline Creation

- [ ] Use log2timeline/Plaso to create super timeline
- [ ] Export timeline to CSV
- [ ] Import into TimelineExplorer or similar tool
- [ ] Normalize all timestamps to UTC
- [ ] Sort chronologically

### Timeline Analysis

**Initial Incident Indicators:**
- [ ] Identify T-0 (time of incident/compromise)
- [ ] Document T-1 activity (immediately before)
- [ ] Document T+1 activity (immediately after)
- [ ] Mark timeline with key events:
  - [ ] User logon
  - [ ] Suspicious website visit
  - [ ] Malware download
  - [ ] Malware execution
  - [ ] C2 communication
  - [ ] Data exfiltration
  - [ ] Evidence destruction attempts

**Activity Patterns:**
- [ ] Identify working hours vs. after-hours activity
- [ ] Note weekend activity
- [ ] Check for automated/scripted behavior (rapid actions)
- [ ] Document activity bursts
- [ ] Identify gaps in activity (clearing evidence?)

**Correlation Windows:**
- [ ] For each suspicious activity, check ±15 minutes:
  - [ ] Browser history
  - [ ] Downloads
  - [ ] File system changes
  - [ ] Process execution
  - [ ] Network connections
  - [ ] User actions

### Timeline Export

- [ ] Export filtered timeline for investigation period
- [ ] Create timeline visualizations
- [ ] Document key events with context
- [ ] Prepare timeline for reporting

---

## Phase 5: Advanced Correlation Analysis

### User Behavior Analysis

**Establish Baseline:**
- [ ] Identify typical browsing patterns:
  - [ ] Most visited sites
  - [ ] Typical working hours
  - [ ] Download frequency
  - [ ] Search patterns
- [ ] Document normal behavior metrics:
  - Average sites visited per day: _______
  - Typical logon time: _______
  - Typical logoff time: _______
  - Common domains: ___________________

**Anomaly Detection:**
- [ ] Compare incident timeframe to baseline
- [ ] Identify deviations:
  - [ ] Unusual sites visited
  - [ ] Atypical access times
  - [ ] Increased download activity
  - [ ] New tools/software searched
  - [ ] Change in browsing patterns
- [ ] Document all anomalies: ___________________

### Download-to-Execution Correlation

For each downloaded executable:
- File: _______________________
- [ ] Download timestamp: _______
- [ ] Download source URL: _______
- [ ] File creation timestamp (MFT): _______
- [ ] Zone.Identifier check: _______
- [ ] Prefetch first execution: _______
- [ ] Time gap between download and execution: _______
- [ ] Process creation event log: _______
- [ ] Network activity post-execution: _______
- [ ] Browser activity change post-execution: _______

**Questions to Answer:**
- [ ] Was file executed immediately after download?
- [ ] Did file execution correlate with new browser activity?
- [ ] Was there C2 communication after execution?
- [ ] Did user behavior change after execution?

### Credential Access Correlation

**Login Data Analysis:**
- [ ] For each credential store access (file open):
  - Timestamp: _______
  - Process: _______
  - Expected (browser) or unexpected? _______
- [ ] Check for credential dumping tools:
  - [ ] LaZagne
  - [ ] Mimikatz
  - [ ] WebBrowserPassView
  - [ ] Other: ___________

**Correlation Steps:**
- [ ] Match Login Data file access with process execution
- [ ] Check for Login Data copies to other locations
- [ ] Identify network activity after credential access
- [ ] Look for logins from new IPs/locations (external logs needed)
- [ ] Document credential theft indicators

### Extension Installation Correlation

For each extension:
Extension Name: ___________________
- [ ] Installation timestamp (folder creation): _______
- [ ] Browser history around installation time (±30 min)
- [ ] Download history for extension file
- [ ] Web store visit (if from official store)
- [ ] Referring URL (how user found extension)
- [ ] First execution/activation: _______
- [ ] Configuration changes: _______
- [ ] Network connections by extension: _______
- [ ] Data access by extension: _______

### Phishing Correlation

**Phishing Indicator Checklist:**
- [ ] Email webmail access before incident
- [ ] Suspicious link click (referrer analysis)
- [ ] Typosquatting domain visit
- [ ] Credential entry on phishing site (form submission)
- [ ] Legitimate site credential change after phishing
- [ ] Account compromise indicators (unusual activity)

**Analysis Steps:**
- [ ] Identify potential phishing email timestamp
- [ ] Extract link from webmail (if in history/cache)
- [ ] Document phishing site characteristics
- [ ] Check for credential submission
- [ ] Verify if credentials were compromised
- [ ] Timeline post-phishing activity
- [ ] Document remediation actions (password changes)

### Data Exfiltration Correlation

**Exfiltration Indicators:**
- [ ] Access to file shares or sensitive directories
- [ ] Large file compression (zip, rar creation)
- [ ] Cloud storage site visits
- [ ] File upload activity (POST requests, large transfers)
- [ ] Email attachment uploads
- [ ] FTP/SFTP site access
- [ ] Paste bin or text sharing site visits

**Analysis Matrix:**
| Timestamp | Sensitive File Access | Compression | Upload Location | File Size |
|-----------|----------------------|-------------|-----------------|-----------|
| _______ | _______ | _______ | _______ | _______ |
| _______ | _______ | _______ | _______ | _______ |

**Correlation:**
- [ ] Match file access times with upload times
- [ ] Document time delta between access and exfil
- [ ] Identify data staging locations
- [ ] Check for encryption before upload
- [ ] Verify upload completion
- [ ] Document destination analysis

### Privacy Tool Usage

**Indicators:**
- [ ] VPN service website visits
- [ ] Tor Browser download
- [ ] Privacy-focused browser installation
- [ ] Encrypted messaging service signup
- [ ] Anonymous email service usage
- [ ] Data destruction tool downloads
- [ ] Anti-forensic tool searches

**Analysis:**
- [ ] Document privacy tool discovery time
- [ ] Timeline tool installation and first use
- [ ] Correlate with other suspicious activities
- [ ] Check for evidence destruction attempts
- [ ] Note motivation (concealment of what?)

### Insider Threat Indicators

**Red Flags:**
- [ ] Competitor website visits
- [ ] Job search activity
- [ ] Resume upload/update
- [ ] Unusual after-hours access
- [ ] Access to areas outside job role
- [ ] Download of company data
- [ ] Personal email usage increase
- [ ] Data exfiltration to personal accounts
- [ ] Grievance-related searches
- [ ] Policy violation searches

**Documentation:**
- [ ] Timeline of insider activity
- [ ] Establish intent (job seeking vs. malicious)
- [ ] Quantify data at risk
- [ ] Document policy violations
- [ ] Correlate with HR events (if available)

---

## Phase 6: Malware & Threat Intelligence

### Malware Artifact Identification

**Download Analysis:**
- [ ] Extract all executables downloaded
- [ ] Calculate file hashes (MD5, SHA-1, SHA-256):
  - File: _______ | MD5: _______ | SHA-256: _______
  - File: _______ | MD5: _______ | SHA-256: _______

**VirusTotal Analysis:**
- [ ] Submit hashes to VirusTotal (not files - avoid data leakage)
- [ ] Document detection ratios: _______
- [ ] Note malware family names: _______
- [ ] Check first submission date
- [ ] Review behavioral reports

**Sandbox Analysis:**
- [ ] Submit samples to sandbox (Any.run, Joe Sandbox)
- [ ] Document network IOCs
- [ ] Note C2 domains
- [ ] Check for persistence mechanisms
- [ ] Identify dropped files

### Threat Intelligence Correlation

**Domain/URL Analysis:**
- [ ] Extract all domains from history
- [ ] Check against threat intel feeds:
  - [ ] AlienVault OTX
  - [ ] VirusTotal
  - [ ] URLhaus
  - [ ] PhishTank
  - [ ] Cisco Talos
- [ ] Document malicious domain matches:
  - Domain: _______ | Threat: _______ | Category: _______
  - Domain: _______ | Threat: _______ | Category: _______

**IP Address Analysis:**
- [ ] Extract IP addresses from URLs
- [ ] Check IP reputation
- [ ] Identify hosting countries
- [ ] Note IP address changes (fast flux?)

**Campaign Attribution:**
- [ ] Match indicators to known campaigns
- [ ] Identify threat actor TTPs
- [ ] Document attack pattern
- [ ] Check for related incidents

---

## Phase 7: Reporting Preparation

### Evidence Compilation

- [ ] Organize all extracted artifacts by category
- [ ] Create evidence file structure:
  ```
  Evidence/
  ├── Chrome/
  ├── Edge/
  ├── Firefox/
  ├── IE/
  ├── System/
  ├── Timeline/
  └── Reports/
  ```
- [ ] Calculate hashes of all extracted evidence
- [ ] Create evidence manifest/index
- [ ] Document file locations in original image

### Key Findings Summary

**Critical Findings:**
1. Finding: ___________________
   - Evidence: ___________________
   - Timeline: ___________________
   - Impact: ___________________

2. Finding: ___________________
   - Evidence: ___________________
   - Timeline: ___________________
   - Impact: ___________________

3. Finding: ___________________
   - Evidence: ___________________
   - Timeline: ___________________
   - Impact: ___________________

### Questions Answered

Investigation Goals (from Phase 1):
- [ ] Goal 1: ___________________
  - Answered: [ ] Yes [ ] No [ ] Partial
  - Evidence: ___________________

- [ ] Goal 2: ___________________
  - Answered: [ ] Yes [ ] No [ ] Partial
  - Evidence: ___________________

### Timeline Highlights

- [ ] Create condensed timeline of key events
- [ ] Highlight T-0 and surrounding activity
- [ ] Document entry point (if identified)
- [ ] Note lateral movement or escalation
- [ ] Mark data exfiltration points
- [ ] Identify cleanup attempts

### Artifact Summary

**Artifacts Analyzed:**
- [ ] Chrome artifacts: _____ files
- [ ] Edge artifacts: _____ files
- [ ] Firefox artifacts: _____ files
- [ ] IE artifacts: _____ files
- [ ] System artifacts: _____ items
- [ ] Total evidence collected: _____ GB

**Key Artifacts:**
- Most significant artifact: ___________________
- Direct evidence: ___________________
- Corroborating evidence: ___________________

### Indicators of Compromise (IOCs)

**Compile all IOCs:**
- [ ] Malicious domains: _____ unique
- [ ] Malicious URLs: _____ unique
- [ ] File hashes: _____ unique
- [ ] IP addresses: _____ unique
- [ ] Email addresses: _____ identified
- [ ] Malware families: ___________________

**IOC Export:**
- [ ] Export IOCs to STIX/OpenIOC format
- [ ] Share with threat intel platform
- [ ] Distribute to security team
- [ ] Update detection rules

### Recommendations

**Immediate Actions:**
- [ ] Recommendation 1: ___________________
- [ ] Recommendation 2: ___________________
- [ ] Recommendation 3: ___________________

**Long-term Improvements:**
- [ ] Security control enhancement: ___________________
- [ ] Policy updates: ___________________
- [ ] Training needs: ___________________
- [ ] Technology solutions: ___________________

---

## Phase 8: Report Generation

### Report Sections

- [ ] Executive Summary (non-technical overview)
- [ ] Investigation Scope and Objectives
- [ ] Methodology and Tools Used
- [ ] System Information
- [ ] Timeline of Events
- [ ] Detailed Findings
- [ ] Evidence Analysis
- [ ] Conclusions
- [ ] Recommendations
- [ ] Appendices (detailed data, screenshots, tool outputs)

### Quality Checks

- [ ] All timestamps converted to consistent timezone
- [ ] All file paths documented accurately
- [ ] Screenshots included for key findings
- [ ] Technical terms defined or explained
- [ ] Chain of custody maintained and documented
- [ ] Peer review completed (if applicable)
- [ ] Legal review completed (if required)
- [ ] Proper citation of tools and methods
- [ ] Hash values verified before final report

### Deliverables Checklist

- [ ] Written investigation report (PDF)
- [ ] Executive summary (separate document)
- [ ] Timeline export (CSV/XLSX)
- [ ] Evidence files (properly packaged)
- [ ] Hash verification file
- [ ] IOC list (machine-readable format)
- [ ] Tool outputs and logs
- [ ] Methodology documentation
- [ ] Chain of custody forms
- [ ] Photos/screenshots

---

## Phase 9: Case Closure

### Evidence Storage

- [ ] Store forensic images in secure location
- [ ] Backup all analysis files
- [ ] Encrypt sensitive evidence
- [ ] Document storage location
- [ ] Set retention schedule per policy
- [ ] Restrict access to authorized personnel

### Knowledge Management

- [ ] Update case management system
- [ ] Add to lessons learned database
- [ ] Share anonymized findings with team
- [ ] Update playbooks based on experience
- [ ] Document new techniques discovered
- [ ] Archive case notes

### Final Checklist

- [ ] All investigation objectives met
- [ ] Report approved and distributed
- [ ] Evidence properly stored
- [ ] IOCs shared with relevant teams
- [ ] Remediation actions initiated
- [ ] Follow-up scheduled (if needed)
- [ ] Case formally closed in tracking system
- [ ] Stakeholders notified of closure

---

## Appendix: Quick Reference

### Critical Timestamps to Document

- [ ] System installation date
- [ ] User account creation date
- [ ] Browser installation dates
- [ ] First browser profile creation
- [ ] Investigation timeframe: From _______ To _______
- [ ] Incident occurrence time: _______
- [ ] Evidence acquisition time: _______

### Critical Questions

1. [ ] What sites were visited during the incident window?
2. [ ] What files were downloaded?
3. [ ] Were any credentials entered on suspicious sites?
4. [ ] What extensions/addons were installed?
5. [ ] Was malware downloaded through the browser?
6. [ ] Is there evidence of data exfiltration?
7. [ ] Were privacy tools used (VPN, Tor, private browsing)?
8. [ ] Is there evidence of manual evidence destruction?
9. [ ] What was the user's intent (malicious, negligent, authorized)?
10. [ ] Can the investigation objectives be conclusively answered?

### Red Flags Checklist

- [ ] Extensions with excessive permissions
- [ ] Sideloaded extensions
- [ ] Typosquatting domains visited
- [ ] Suspicious downloads from unknown sources
- [ ] Credential entry on non-HTTPS sites
- [ ] Access to known malicious domains
- [ ] Evidence clearing (CCleaner, manual deletion)
- [ ] Private/incognito mode usage during incident
- [ ] After-hours suspicious activity
- [ ] Rapid sequential actions (scripted behavior)
- [ ] Privacy tool installation
- [ ] Anti-forensic tool searches
- [ ] Data staging for exfiltration
- [ ] Unusual file compression activity
- [ ] Multiple failed login attempts

---

**Investigation Completed By:** ___________________  
**Date Completed:** ___________________  
**Review Status:** ___________________  
**Case Status:** ___________________

---

**End of Browser Forensics Analysis Checklist**
