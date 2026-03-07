# Configuration Files

This directory contains external configuration files used by the Memory Correlation Engine to reduce false positives and improve detection accuracy.

## `api_keys.json`

**⚠️ SECURITY WARNING: This file contains sensitive API keys. Add it to `.gitignore`!**

This file stores API keys for threat intelligence services:

```json
{
  "abuseipdb": {
    "api_key": "your_key_here",
    "enabled": true
  },
  "virustotal": {
    "api_key": "your_key_here",
    "enabled": true
  },
  "urlscan": {
    "api_key": "your_key_here",
    "enabled": true
  },
  "settings": {
    "timeout_secs": 10,
    "max_lookups": 20
  }
}
```

- **api_key**: Your API key for the service
- **enabled**: Set to `false` to disable a specific service
- **timeout_secs**: Request timeout in seconds
- **max_lookups**: Maximum number of IPs to check per analysis (prevents rate limiting)

## `whitelist.json`

This file defines legitimate paths and files that should strictly **NOT** be flagged as suspicious.

*   **`dll_whitelist`**: A list of paths (directories) and specific filenames that are known to be safe.
    *   `path_pattern`: A substring to match against the DLL path (e.g., `appdata\\local\\discord\\`).
    *   `filenames`: A list of specific filenames allowed in that path. If empty, *any* file in that path is allowed.
*   **`process_dll_whitelist`**: Defines the "known good" set of DLLs for specific sensitive processes.
    *   `process_name`: The process to check (e.g., `lsass.exe`).
    *   `allowed_dlls`: A list of DLL names expected to be loaded by this process.

## `blacklist.json`

This file defines patterns that are inherently suspicious for specific operations (like DLL loading).

*   **`suspicious_paths`**: A simple list of substrings. If a DLL path contains any of these strings (e.g., `\temp\`, `\downloads\`), and is *not* whitelisted, it is flagged as suspicious.
