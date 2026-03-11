---
noteId: "620563301d7711f1a259b77a5e3a79c1"
tags: []

---

# Hayabusa Command Reference

This file is a standalone reference for the top-level commands Hayabusa can execute.

General syntax:

```text
hayabusa.exe <command> <INPUT> [OPTIONS]
```

Use `hayabusa.exe help` or `hayabusa.exe <command> --help` to see command-specific options.

## Analysis Commands

* `computer-metrics`: Output the total number of events according to computer names.
* `eid-metrics`: Output event ID metrics.
* `expand-list`: Extract expand placeholders from the rules folder.
* `extract-base64`: Extract and decode base64 strings from events.
* `log-metrics`: Output evtx file metadata.
* `logon-summary`: Output a summary of successful and failed logons.
* `pivot-keywords-list`: Create a list of pivot keywords.
* `search`: Search all events by keyword(s) or regular expression.

## Configuration Commands

* `config-critical-systems`: Find critical systems like domain controllers and file servers.

## Timeline Commands

* `csv-timeline`: Create a DFIR timeline and save it in CSV format.
* `json-timeline`: Create a DFIR timeline and save it in JSON/JSONL format.
* `level-tuning`: Tune alert levels for the DFIR timeline.
* `list-profiles`: List the output profiles for the DFIR timeline.
* `set-default-profile`: Set default output profile for the DFIR timeline.
* `update-rules`: Update to the latest rules in the hayabusa-rules GitHub repository.

## Forensic Summary Commands

* `account-changes`: Output a summary of account lifecycle changes.
* `account-lockout-summary`: Output a summary of account lockout events.
* `audit-policy-changes`: Output a summary of audit policy changes.
* `crash-summary`: Output a summary of application crashes.
* `driver-summary`: Output a summary of kernel driver installations.
* `failed-logon-detail`: Output a detailed breakdown of failed logons by reason.
* `firewall-summary`: Output a summary of Windows Filtering Platform events.
* `forensic-report`: Run **all** forensic summaries plus EID metrics, computer metrics, logon summary, log file metrics, and base64 extractions in a single pass and generate a comprehensive combined HTML report.
* `group-changes`: Output a summary of group membership changes.
* `kerberos-summary`: Output a summary of Kerberos authentication events.
* `lateral-movement-summary`: Output a summary of likely lateral movement activity.
* `log-cleared`: Output a summary of log clearing events.
* `logon-type-breakdown`: Output a breakdown of logon types.
* `object-access-summary`: Output a summary of object access events.
* `password-changes`: Output a summary of password change events.
* `policy-tampering-summary`: Output a summary of policy and logging tampering events.
* `process-execution-summary`: Output a summary of process execution activity. When `-o` is used, Hayabusa also writes a Graphviz DOT process graph beside the CSV output.
* `privilege-use-summary`: Output a summary of sensitive privilege usage.
* `rdp-summary`: Output a dedicated RDP session summary.
* `reboot-shutdown-summary`: Output a summary of reboot and shutdown events.
* `scheduled-persistence-summary`: Output a summary of scheduled-task persistence changes.
* `scheduled-task-summary`: Output a summary of scheduled task activity.
* `service-summary`: Output a summary of service activity (install/change/crash).
* `share-access-summary`: Output a summary of network share access.
* `software-install-summary`: Output a summary of software installation events.
* `suspicious-encoding-summary`: Output a summary of suspicious encoded command activity.
* `windows-update-summary`: Output a summary of Windows Update events.

## General Commands

* `help`: Print help for the main CLI or a given subcommand.
* `list-contributors`: Print the list of contributors.

## Notes

* Most analysis, timeline, and forensic summary commands accept either EVTX input or JSON/JSONL input when the relevant options are supplied.
* The forensic summary commands are designed for Windows Event Logs and do not require Sysmon.
* The standalone HTML report is generated with `forensic-report`. It executes every forensic summary command, EID metrics, computer metrics, logon summary, log file metrics, and base64 extraction — producing a single compiled HTML report.