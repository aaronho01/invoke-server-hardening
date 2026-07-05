# Invoke-ServerHardening

Modular PowerShell framework for automating Windows Server security hardening across nine configuration domains, with centralized logging and pre/post state verification.

---

## Project Context

This was developed as a final project for SYS-255-01 (Sysadmin and Net Services I) at Champlain College in April 2026. It was built and tested in a Windows Server 2025 lab environment as a practical application of system administration and security hardening concepts covered throughout the course.

It is not intended as a production-ready hardening baseline. Several configuration values, such as account names, password policy thresholds, and allowed subnets, are set for a controlled lab environment and would need to be reviewed and adjusted before use in any real deployment.

---

## Overview

`Invoke-ServerHardening.ps1` is the master orchestration script. It dot-sources and executes nine hardening modules in sequence, tracks success and failure counts from each, and generates a timestamped summary report. All output is written to both the console (color-coded by severity) and a log file under `C:\HardeningLogs` by default.

`Get-HardeningState.ps1` is a companion enumeration script. Run it before and after hardening to produce a readable snapshot of the system's security configuration and confirm that changes took effect.

---

## Modules

| # | Name | Description | Author |
|---|------|-------------|--------|
| 1 | User Account Hardening | Disables Guest, DefaultAccount, and WDAGUtilityAccount; renames the built-in Administrator account; creates a new dedicated admin user | Andrew Zombek |
| 2 | Password and Lockout Policy | Enforces 14-character minimum length, 90-day max age, 24-password history, 5-attempt lockout threshold with a 30-minute lockout window | Andrew Zombek |
| 3 | Local Group Membership Audit | Audits and restricts Administrators, Remote Desktop Users, Backup Operators, and Power Users group membership; removes unauthorized accounts | Andrew Zombek |
| 4 | Audit Policy and Logging | Enables audit policies for account logon, privilege use, process creation, and object access; sets the Security log to 1 GB with command-line logging | Nad AlDulaimi |
| 5 | File System Permissions | Audits and tightens NTFS permissions on Windows, System32, SAM/SECURITY/SYSTEM hive files, and scheduled task directories | Nad AlDulaimi |
| 6 | Windows Firewall Configuration | Enables Windows Defender Firewall on all profiles with deny-by-default inbound; blocks SMB (445), RDP (3389) externally, and disables NetBIOS; enables firewall logging | Aaron Ho |
| 7 | Service Hardening | Disables Remote Registry, Print Spooler, Telnet, SNMP, and all Xbox-related services; sets non-critical services to Manual startup | Aaron Ho |
| 8 | Attack Surface Reduction | Disables SMBv1, LLMNR, NetBIOS over TCP/IP, PowerShell v2 engine, and Windows Script Host; configures Windows Defender real-time protection; enables Credential Guard where hardware supports it | Aaron Ho |
| 9 | Registry Security Hardening | Disables AutoRun/AutoPlay; restricts anonymous SAM enumeration; enables LSASS RunAsPPL; disables WDigest credential caching; restricts NTLM; enables SMB signing; disables LM hash storage | Aaron Ho |

---

## Requirements

- Windows Server (tested on Windows Server 2025)
- PowerShell 5.1 or later
- Must be run as Administrator (`#Requires -RunAsAdministrator` is enforced)
- All module scripts must reside in the same directory as `Invoke-ServerHardening.ps1`

---

## Usage

**Run all modules with defaults:**
```powershell
.\Invoke-ServerHardening.ps1
```

**Skip specific modules:**
```powershell
.\Invoke-ServerHardening.ps1 -SkipModules 7,8
```

**Specify a custom log directory:**
```powershell
.\Invoke-ServerHardening.ps1 -LogDirectory "D:\Logs\Hardening"
```

**Stop execution if any module fails:**
```powershell
.\Invoke-ServerHardening.ps1 -StopOnFailure
```

**Check security state before/after hardening:**
```powershell
.\Get-HardeningState.ps1
```

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SkipModules` | `int[]` | `@()` | Module numbers (1–9) to skip during execution |
| `-LogDirectory` | `string` | `C:\HardeningLogs` | Directory where timestamped log files are written |
| `-StopOnFailure` | `switch` | off | Halts execution immediately if any module returns a failure |

---

## Output

Each run creates a timestamped log file (`Hardening_yyyy-MM-dd_HHmmss.log`) in the log directory. The log contains per-module headers, action-level results, and a final summary report:

```
======================================================================
 HARDENING SUMMARY REPORT
======================================================================
 Execution Time:     12.34 seconds
 Modules Executed:   9 of 9
 Modules Skipped:    0

 MODULE RESULTS
   Succeeded:        9
   Failed:           0

 ACTION TOTALS
   Attempted:        52
   Succeeded:        50
   Warnings:         2
   Failed:           0

 Log File:           C:\HardeningLogs\Hardening_2026-04-15_143022.log
======================================================================
```

Console output mirrors the log with color coding: cyan for INFO, green for SUCCESS, yellow for WARNING, and red for ERROR.

---

## Important Notes

**Hardcoded credentials:** `Module1-UserAccounts.ps1` contains a plaintext admin password in its `$Config` block. This is intentional for lab/classroom use but must be changed before deploying to any real environment. Consider replacing it with a `Read-Host -AsSecureString` prompt or pulling from a secrets manager.

**Idempotency:** Modules are written to be safely re-runnable. Actions that are already in the desired state are logged but do not count as failures.

**Environment specifics:** Some behaviors (such as DISM-dependent feature removal and CIM-based queries) may require adjustment depending on the server role and Windows build. Known workarounds for lab environment issues are documented inline within the affected modules.

---

## Authors

| Name | Role |
|------|------|
| Aaron Ho | Modules 6, 7, 8, 9; orchestration script author |
| Andrew Zombek | Modules 1, 2, 3 |
| Nad AlDulaimi | Modules 4, 5 |

**Course:** SYS-255-01 — Sysadmin and Net Services I  
**Professor:** Joseph Letourneau  
**Institution:** Champlain College  
**Date:** April 2026

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
