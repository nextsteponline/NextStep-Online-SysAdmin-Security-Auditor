# NextStep Online SysAdmin Security Auditor

A high-performance, context-aware Windows security auditing and tactical threat hunting script. This tool is engineered specifically to detect and disrupt **lateral movement vectors**, eliminate alert fatigue from development and system environments, and surface actionable security gaps on enterprise endpoints or servers.

---

## Core Design Philosophy & Enhancements

Unlike generic keyword scanners or heavy auditing frameworks, this script introduces advanced, context-rich analysis to save engineering time:
* **Anti-Lateral Movement Focus**: Targets key pathways favored by threat actors during internal pivot phases—including detailed Remote Desktop (RDP) Network Level Authentication (NLA) status, WinRM CredSSP cleartext delegation exposures, and deep-dive local administrative group validation.
* **Smart Noise Cancellation**: Implements an aggressive directory filter to ignore volatile developer artifacts (e.g., `.codex`, `node_modules`, `.vscode`, build `bin/obj` outputs) and user space temp paths (`AppData\Local\Temp`), ensuring generated `CRITICAL` alerts are true indicators of risk.
* **Temporal Threat Hunting**: Replaces superficial, blind "top-10 log entry" fetches with a strict time-driven analysis window (`-RecentDays`). This ensures high-signal defensive evasion (log clears) and execution artifacts (malicious service setups via `PsExec` or `Impacket`) are reliably caught inside the audit timeline.

---

## Operational Modules

| Module Name | Audit & Hunting Objective | Defensive Goal |
| :--- | :--- | :--- |
| **Telemetry & Audit Controls** | Verifies the operational enforcement of PowerShell Script Block Logging. | Maintains visibility against fileless Living-off-the-Land (LotL) execution tactics. |
| **System Hardening Baseline** | Inspects core host protection metrics: Windows Defender state, LSA Protection (`RunAsPPL`), and Credential Guard. | Hardens the LSASS memory space against raw credential harvesting utilities like Mimikatz. |
| **Services & Firewall Exposure** | Identifies Unquoted Service Paths and weak discretionary access controls (ACLs) on service executable binaries. | Precludes local Privilege Escalation (PrivEsc) vulnerabilities. |
| **Network & Ports Binding** | Enumerates global interface listener bindings (`0.0.0.0`) on high-risk ingress points (Ports 135, 445, 3389, 5985/5986). | Closes unnecessary exposure vectors across internal local subnets. |
| **Persistence Artifacts** | Evaluates registry run paths (`Run`/`RunOnce`) using conditional parsing rules to flag anomalies (e.g., LOLBins, temp executions). | Spots implant footprinting without triggering flags on verified application shortcuts. |
| **File System Secrets** | Performs recursive analysis on protected system logs (Panther/Sysprep setup logs) and raw credential formats (`.pem`, `.kdbx`, `.env`). | Starves attackers of plaintext credentials or keys required to authenticate downstream. |
| **Tactical Security Log Hunt** | Traverses security and system logs within a set chronological window for Event IDs 1102, 4697, and 7045. | Uncovers remote service injection routines associated with active network lateral movement. |
| **Local Administrators Audit** | Uses native CIM routines to map every local security identifier (SID) and account matching administrative status. | Resolves credential sprawl and tracks unmapped shadow admin paths. |
| **Remote Access Control** | Assesses active remote management layers for structural vulnerabilities (RDP without NLA, active CredSSP endpoints). | Protects authentication workflows from network-layer relaying and password spraying. |

---

## Prerequisites

* **Operating System**: Windows 10 / 11 or Windows Server 2016 / 2019 / 2022 / 2025
* **Execution Environment**: PowerShell 5.1 or higher
* **Permissions**: Must be run from an elevated PowerShell console (**Run as Administrator**)

---

## Usage

### 1. Standard Execution
By default, the script conducts a comprehensive system review and inspects event logs over the last **7 days**:

```powershell
.\NSO-Windows-Audit.ps1

```

### 2. Custom Audit Timeline & File Scanning Constraints

Modify execution parameters to alter the logging time-window or safely process environments with larger text files:

```powershell
.\NSO-Windows-Audit.ps1 -RecentDays 14 -MaxContentFileMB 10

```

* `-RecentDays`: Defines how many days of event-log metrics are scraped for lateral indicator trends (Default: `7`).
* `-MaxContentFileMB`: Sets the maximum file size cap processed during raw text regex match passes (Default: `5`), protecting memory baselines on target infrastructure.

---

## Generated Reports

Upon conclusion, the engine automatically compiles three separate telemetry outputs within the execution folder:

1. **System Log (`NextStep_Security_Scan_[Timestamp].log`)**
* A sequential, newline-delimited operational trace file. Ideal for auditing script runtime performance or piping directly into centralized SIEM forwarders.


2. **Structured Findings Matrix (`NextStep_Security_Findings_[Timestamp].csv`)**
* Flat-file schema documenting raw finding parameters (`Severity`, `Category`, `Location`, `Evidence`, `Remediation`). Ready for direct import into Excel, BI platforms, or Elasticsearch for cross-fleet analysis.


3. **Interactive Dashboard (`NextStep_Security_Report_[Timestamp].html`)**
* A premium dark-mode, responsive executive presentation report. Includes dynamic tracking widgets mapping current risk volume (`CRITICAL`, `HIGH`, `WARNING`, `SECURE`, `INFO`) paired with detailed, developer-validated remediation pathways for local sysadmins.



---

## Disclaimer

*This script is intended exclusively for authorized security compliance reviews, threat hunting simulations, and defensive engineering validations. Ensure proper change-management protocols are followed prior to executing scripts in high-availability production cluster contexts.*
