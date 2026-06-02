# NextStep Online SysAdmin Security Auditor (v9.0)

Developed by **NextStep Online Solutions**, the SysAdmin Security Auditor is a specialized PowerShell-based defensive security tool designed for Windows system administrators, IT security teams, and incident responders.

### ⚠️ Important: Administrative Privileges Required

This script performs low-level system configuration audits, registry interrogation, and security policy verification. To function correctly and access protected areas of the operating system (such as HKLM policies, system service configurations, and security descriptors), **this script must be executed in an elevated PowerShell session (Run as Administrator).** Attempting to run this without administrative privileges will cause the script to terminate immediately to prevent partial, inaccurate results.

---

### Overview

In modern enterprise environments, maintaining system integrity requires more than just high-level checks. This tool provides a deep-dive audit of system artifacts, focusing on the exact locations where security misconfigurations, privilege escalation vectors, and potential threats often hide. By automating the identification of vulnerable settings, weak Access Control Lists (ACLs), and unauthorized network exposure, this script enables administrators to perform rapid security hardening and compliance verification across their Windows infrastructure.

### Core Functions

* **System Hardening Baseline:** Audits critical security controls, including Windows Defender (Tamper Protection), Virtualization-Based Security (VBS), BitLocker status, SMBv1 protocols, and UEFI Secure Boot.
* **Privilege Escalation Hunting:** Detects common misconfigurations such as unquoted service paths and identifies service binaries with weak ACLs that could be exploited by unprivileged users to gain higher privileges.
* **Network & Threat Visibility:** Scans active TCP listeners for exposure on non-standard or sensitive ports, evaluates Windows Firewall profiles, and detects unauthorized modifications to the system `hosts` file.
* **Telemetry & Logging:** Audits PowerShell security configurations, specifically checking for the enforcement of Script Block Logging and Transcription—vital for detecting and investigating fileless attack techniques.
* **Deep Content Scanning:** Proactively searches for sensitive file types (like SSH keys, PEMs, or configuration files) and scans file content for patterns indicating hardcoded credentials or API keys.
* **Actionable Reporting:** Generates comprehensive findings with clear evidence and specific remediation guidance, outputting data in terminal, CSV, and HTML formats for easy integration into existing ticketing systems or security dashboards.

---

### Contact & Support

This project is maintained and actively developed by the team at NextStep Online Solutions.

* **Official Website:** [https://nextsteponline.io/](https://nextsteponline.io/)
* **Support & Development:** For technical inquiries, bug reports, or feature requests, please contact [dev@nextsteponline.io](https://www.google.com/search?q=mailto%3Adev%40nextsteponline.io).
* **Join Our Team:** We are constantly looking for talented security researchers, systems engineers, and developers to join our mission. If you are passionate about defensive security and automation, we would love to hear from you. Please send your resume to [hr@nextsteponline.io](https://www.google.com/search?q=mailto%3Ahr%40nextsteponline.io).
