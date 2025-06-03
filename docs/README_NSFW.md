# 🔒 Project NSFW: Net Sharing Fileless Wiperware

## Executive Summary
**Project NSFW** is a red/purple team research effort that simulates a **fileless, polymorphic malware** framework tailored for **Windows 11** systems. This framework demonstrates the feasibility of high-impact cyberattacks using only in-memory payloads and built-in system binaries (LOLBins). Inspired by NotPetya-style threats, the project focuses on abusing Windows **print spooler services** for lateral movement and privilege escalation, while emphasizing real-world detection, mitigation, and offensive security education.

## 🧠 Core Concepts

### Net Sharing (Initial Access & Wormability)
- Exploits Windows print and file sharing via `net.exe`, `net use`, and related LOLBins.
- Implements **PrintNightmare** and **HiveNightmare** vulnerabilities (`CVE-2021-34527`, `CVE-2021-36934`) for privilege escalation and self-propagation.
- Supports automated exploitation via Metasploit (`exploit/windows/printnightmare`) or scripted remote execution using PowerShell/WMI.

### Fileless Execution (Stealth & Evasion)
- All payloads execute from memory using trusted binaries:
  - `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `cmdkey.exe`, `wmic.exe`
- Avoids writing to disk to minimize forensics footprint and evade AV/EDR tools.
- Embeds shellcode payloads via `.jpg`, `.lnk`, or `.ps1` files for phishing delivery.

### Wiper Logic (Final Stage Payload)
- Final-stage behavior mimics ransomware but prioritizes **destruction over extortion**.
- Uses **DiskCryptor-based encryption** integrated with **Azure AI-powered polymorphic logic** ("Copycat") for code mutation and anomaly bypass.
- Supports optional ransom printout via Windows printer services.

## 🧩 Attack Flow Overview

1. **Initial Access** – Spear phishing with embedded `.jpg` or `.lnk`.
2. **Exploit** – Use of Print Spooler or Registry CVEs.
3. **Lateral Movement** – `net use`, WMI, PowerShell remoting.
4. **Persistence** – LOLBins-based scheduled tasks or registry keys.
5. **Payload Execution** – In-memory DLL shellcode injection via Donut/sRDI.
6. **Impact** – NTFS metadata destruction, ransom notes, service disruption.

## 🎯 Objectives

| Red Team (Adversary Simulation)       | Blue Team (Defender Insight)               |
|--------------------------------------|--------------------------------------------|
| Simulate polymorphic worm-like malware | Build detection for fileless attack chains |
| Demonstrate AV/EDR evasion with LOLBins | Tune threat hunting based on ATT&CK mapping |
| Trigger controlled system failure    | Apply Sigma/Sysmon for real-time monitoring |

## 🔍 Detection & Mitigation Strategy

- Aligns with MITRE ATT&CK tactics:
  - `T1055` (Process Injection), `T1562` (Defense Evasion), `T1021` (Remote Services)
- Suggested detection sources:
  - **Sysmon**, **ELK**, **Splunk**, **Sigma Rules**
- Watch for:
  - Spooler restarts, `rundll32` or `regsvr32` anomalies
  - Driver or service installs
  - Memory entropy changes

## 🧪 Key Takeaways

- Demonstrated feasibility of **fully fileless**, **wormable**, and **destructive** malware.
- Validated legacy Windows vulnerabilities still pose systemic risks in modern networks.
- Showcased the power of LOLBins + polymorphism for sustained evasion.
- Reinforced blue team defense posture using MITRE mappings and behavioral monitoring.

## 💼 Position Readiness

This project demonstrates readiness for the following roles:

- **Red Team Operator / Adversary Emulation Specialist**
- **Threat Intelligence / Malware Analyst**
- **Windows Security Researcher**
- **Detection Engineering / EDR Evasion Expert**

## ⚠️ Legal Disclaimer

All content and code referenced in this project are strictly for **educational** and **authorized penetration testing** purposes. Testing must occur only within **lab environments** and with **explicit permission**. Unauthorized use may violate local or international laws.

## 🧭 Additional Resources

- [LOLOL Farm – LOLBin Playground](https://lolol.farm/)
- [LOLGEN – Generate LOLBin Chains](https://lolgen.hdks.org/)
- [MITRE ATT&CK: S0697](https://attack.mitre.org/software/S0697/)
- [DLL Injection Primer](https://www.crow.rip/crows-nest/mal/dev/inject/dll-injection)
- [Print Spooler Exploit Chain](https://itm4n.github.io/printnightmare-not-over/)
- [Fileless Malware – Wikipedia](https://en.wikipedia.org/wiki/Fileless_malware)

## 📚 Print Spooler CVEs

- [SysNightmare](https://github.com/GossiTheDog/SystemNightmare)
- [PrintSpoofer (Original)](https://github.com/itm4n/PrintSpoofer/tree/master)
- [PrintSpoofer 2](https://github.com/dievus/printspoofer)
- [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
