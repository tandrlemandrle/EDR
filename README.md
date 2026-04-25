# 🛡️ GorstaksEDR - Unified Endpoint Defense Platform

> **A single-file PowerShell EDR that combines threat detection, automated response, and endpoint hardening into one self-installing script. No dependencies. PS 5.1 compatible.**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EVENT SOURCES                            │
│  WMI Process Trace │ FileSystemWatcher │ Network Monitor    │
└──────────┬──────────────────┬──────────────────┬────────────┘
           ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                  ANALYSIS PIPELINE                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐│
│  │Static Analysis│ │Behavior Eng. │ │ YARA-like Rules      ││
│  │ Hashes/Entropy│ │ LOLBin args  │ │ 10 embedded rules    ││
│  │ PE parsing    │ │ 23 cmd pats  │ │ Pattern matching     ││
│  │ Signatures    │ │ 32 LOLBins   │ │                      ││
│  └──────────────┘ └──────────────┘ └──────────────────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐│
│  │MITRE ATT&CK  │ │Network Mon.  │ │ Process Chain Mon.   ││
│  │ 18 techniques│ │ Beaconing det│ │ Parent-child trees    ││
│  │ Auto-mapping │ │ Port analysis│ │ LOLBin chain scoring  ││
│  └──────────────┘ └──────────────┘ └──────────────────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐│
│  │Memory Scanner│ │ AMSI Scanner │ │ Ransomware Detector  ││
│  │ RWX regions  │ │ Script scan  │ │ Mass rename detect   ││
│  │ Shellcode sig│ │ via Windows  │ │ 60+ ransom extensions││
│  │ Reflective PE│ │ AMSI API     │ │ Ransom note patterns ││
│  └──────────────┘ └──────────────┘ └──────────────────────┘│
│  ┌──────────────┐ ┌──────────────┐                         │
│  │Hash Reputation│ │ Whitelist   │                         │
│  │ Known-bad DB │ │ Path + Hash │                         │
│  └──────────────┘ └──────────────┘                         │
└──────────┬──────────────────────────────────────────────────┘
           ▼
┌─────────────────────────────────────────────────────────────┐
│              WEIGHTED SCORING ENGINE                        │
│  Behavior 1.5x │ Memory 1.5x │ Chain 1.4x │ YARA 1.3x    │
│  Network  1.2x │ Static 1.0x │ MITRE 0.8x │ HashRep 1.0x │
│  + Corroboration bonus │ + Signed binary discount          │
└──────────┬──────────────────────────────────────────────────┘
           ▼
┌─────────────────────────────────────────────────────────────┐
│              RESPONSE ENGINE                                │
│  🔴 Critical (120+) : Kill + Quarantine + Block            │
│  🟠 Malicious (80+) : Quarantine + Block + Alert           │
│  🟡 Suspicious (50+): Alert                                │
│  🟢 Clean/Low       : Log only                             │
└─────────────────────────────────────────────────────────────┘
           +
┌─────────────────────────────────────────────────────────────┐
│              HARDENING MODULES (from GShield)               │
│  🔑 Password Rotator      │ ⚔️ Retaliate Monitor           │
│  🛡️ UAC Enforcement       │ 🔍 Self-Integrity Watchdog     │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

```powershell
# Install (copies to C:\ProgramData\Antivirus, registers startup task)
.\GorstaksEDR.ps1 -Install

# Run directly (as Administrator)
.\GorstaksEDR.ps1

# Dot-source for interactive use
. .\GorstaksEDR.ps1
Start-EDR
```

---

## 🚀 Usage

### 📡 Real-Time Monitoring

```powershell
Start-EDR                    # Start all monitors + hardening
Stop-EDR                     # Graceful shutdown
Show-EDRDashboard            # View current status
```

### 🔍 Manual Scanning

```powershell
Invoke-EDRScan -Path "C:\suspect.exe"      # Scan a file
Invoke-EDRScan -Path "C:\Downloads"         # Scan a directory
```

### 🚨 Response Actions

```powershell
# Auto-response is OFF by default (monitor-only mode)
Set-AutoResponse -Enabled $true     # Enable auto kill/quarantine/block
Set-AutoResponse -Enabled $false    # Back to monitor-only
```

### 📊 Reports

```powershell
Show-EDRDashboard              # Full status overview
Get-QuarantinedFiles           # List quarantined files
Get-EDRFirewallRules           # List EDR firewall blocks
```

---

## 🔎 Detection Capabilities

### 🧬 Static Analysis
- 🔐 MD5 / SHA1 / SHA256 hashing
- 📊 Shannon entropy calculation (packer detection)
- 🔬 PE header parsing (section names, suspicious imports)
- ✍️ Authenticode signature verification
- 📝 UTF-8 and UTF-16 string extraction
- 📏 Double extension detection
- 🏷️ Hash reputation database lookup

### 🧠 Behavior Engine
- 🧰 **32 LOLBins** with per-binary suspicious argument matching
- 💻 **23 command-line heuristic patterns** (encoded PS, download cradles, ransomware indicators)
- 👪 **19 suspicious parent-child** process combinations (Office→PS, IIS→cmd, WMI→PS, etc.)
- 📂 Suspicious execution path detection
- 🔤 Obfuscation scoring (special character density)
- 📏 Long command-line detection

### 🔗 Process Chain Monitor
- 🌳 Full ancestor tree walking (up to 20 levels)
- ⛓️ Cumulative command-line scoring across entire chain
- 🧰 LOLBin chain detection (2+ LOLBins chained)
- 🏭 Non-interactive parent → interactive shell detection
- 💨 Rapid child spawning detection (fork bomb / spray)
- 📏 Configurable chain depth alerting

### 🧪 Memory Scanner (P/Invoke)
- 🔴 RWX memory region detection
- 💉 Shellcode signature scanning (x86/x64 prologues, Metasploit)
- 🪞 Reflective PE/DLL injection detection (MZ headers in private memory)
- 🔍 In-memory string pattern matching (mimikatz, cobalt strike, meterpreter)

### 📐 YARA-like Rule Engine
- 10 embedded rules covering: Cobalt Strike, PowerSploit, Mimikatz, SharpTools, download cradles, process injection, AMSI bypass, persistence, lateral movement, exfiltration

### 🗺️ MITRE ATT&CK Mapping
- 18 technique mappings across Execution, Persistence, Defense Evasion, Impact, Discovery
- Confidence-weighted scoring (High/Medium/Low)
- Multi-tactic bonus when 3+ tactics observed

### 📡 Network Monitor
- Connection tracking per process
- Suspicious port detection (Meterpreter, IRC, RAT ports)
- Beaconing detection via connection interval analysis (jitter ratio)

### 🦠 Ransomware Detector
- Mass file rename detection (sliding time window)
- 60+ known ransomware extension patterns
- Ransom note filename detection
- Configurable thresholds

### 🔬 AMSI Integration
- Scans script files (.ps1, .vbs, .js, .bat, .cmd, .hta) through Windows AMSI
- Leverages whatever AV engine is registered (typically Defender)

---

## 🔒 Hardening Modules (from GShield)

| Module | Description |
|--------|-------------|
| ⌨️ **Key Scrambler** | Low-level keyboard hook that injects fake keystrokes around real ones to blind keyloggers. Runs in background runspace. |
| 🔑 **Password Rotator** | Rotates local user password every 10 minutes while logged in. Blanks password on logoff/startup for seamless login. |
| ⚔️ **Retaliate Monitor** | Detects browser processes phoning home to non-browsing IPs and floods attacker's admin share with garbage data. |
| 🛡️ **UAC Enforcement** | Enforces `ConsentPromptBehaviorAdmin = 5` (Microsoft default: prompt for consent on non-Windows binaries). |
| 🔍 **Self-Integrity** | Hashes own script at startup, verifies every 5 minutes. Alerts on tampering. |

---

## 🎯 Scoring System

| Score Range | Verdict | Auto-Response (if enabled) |
|-------------|---------|----------------------------|
| 0-24 | ✅ Clean | None |
| 25-49 | 🔵 Low | Log only |
| 50-79 | 🟡 Suspicious | Alert generated |
| 80-119 | 🟠 Malicious | Alert + Quarantine + Block |
| 120+ | 🔴 Critical | Alert + Kill + Quarantine + Block |

**Score weights:**
| Source | Weight | Rationale |
|--------|--------|-----------|
| Behavior Engine | 1.5x | Behavior is king |
| Memory Scanner | 1.5x | Catches fileless malware |
| Process Chain | 1.4x | Chain context is strong signal |
| YARA Rules | 1.3x | Rule matches are reliable |
| Network | 1.2x | Network activity matters |
| Static Analysis | 1.0x | Baseline |
| Hash Reputation | 1.0x | Known-bad is definitive |
| MITRE Mapping | 0.8x | Adds context, not primary signal |

**Adjustments:**
- Signed binary from trusted publisher: -50 pts
- Signed binary (any valid signature): -20 pts
- System process from `C:\Windows\System32`: -15 pts
- 4+ independent detection sources agree: +35 pts
- 3 independent sources agree: +25 pts

---

## 🏠 Self-Install & Self-Protection

```powershell
# Install to C:\ProgramData\Antivirus
.\GorstaksEDR.ps1 -Install
```

This will:
1. 📁 Create `C:\ProgramData\Antivirus` with `Logs`, `Quarantine`, `Alerts` subdirectories
2. 📋 Copy the script to the install directory
3. ⏰ Register `GorstaksEDR` scheduled task (ONLOGON, HIGHEST privileges)
4. 🛡️ Add Defender exclusion for the install directory

**Self-protection features:**
- 🚫 Never kills its own process
- 📂 Excludes its own install directory from scanning
- ✅ Auto-whitelists its own SHA256 hash
- 🔍 Self-integrity watchdog (5-minute verification cycle)
- 🔒 Protected process list prevents accidental self-termination

---

## 🔧 Configuration

### Whitelist (`C:\ProgramData\Antivirus\whitelist.json`)
```json
{
    "Paths": ["C:\\Program Files\\TrustedApp"],
    "Hashes": ["ABC123...SHA256..."]
}
```

### Hash Reputation DB (`C:\ProgramData\Antivirus\hashdb.json`)
```json
[
    { "Hash": "SHA256_HERE", "ThreatName": "Trojan.GenericKD" }
]
```

---

## ⚠️ Limitations

- No kernel-level visibility (rootkits can bypass)
- Memory scanner requires sufficient process access rights
- AMSI depends on registered AV engine availability
- Network monitoring is connection-based, not packet-level
- Retaliate module requires network access to attacker's admin share
- Password rotator requires local admin privileges

---

## 📜 License & Disclaimer

**This project is intended for authorized defensive, administrative, research, or educational use only.**

- ✅ Use only on systems, networks, and environments where you have **explicit permission**
- ⚠️ Misuse may violate law, contracts, policy, or acceptable-use terms
- ⚠️ Running security, hardening, monitoring, or response tooling **can impact stability** and may disrupt legitimate software
- ⚠️ The **Retaliate module** performs active network operations against detected threats — ensure this is authorized in your environment
- ⚠️ The **Password Rotator** changes local user passwords — understand the implications before enabling
- 🧪 **Validate all changes in a test environment before production use**
- 📋 This project is provided **"AS IS"**, without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement
- 🚫 Authors and contributors are **not liable** for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact
- 👤 **You are solely responsible** for lawful operation, configuration choices, and compliance obligations in your jurisdiction

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
