# AttackSight 🔴🔵
> *"You can't trust a detection rule you've never tested."*

**AttackSight** is a Purple Team Detection Validation Framework.  
It executes real (benign) ATT&CK-mapped payloads, captures the logs they generate, and tests those logs against Sigma rules — telling you exactly which techniques your SIEM would catch, and which it would miss.

---

## The Problem It Solves

Most SOC teams write Sigma/SIEM detection rules and assume they work.  
They don't validate them against real attack behavior.  
AttackSight closes that gap.

```
Without AttackSight:   Write rule → Deploy → Hope it works
With AttackSight:      Write rule → Execute technique → Verify detection → Ship with confidence
```

---

## How It Works

```
1. You select an ATT&CK technique (e.g. T1059.001 - PowerShell)
2. AttackSight executes a safe, benign atomic payload
3. It captures the logs generated (Sysmon, Windows Event Log, etc.)
4. It tests those logs against your Sigma rules
5. It outputs a coverage report: Detected / Missed / Partial
```

---

## Quick Start

```bash
# Install
git clone https://github.com/farouq7assan0o/attacksight
cd attacksight
pip install -r requirements.txt

# List available techniques
python cli.py list

# Run a single technique
python cli.py run --technique T1059.001

# Run all techniques and generate report
python cli.py run --all --report html

# Test your Sigma rules against captured logs
python cli.py validate --logs reports/last_run.json --rules sigma_rules/
```

---

## Output Example

```
╔══════════════════════════════════════════════════════╗
║           AttackSight — Coverage Report              ║
╠══════════════════════════════════════════════════════╣
║  T1059.001  PowerShell Encoded Cmd     ✅ DETECTED   ║
║  T1003.001  LSASS Memory Dump          ❌ MISSED      ║
║  T1055.001  Process Injection          ⚠️  PARTIAL    ║
║  T1547.001  Registry Run Key           ✅ DETECTED   ║
║  T1070.004  File Deletion              ❌ MISSED      ║
╠══════════════════════════════════════════════════════╣
║  Coverage Score: 40%  (2/5 techniques detected)      ║
║  Report saved: reports/2026-03-11_coverage.html      ║
╚══════════════════════════════════════════════════════╝
```

---

## Atomic YAML Format

Each technique is defined in a YAML file under `atomics/`:

```yaml
technique_id: T1059.001
name: PowerShell Encoded Command
description: Simulates encoded PowerShell execution used in fileless attacks
platforms: [windows]
payloads:
  - name: Base64 encoded command
    executor: powershell
    command: powershell.exe -EncodedCommand JABzACAAPQAgACcAdABlAHMAdAAnAA==
    cleanup: ""
expected_logs:
  - source: Microsoft-Windows-Sysmon/Operational
    event_id: 1
  - source: Security
    event_id: 4688
sigma_rules:
  - sigma_rules/proc_creation_win_powershell_encoded.yml
references:
  - https://attack.mitre.org/techniques/T1059/001/
```

---

## Project Structure

```
attacksight/
├── atomics/                  # YAML technique definitions
│   ├── T1059.001.yaml
│   ├── T1003.001.yaml
│   ├── T1055.001.yaml
│   ├── T1547.001.yaml
│   └── T1070.004.yaml
├── sigma_rules/              # Sigma detection rules
├── engine/
│   ├── executor.py           # Executes atomic payloads safely
│   ├── log_collector.py      # Captures Windows/Syslog events
│   ├── sigma_tester.py       # Tests logs vs Sigma rules
│   └── reporter.py           # Generates HTML/JSON reports
├── reports/                  # Output reports
├── tests/                    # Unit tests
├── cli.py                    # Main entry point
├── requirements.txt
└── README.md
```

---

## Supported Platforms

| Platform | Status |
|----------|--------|
| Windows 10/11 | ✅ Full support |
| Windows Server 2019/2022 | ✅ Full support |
| Linux | 🔄 Partial (Syslog techniques) |

> **Note:** Sysmon must be installed for full Windows log coverage.  
> Download: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Sigma Rule Compatibility

AttackSight uses `sigma-cli` under the hood, making it **SIEM-agnostic**.  
Convert rules to your target backend:

```bash
# Splunk
sigma convert -t splunk sigma_rules/

# Elastic
sigma convert -t elasticsearch sigma_rules/

# Microsoft Sentinel
sigma convert -t sentinelasim sigma_rules/
```

---

## Built By

**Farouq Hassan** — Cybersecurity student, HTU Jordan  
Internship @ Special Communications Commission – Jordan Armed Forces  
[GitHub](https://github.com/farouq7assan0o) · [LinkedIn](https://linkedin.com/in/FarouqHassan02) · [Medium](https://medium.com/@12farouq12)

---

## Disclaimer

AttackSight is designed for **authorized testing only**.  
All payloads are benign and designed for controlled lab/SOC environments.  
Never run this against systems you do not own or have explicit permission to test.
