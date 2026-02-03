# ATT&CKFlow

**MITRE ATT&CK–Based Detection & Attack Chain Analysis Tool**

ATT&CKFlow is a prototype detection analysis engine that processes endpoint log data, maps activity to MITRE ATT&CK techniques, and reconstructs attack chains through process lineage and timeline correlation. The tool is designed to simulate how detection engineering platforms turn raw telemetry into structured threat intelligence.

This project focuses on **detection logic, behavior correlation, and attack reconstruction**, rather than simple alert matching.

---

## Features

### Log Normalization

Supports structured log ingestion and converts raw endpoint events into a standardized internal schema including:

* Timestamp
* Host
* User
* Process
* Parent process
* Command line

This simulates the normalization layer of SIEM/XDR pipelines.

### MITRE ATT&CK Mapping

Maps detected behaviors to MITRE ATT&CK techniques and tactics using keyword and behavior-based logic. Each detection includes:

* Technique ID
* Technique name
* Tactic
* Confidence score
* Severity rating

### Process Lineage Correlation

Reconstructs parent-child process relationships to build behavioral chains rather than treating logs as isolated events.

### Timeline Reconstruction

Sorts detections chronologically to produce an investigation-style attack timeline showing how activity progressed on each host.

### Host-Based Investigation View

Separates analysis per host, allowing independent attack timelines and tactic summaries for each machine.

### Structured Reporting

Outputs a JSON report containing detailed detection metadata, making the tool suitable for further automation or analysis.

---

## Example Output

ATT&CKFlow produces investigation-style summaries such as:

```
=== ATTACK TIMELINE | HOST: WS-01 ===
2026-02-03 10:00:01 | Execution | T1059.001 | powershell.exe ← ROOT
2026-02-03 10:00:45 | Persistence | T1547 | schtasks.exe ← powershell.exe
2026-02-03 10:02:35 | Credential Access | T1003 | procdump.exe ← curl.exe
```

---

## Architecture Overview

ATT&CKFlow is structured in four logical layers:

1. **Normalization Layer** – Converts raw logs into a consistent schema
2. **Detection Layer** – Applies behavior-based logic and MITRE mapping
3. **Correlation Layer** – Builds process lineage and attack chains
4. **Presentation Layer** – Generates summaries, timelines, and reports

This mirrors the high-level architecture of modern detection engineering platforms.

---

## Usage

### Analyze a Single Log Manually

```
python3 mapper.py
```

### Analyze a Log File

```
python3 mapper.py --file logs.txt
```

### Show Help Menu

```
python3 mapper.py --help
```

---

## Log Format

The tool expects structured endpoint-style logs containing fields such as:

```
Time=2026-02-03T10:00:01 Host=WS-01 User=sid Parent=winword.exe Process=powershell.exe Cmd="powershell -enc SQBFAFgA"
```

Logs are normalized internally, allowing consistent detection and correlation.

---

## Project Scope

ATT&CKFlow is a **detection engineering prototype**, not a production security platform. It demonstrates:

* Threat-informed detection design
* MITRE ATT&CK integration
* Behavioral process correlation
* Attack chain reconstruction

---

## Current Limitations

* Correlation is heuristic-based (no PID/GUID tracking)
* Keyword-driven detection logic is used instead of full behavioral analytics
* No real-time streaming or alerting
* No integration with real telemetry sources (Sysmon, EDR, network logs)
* Confidence scoring is static and not environment-aware

---

## Future Improvements

* PID-based process correlation
* Multi-event behavioral detection rules
* Real telemetry ingestion (Sysmon/EDR JSON)
* Network telemetry correlation
* Baseline-driven anomaly scoring
* Real-time detection pipeline

---

## Author

smartytinker

Detection Engineering and Threat Analysis Enthusiast
