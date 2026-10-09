# Super EVTX Analyzer

A modular Windows Event Log (EVTX) forensic analysis and incident investigation platform built with Python and PyQt6.

The project is designed to help investigators acquire EVTX evidence, preserve its integrity, parse events, detect security-relevant activity, correlate events, extract investigation intelligence, calculate risk, visualize relationships, and generate forensic reports.

> **Important:** This repository contains the application source code only. Real `.evtx` evidence files are not included in the repository.

---

## What is EVTX?

**EVTX** is the file format used by modern Microsoft Windows systems to store Windows Event Logs.

Windows records many types of operating-system and application activity as events. These events can contain information such as:

- Logon and authentication activity
- Process creation
- Privilege assignments
- System and service activity
- Application errors
- PowerShell activity
- Security events
- Remote access activity
- Task Scheduler activity
- Windows Defender activity
- Network and firewall-related activity

Windows stores these events in `.evtx` files.

Common examples include:

```text
Security.evtx
System.evtx
Application.evtx
```

The exact available logs depend on the Windows installation, enabled auditing policies, installed software, and configured services.

### Why are EVTX files important in Digital Forensics?

EVTX files can provide a historical record of activity that occurred on a Windows machine.

During a forensic investigation, an analyst can examine event records to reconstruct activities such as:

```text
User authentication
       ↓
Process execution
       ↓
Privilege assignment
       ↓
System activity
       ↓
Possible suspicious behavior
```

An EVTX record can contain information such as:

- Event ID
- Record ID
- Timestamp
- Channel
- Provider
- Computer name
- Event data
- Raw XML representation

The usefulness of an event depends on the event type, available fields, Windows configuration, and the context of the investigation.

> An EVTX event is evidence of recorded activity. A matching security rule does not automatically prove that malicious activity occurred.

---

# Features

## Evidence Acquisition

The evidence layer provides functionality for:

- Importing external `.evtx` files
- Preserving evidence through controlled acquisition
- Calculating SHA-256 hashes
- Verifying evidence integrity
- Storing evidence metadata
- Associating evidence with cases

## EVTX Parsing

The EVTX parser extracts information from Windows Event Log records, including:

- Event ID
- Record ID
- Timestamp
- Channel
- Provider
- Computer
- EventData
- Raw XML
- Evidence ID

The parser is intended to work with valid Windows EVTX files supplied by the investigator.

Parsing and detection are separate concepts. An EVTX file can be successfully parsed even when the project does not contain a dedicated detection rule for a particular event.

## Security Detection

The current security rules cover:

| Event ID | Description |
|---:|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |

The detection architecture separates rules from the detection engine so additional detection rules can be added independently.

## IOC Extraction

The intelligence layer extracts and deduplicates investigation-relevant indicators from events.

Examples include:

- IP addresses
- Usernames
- Process-related information
- Other event-derived indicators

IOCs can be associated with the events from which they were extracted.

## Entity Analysis

The intelligence layer represents investigation entities and their relationships with events, IOCs, and findings.

## Event Correlation

The correlation engine connects related events using temporal and contextual relationships.

This allows an investigation to move from isolated events toward activity sequences such as:

```text
Authentication
      ↓
Privilege Assignment
      ↓
Process Creation
      ↓
Related Activity
```

## Anomaly Detection

The analytics layer provides event-burst analysis over time windows to identify unusual concentrations of activity.

## MITRE ATT&CK Mapping

Security-relevant findings can be associated with MITRE ATT&CK techniques.

Mappings are intended as investigative indicators rather than automatic proof of attacker behavior.

## Risk Scoring

The analytics layer calculates an explainable risk score based on investigation results.

The score considers factors such as:

- Finding severity
- Number of findings
- Correlations
- Anomalies
- IOC presence

The final score is bounded between `0` and `100`.

Risk levels are represented as:

```text
Low
Medium
High
Critical
```

## Investigation Graph

The investigation module provides graph data and a graphical investigation view for relationships between entities such as:

- Findings
- Events
- IOCs
- Entities
- MITRE techniques
- Correlated activity

## Timeline Analysis

The timeline module provides functionality for:

- Event ordering
- Timeline merging
- Filtering
- Timeline analysis

## Chain of Custody

The lifecycle service records major evidence-processing operations.

Examples include:

```text
EVIDENCE_ACQUIRED
HASH_VERIFIED
EVIDENCE_PARSED
ANALYSIS_PERFORMED
REPORT_GENERATED
```

This provides traceability for important forensic processing steps.

## PDF Reporting

The reporting module generates investigation reports from the stored analysis data.

---

# Architecture

```text
                         ┌──────────────────────┐
                         │       PyQt6 GUI      │
                         │    app/gui/          │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │  Lifecycle / Workers │
                         │  services/           │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
      ┌─────────────┐        ┌─────────────┐       ┌─────────────┐
      │ EVTX Parser │        │  Detection  │       │  Timeline   │
      │ parsers/    │        │ detection/  │       │ timeline/   │
      └──────┬──────┘        └──────┬──────┘       └──────┬──────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │      Analysis        │
                         │ analysis/            │
                         │ correlation/         │
                         │ analytics/           │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             ▼                      ▼                      ▼
      ┌─────────────┐        ┌─────────────┐       ┌─────────────┐
      │ Intelligence│        │  Findings   │       │ Investigation│
      │ intelligence│        │ findings/   │       │ investigation│
      └──────┬──────┘        └──────┬──────┘       └──────┬──────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │      Storage         │
                         │ storage/             │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       Reporting      │
                         │ reporting/           │
                         └──────────────────────┘
```

---

# Project Structure

```text
Super Evtx analyzer/
│
├── analysis/
│   ├── __init__.py
│   └── engine.py
│
├── analytics/
│   ├── __init__.py
│   ├── anomaly.py
│   ├── scoring.py
│   └── statistics.py
│
├── app/
│   ├── __init__.py
│   ├── modular_main.py
│   └── gui/
│       ├── __init__.py
│       ├── main_window.py
│       └── workers.py
│
├── cases/
│   ├── __init__.py
│   └── manager.py
│
├── correlation/
│   ├── __init__.py
│   └── engine.py
│
├── detection/
│   ├── __init__.py
│   └── engine.py
│
├── evidence/
│   ├── __init__.py
│   ├── acquisition.py
│   ├── hashing.py
│   └── metadata.py
│
├── findings/
│   ├── __init__.py
│   └── finding.py
│
├── intelligence/
│   ├── __init__.py
│   ├── entities.py
│   ├── ioc.py
│   └── mitre.py
│
├── investigation/
│   ├── __init__.py
│   ├── graph.py
│   └── graph_view.py
│
├── models/
│   ├── __init__.py
│   └── event.py
│
├── parsers/
│   ├── __init__.py
│   └── evtx_parser.py
│
├── reporting/
│   ├── __init__.py
│   └── report.py
│
├── rules/
│   ├── base.py
│   └── security.py
│
├── scripts/
│   └── clean.py
│
├── services/
│   ├── __init__.py
│   ├── lifecycle.py
│   └── workers.py
│
├── storage/
│   ├── __init__.py
│   ├── database.py
│   └── search.py
│
├── timeline/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── filters.py
│   └── merger.py
│
├── config.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Requirements

The project is written in Python and uses a PyQt6-based graphical interface.

Install the project dependencies with:

```powershell
pip install -r requirements.txt
```

It is recommended to use a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then install the dependencies:

```powershell
pip install -r requirements.txt
```

---

# Running the Application

Run the application from the project root:

```powershell
python -m app.modular_main
```

The graphical interface provides the main forensic workflow for working with EVTX evidence.

---

# Obtaining EVTX Files on Windows

The application expects `.evtx` files as external forensic evidence.

Windows normally stores Event Log files under:

```text
C:\Windows\System32\winevt\Logs\
```

For example:

```text
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\System32\winevt\Logs\Application.evtx
```

Additional logs may also exist depending on the Windows version, enabled services, installed applications, auditing configuration, PowerShell configuration, Sysmon installation, and other system components.

## Method 1 — Copy EVTX Files Directly

Open PowerShell as Administrator and inspect the Windows Event Log directory:

```powershell
Get-ChildItem "C:\Windows\System32\winevt\Logs\*.evtx"
```

You can copy a log to a separate investigation directory:

```powershell
Copy-Item `
    "C:\Windows\System32\winevt\Logs\Security.evtx" `
    "C:\Users\<USERNAME>\Desktop\Security.evtx"
```

For multiple EVTX files:

```powershell
Copy-Item `
    "C:\Windows\System32\winevt\Logs\*.evtx" `
    "C:\Users\<USERNAME>\Desktop\EVTX\"
```

Create the destination directory first if necessary:

```powershell
New-Item -ItemType Directory `
    -Path "C:\Users\<USERNAME>\Desktop\EVTX" `
    -Force
```

> For real forensic investigations, preserve the original evidence and work on a controlled copy.

## Method 2 — Export a Log Using Event Viewer

Windows Event Viewer can also save event logs.

1. Press `Win + R`.
2. Enter:

```text
eventvwr.msc
```

3. Open **Windows Logs**.
4. Select a log such as:
   - Security
   - System
   - Application
5. Use **Save All Events As...**.
6. Select the `.evtx` format when saving the log.

This creates an EVTX file that can be supplied to the analyzer.

## Method 3 — Export Using `wevtutil`

Windows also provides the `wevtutil` command-line utility.

For example:

```powershell
wevtutil epl Security Security.evtx
```

Export the System log:

```powershell
wevtutil epl System System.evtx
```

Export the Application log:

```powershell
wevtutil epl Application Application.evtx
```

You can then move the resulting files into a separate evidence directory and import them into the application.

### Important Evidence Consideration

Do not modify the original evidence unnecessarily.

A safer investigation workflow is:

```text
Windows Host
     │
     ▼
Acquire EVTX
     │
     ▼
Preserve Original
     │
     ▼
Calculate SHA-256
     │
     ▼
Verify Integrity
     │
     ▼
Analyze a Controlled Copy
```

---

# Example Windows EVTX Sources

Depending on the Windows configuration, useful logs can include:

```text
Security.evtx
System.evtx
Application.evtx
```

Other logs may include channels related to:

```text
PowerShell
Sysmon
Windows Defender
Task Scheduler
Remote Desktop
Windows Firewall
```

The exact filenames and availability depend on the Windows system and its configuration.

---

# Investigation Workflow

The intended workflow is:

```text
1. Create a Case
        ↓
2. Add EVTX Evidence
        ↓
3. Acquire / Preserve Evidence
        ↓
4. Verify SHA-256
        ↓
5. Parse EVTX
        ↓
6. Run Analysis
        ↓
7. Generate Findings
        ↓
8. Extract IOCs / Entities
        ↓
9. Correlate Events
        ↓
10. Detect Anomalies
        ↓
11. Map MITRE Techniques
        ↓
12. Calculate Risk
        ↓
13. Investigate Graph
        ↓
14. Generate Report
```

---

# Data Storage

The application uses SQLite for persistent investigation data.

The storage layer is responsible for information such as:

```text
Cases
Evidence
Events
Findings
IOCs
Entities
Correlations
Anomalies
MITRE mappings
Chain of Custody
```

Runtime databases and generated artifacts should not be committed to Git.

---

# Repository and Evidence Separation

The repository intentionally does **not** contain real EVTX evidence.

This is important because EVTX files can contain sensitive information, including:

- Usernames
- Computer names
- IP addresses
- Security events
- Process information
- Authentication activity
- Other host-specific information

Therefore:

```text
Source Code
    → Git repository

Real EVTX Evidence
    → Local / controlled evidence storage
```

Do not commit real forensic evidence to a public repository unless it has been intentionally sanitized and you have permission to distribute it.

---

# Cleaning Generated Artifacts

The project contains:

```text
scripts/clean.py
```

Run it with:

```powershell
python scripts/clean.py
```

The cleanup script is intended to remove generated runtime artifacts such as databases, logs, temporary files, reports, and Python cache directories.

It does **not** remove the project's source code.

Real forensic evidence should always be handled separately and should not be removed automatically by a general cleanup operation.

---

# Current Detection Coverage

The current security rules include:

| Event ID | Description |
|---:|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |

This is only a subset of Windows security events.

The ability to parse an EVTX file does not mean that every event inside it has a dedicated detection rule.

For example, an EVTX file may contain hundreds of event types that can be stored and investigated without having a specialized detection rule.

Future rule groups can include:

- Additional Security events
- System events
- PowerShell events
- Sysmon events
- Windows Defender events
- Remote Desktop events
- Task Scheduler events
- Firewall events
- Additional authentication events
- Persistence-related events

---

# Limitations

- Detection coverage is smaller than the total Windows EVTX event space.
- A detected event does not automatically prove malicious activity.
- MITRE mappings are investigative indicators rather than proof of attacker behavior.
- Detection quality depends on the fields available in the source EVTX.
- Different Windows configurations produce different available logs and event fields.
- Some Windows logs require specialized rules for meaningful interpretation.
- The project is primarily designed for forensic investigation and analysis rather than real-time endpoint monitoring.

---

# Development Principles

## Evidence Integrity

Evidence should be preserved and verified using cryptographic hashing.

## Traceability

Important evidence-processing operations are recorded through the chain-of-custody functionality.

## Explainability

Detection and risk scoring should provide understandable investigation results.

## Modularity

Parsing, detection, intelligence, analytics, storage, investigation, visualization, and reporting are separated into dedicated modules.

## Separation of Concerns

The GUI is separated from backend processing, while heavy operations use worker mechanisms to keep the interface responsive.

## Evidence Safety

Real forensic evidence is kept outside source control and should be handled as controlled data.

---

# Disclaimer

This project is intended for:

- Digital forensics education
- Security analysis
- Incident investigation
- Windows Event Log research
- Defensive cybersecurity

The analyzer should be used only on systems and evidence that you are authorized to investigate.

---

# License

This project is licensed under the MIT License.

Copyright (c) 2026 triplePoint3r

See the [LICENSE](LICENSE) file for the full license text.

## User-Friendly Investigation Interface

The GUI provides investigation-focused controls for working with large event datasets:

- Search across all visible table columns.
- Filter by a specific table column.
- Sort every table column by clicking its header.
- Select multiple rows and copy them to the clipboard.
- Open a detailed read-only view for any event or result row.
- Display the number of visible and total rows.
- Clear filters and return to the complete dataset.
- Refresh the current case from the database.
- Timeline-specific filtering by:
  - Channel
  - Event ID
  - Start time
  - End time
- Confirmation dialogs for potentially long-running analysis operations.
- Status-bar progress and operation messages.
- Read-only forensic tables to prevent accidental modification of evidence/results.
- Evidence, Findings, IOCs, MITRE, Chain of Custody, Timeline, and Graph views.

Table sorting is type-aware where possible, so numeric and timestamp values are sorted by their actual value rather than simple text order.

