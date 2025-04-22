# Threat Hunting Lab: Detecting Unauthorized Port Scanning

Leveraging Microsoft Defender for Endpoint & KQL to Investigate Network Anomalies


## Created By:
- **Author Name**: Richard Edwards
- **Author Contact**: https://www.linkedin.com/in/richard-demetrius-edwards
- **Date**: April, 21 2025
---

## Lab Overview
Scenario: Responded to performance degradation reports on legacy system windows10-vm-ri (10.1.0.37), uncovering an internal port scan executed via PowerShell. 
Key Skills Demonstrated:
* Endpoint detection with Microsoft Defender for Endpoint (MDE)
* KQL query development for threat hunting
* MITRE ATT&CK mapping and policy gap analysis
* Incident response workflow (detection → containment → lessons learned) 
--

## Technical Investigation

### 1. Hypothesis & Initial Detection

Observation:

Sudden performance degradation on windows10-vm-ri (10.1.0.37)
40+ failed internal connection attempts detected
Suspected TTP:

Unauthorized port scanning or data exfiltration
KQL Query 1 - Identify Anomalous Connections:

kql
DeviceNetworkEvents
| where DeviceName contains "windows10-"
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc


<img width="1390" alt="Query1-results" src="https://github.com/user-attachments/assets/c1155d78-c306-4de3-aeff-f7e6bf6512d7" />

Finding: Mass connection failures indicative of scanning activity.

### 2. Port Scan Identification

Analysis:

Sequential connection attempts to multiple ports on 10.1.0.37
Pattern matches known port scanning behavior
KQL Query 2 - Isolate Target IP Activity:

kql
let IPInQuestion = "10.1.0.37";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc

<img width="1233" alt="Observing-failedconnections-10 1 0 37" src="https://github.com/user-attachments/assets/f433b398-dfb6-48d8-8c6e-dee5412e62f7" />

Key Insight: Scan originated from the same VM experiencing slowdowns.

### 3. Process Execution Trace

Investigation Pivot:

Identified earliest scan timestamp (2025-04-21T17:05:01Z)
Correlated with process creation events
KQL Query 3 - Trace Suspicious Process:

kql
let VMName = "windows10-vm-ri";
let specificTime = datetime(2025-04-21T17:05:01.87382Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

<img width="1139" alt="DeviceProcessEvents-query" src="https://github.com/user-attachments/assets/88e539be-ed9c-4c7d-86a7-d5fee968258e" />


Discovery: PowerShell executing portscan.ps1 script.

### 4. Script Content Analysis

Forensic Action:

Retrieved script contents despite file deletion:
powershell
Get-Content -Path 'C:\ProgramData\portscan.ps1'

<img width="1440" alt="portscan ps1-powershell" src="https://github.com/user-attachments/assets/33061b6c-6ede-4a87-a379-0190e3cdf6f0" />


Finding: Confirmed port scanning functionality via PowerShell.

### 5. Account Attribution & Containment

Critical Observations:

Script executed under WINDOWS account (non-standard context)
No legitimate business purpose for this activity

<img width="1276" alt="AccountName-windows" src="https://github.com/user-attachments/assets/7c23ff4b-3668-4447-9eab-4bc6788bbd90" />


Response Actions:

Immediate host isolation
Defender AV scan (no malware detected)
Initiated reimaging process

### 6. Root Cause & Resolution

Final Determination:

Day 3 intern conducted unauthorized scanning for KQL training
Legacy system vulnerability to scan traffic
Remediation Steps:

Revised intern access privileges
Established security training policies
Created isolated lab environment for future exercises

## MITRE ATT&CK Mapping
Tactic	Technique	Relevance
Discovery	T1046 (Network Scanning)	Port scan disrupted legacy systems.
Execution	T1059.001 (PowerShell)	Unrestricted script execution enabled abuse.
Defense Evasion	T1070.004 (File Deletion)	Script auto-removed post-execution (evaded static analysis).


## Key Findings & Recommendations
Security Gaps Identified
1. Policy:
    * Unrestricted PowerShell and default-permissive internal network rules.
2. Monitoring:
    * No alerts for mass ConnectionFailed events or atypical account behavior (WINDOWS running scripts).
Actionable Mitigations
* Immediate:
    * Implement PowerShell Constrained Language Mode.
    * Segment legacy systems via VLANs/NSGs.
* Long-Term:
    * Deploy behavioral baselining (e.g., alert on WINDOWS account anomalies).
    * Formalize security training policies for interns.

## Lessons Learned
1. Operational Impact: Even benign activities (e.g., training scans) can disrupt fragile systems.
2. Defense-in-Depth: Technical controls (e.g., least privilege) must align with procedural controls (training).
Lab Value: This exercise mirrors real-world threat hunting workflows, demonstrating proficiency in EDR tools, KQL, and incident response – critical skills for SOC/blue team roles.

