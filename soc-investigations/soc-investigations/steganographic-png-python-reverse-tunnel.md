# 🚨 Incident Investigation: ClickFix Lure, DLL Sideloading, Steganographic PNG Payload & Python Reverse Tunnel

## 📋 Case Overview
* **Category:** Endpoint Security / DLL Sideloading, Persistence & Command-and-Control (C2)
* **Affected Endpoint:** `CMI-WKS-07` (Windows 11 Enterprise) – User: `harper.lunde`
* **Log Sources Analyzed:** Endpoint XDR Process Tree, Sysmon Process Creation & Image Load Telemetry, Windows Registry & Scheduled Task Logs, Perimeter Firewall & DNS Logs
* **Scenario Context:** Following a ClickFix-style "verification" command pasted by the user, an alert triggered on `CMI-WKS-07` involving a legitimate Microsoft-signed binary (`LockScreenContentServer.exe`) executing alongside three `.png` image files to establish a persistent outbound Python reverse tunnel.

---

## 🔍 Investigation Methodology

### 1. Non-Standard Execution Path & DLL Sideloading (`C:\ProgramData\f47f2a8c21c9df4e`)
* **Process & Image-Load Inspection:** Examined Sysmon process creation (`Event ID 1`) and DLL image-load (`Event ID 7`) telemetry on `CMI-WKS-07` to trace where `LockScreenContentServer.exe` executed.
* **Finding:** Although `LockScreenContentServer.exe` carries a valid Microsoft signature, it was staged inside a hidden, non-standard subfolder (**`C:\ProgramData\f47f2a8c21c9df4e`**) alongside a rogue DLL and three steganographic `.png` image files—confirming **DLL search-order hijacking / sideloading** to decode the hidden `.png` payload in memory.

### 2. Dual Persistence Mechanism (`LockScreenContentServer_MuODG5yBM`)
* **Registry & Scheduled Task Analysis:** Audited Windows Registry modification events and Task Scheduler telemetry to determine how the sideloaded binary maintained survival across reboots.
* **Finding:** Identified two redundant persistence mechanisms created simultaneously—a **Registry `Run` key value** and a **recurring Scheduled Task**—both pointing to the staged binary in `C:\ProgramData\f47f2a8c21c9df4e` and sharing the exact identifier **`LockScreenContentServer_MuODG5yBM`**.

### 3. Outbound Python Reverse Tunnel & C2 Network Telemetry (`gitnow[.]dev`)
* **DNS, Firewall & Endpoint Network Correlation:** Correlated DNS query logs with perimeter firewall and endpoint socket telemetry to isolate anomalous outbound connections initiated by a windowless background process.
* **Finding:** Identified a persistent, long-lived outbound C2 tunnel established by the unpacked Python runtime communicating with the external domain **`gitnow[.]dev`**, distinct from the workstation's standard browser traffic.

---

## 🛡️ Verdict & Remediation Actions

* **Final Classification:** **True Positive – DLL Sideloading & Steganographic Payload Execution Leading to Persistent Python C2 Tunnel**
* **Containment & Response:**
  1. **Host Isolation:** Immediately isolate `CMI-WKS-07` via XDR to sever the active outbound Python reverse tunnel to `gitnow[.]dev`.
  2. **Process & Artifact Eradication:** Terminate the malicious `LockScreenContentServer.exe` and child Python processes, and purge the entire **`C:\ProgramData\f47f2a8c21c9df4e`** directory (including the staged binary, rogue DLL, and three `.png` payload files).
  3. **Persistence Removal:** Delete both the Registry `Run` key entry and the recurring Scheduled Task matching the persistence identifier **`LockScreenContentServer_MuODG5yBM`**, then re-scan to verify full cleanup.
  4. **Network & Fleet Hunt:** Sinkhole/block **`gitnow[.]dev`** and its resolved IPs at the perimeter firewall and DNS filter, reset credentials for `harper.lunde`, and hunt across all endpoints for `LockScreenContentServer.exe` executing outside `System32` or referencing `LockScreenContentServer_MuODG5yBM`.

---
*Note: Case study sanitized and structured for defensive portfolio demonstration.*
