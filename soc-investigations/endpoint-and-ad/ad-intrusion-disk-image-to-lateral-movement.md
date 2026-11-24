# 🚨 Incident Investigation: Multi-Day Active Directory Intrusion (Disk Image Lure to Lateral Movement)

## 📋 Case Overview
* **Category:** Enterprise Intrusion / Active Directory Compromise & Pre-Ransomware Staging
* **Environment:** `halvoren.local` (Windows Active Directory estate: Domain Controller, File Server, Application Server, and Operations/Finance Workstations)
* **Patient Zero:** `HALVOREN\marit.osterberg`
* **Log Sources Analyzed:** Endpoint XDR Process Tree, Sysmon Process & File Creation Logs, Windows Security Event Logs, Perimeter Firewall, Proxy & DNS Logs
* **Scenario Context:** Over a four-day window, low-priority alerts scattered across SIEM, XDR, and perimeter telemetry masked a coordinated intrusion. Retrospective correlation reconstructed the full kill chain—from an emailed disk-image attachment (`E:\`) to Active Directory discovery, LSASS credential dumping, rogue admin creation, and a fallback remote-access channel on an internal application server.

---

## 🔍 Kill-Chain Reconstruction & Investigation Methodology

### 1. Initial Access & Hidden Loader Execution (`rundll32.exe`)
* **XDR & Sysmon Process Correlation:** Traced `explorer.exe` (`PID 4180`) under `HALVOREN\marit.osterberg` mounting an emailed disk-image attachment (`E:\`) and clicking a disguised shortcut that executed a hidden DLL export:
  * **Initial Loader Command Line:** `rundll32.exe E:\tamirlan.dll,EdhVniqdWt` (`PID 6512`)
  * **Loader SHA-256 Hash:** `123f96ff0a583d507439f79033ba4f5aa28cf43c5f2c093ac2445aaebdcfd31b`
  * **Secondary Staged Execution:** `rundll32.exe C:\Users\marit.osterberg\AppData\Local\Temp\settings.dll,StartM` (`PID 7220`)

### 2. Active Directory & Domain Trust Discovery

* **Enumeration Commands Identified:** Observed hands-on-keyboard reconnaissance utilities spawned under the compromised session:
  * `ad.exe -f "(objectCategory=person)" -gcb -sc trustdmp` (`PID 7544`) – Queried Global Catalog user objects and dumped domain trust relationships.
  * `nltest /dclist:halvoren.local` (`PID 7618`) – Enumerated Domain Controllers for the `halvoren.local` forest.

### 3. Defense Evasion, Cobalt Strike C2, LSASS Credential Theft & Fallback RMM

* **Process Masquerading (`MITRE ATT&CK T1036`):** Rather than generating outbound network traffic directly from the loader, the threat actor injected into a signed Windows Mail binary (`wabmig.exe`, `PID 6808`) via `WmiPrvSE.exe -Embedding` (`PID 2104`) so HTTPS C2 beacons appeared to originate from a trusted Microsoft-signed executable.
* **Cobalt Strike Beacon C2 Domain:** Correlated DNS query telemetry with perimeter firewall HTTPS logs to identify the beacon's command-and-control domain resolved seconds prior to session establishment: **`fuvataren[.]com`**.
* **LSASS Credential Harvesting (`dag.fjellheim`):** Identified a signed Sysinternals utility dumping `lsass.exe` memory to disk on the application server and compressing the archive, followed hours later by anomalous lateral logons using the harvested privileged account **`HALVOREN\dag.fjellheim`**.
* **Fallback Remote-Access Persistence (`MITRE ATT&CK T1219`):** On Day 4, after creating a rogue local administrator account on the application server, the operator installed a commodity remote-desktop utility as a persistent service and connected inbound from external operator IP **`108.177.235[.]25`**.

---

## 🛡️ Verdict & Remediation Actions

* **Final Classification:** **True Positive – Multi-Stage Active Directory Intrusion & Pre-Ransomware Staging**
* **Containment & Recovery:**
  1. **Host & Server Isolation:** Isolate Patient Zero (`marit.osterberg`'s workstation) and the compromised application server via XDR to sever active outbound C2 (`fuvataren[.]com`) and inbound RMM sessions (`108.177.235[.]25`).
  2. **Eradicate Rogue Persistence & Tooling:** Remove the unauthorized remote-access service (`T1219`) and rogue local administrator account from the application server, purge staged DLLs (`settings.dll`, `tamirlan.dll`), and block loader SHA-256 `123f96ff0a583d507439f79033ba4f5aa28cf43c5f2c093ac2445aaebdcfd31b` across EDR.
  3. **Domain-Wide Credential Reset:** Force immediate password resets and token revocations for **`HALVOREN\dag.fjellheim`**, **`HALVOREN\marit.osterberg`**, and all privileged/service accounts exposed on the application server, and execute a double `KRBTGT` password reset.
  4. **Perimeter & Policy Hardening:** Block **`fuvataren[.]com`**, **`108.177.235[.]25`**, and all loader/stager IPs at the perimeter firewall and DNS filter, restrict `.iso`/`.img` disk-image attachments at the email gateway, and audit WMI/process-injection and RMM service installation policies.

---
*Note: Case study sanitized and structured for defensive portfolio demonstration.*
