# 🚨 Incident Investigation: Help-Desk Vishing, Rogue MFA Registration & SharePoint Exfiltration

## 📋 Case Overview
* **Category:** Identity & Cloud Security / Vishing & Account Takeover (ATO)
* **Log Sources Analyzed:** Cloud Identity / Entra ID Sign-In & Audit Logs, Microsoft Graph API Logs, SharePoint Audit Logs, Exchange Mailbox Access Logs, DNS Logs
* **Scenario Context:** An employee reported receiving a voice call from someone impersonating internal IT Help Desk who guided them through registering a new sign-in method (passkey/MFA) on their phone. Later that evening, high-volume file downloads occurred from the employee's SharePoint account.

---

## ⚠️ Triggered SIEM Detection Rules
Six correlated alerts fired across identity, DNS, Graph API, and cloud storage telemetry:
1. **`Security-Info-Registration-From-New-Origin`** – New authentication method registered from an IP with no baseline sign-in history.
2. **`Concurrent-Managed-And-Unmanaged-Sessions`** – Active browser session from an unmanaged IP alongside normal corporate managed-device token refreshes within the same hour.
3. **`Identity-Themed-New-Domain-Resolution`** – DNS query for an unapproved domain containing identity keywords (`passkey`, `sso`, `mfa`, `login`).
4. **`Paced-Graph-Directory-Enumeration`** – Automated Microsoft Graph API queries spanning 3+ resource categories (`tenant`, `directory`, `privilege`, `application`, `repository`, `mailbox`) within 90 minutes.
5. **`Scripted-Client-Library-Retrieval-From-Outside`** – Automated/scripted file downloads from multiple SharePoint libraries outside corporate egress IPs.
6. **`Exchange-API-Mailbox-Reads-From-New-Origin`** – REST API `MailItemsAccessed` activity from a newly observed source IP.

---

## 🔍 Investigation Methodology

### 1. Baseline Identity Comparison & Initial Intrusion Origin

* **Baseline Analysis:** Reviewed three weeks of historical authentication logs for the targeted employee to establish normal login origins across their managed laptop, enrolled mobile device, and corporate office network.
* **Anomalous Sign-In Finding:** Identified a rogue web logon on the afternoon of **29 September** originating from **`203.0.113[.]154`**, an external IP completely absent from the user's three-week baseline.

### 2. Vishing Lure Domain, Rogue MFA Registration & Alert Triage (`tomas.ferreira`)

* **Phishing/Vishing Lure Domain:** Pivoted to DNS and web proxy telemetry a few minutes prior to the external logon (`203.0.113[.]154`) and confirmed that **`tomas.ferreira`** navigated to the caller-supplied lure domain **`northcape.passkeyhelpdesk[.]com`**.
* **Rogue Authentication Method Persistence:** Reviewed platform identity audit events and discovered that, rather than registering a corporate FIDO2 passkey as claimed during the call, the attacker enrolled a rogue authenticator app entry logged under the tag **`SoftwareTokenActivated`**.
* **True Positive vs. False Positive Scoping:** Differentiated two high-volume library retrieval alerts triggered on the afternoon of 29 September—verifying that an earlier alert on a colleague was a benign false positive tied to a scheduled **`Claims-Archive-2026`** repository migration, whereas the evening activity on **`tomas.ferreira`** represented unauthorized post-compromise access.

### 3. Post-Compromise Persistence, Scripted Retrieval & Exchange Exfiltration
* **Scripted SharePoint & Storage Retrieval:** Analyzed file download telemetry between the afternoon of 29 September and the following morning, confirming that dozens of items were pulled from external origins using the automated Python client **`python-httpx/0.27.2`** rather than a standard browser on the user's corporate laptop.
* **Follow-Up Persistence Logon:** Identified a second unauthorized external sign-in before 07:00 the next morning from a secondary outside IP, which bypassed MFA by entering an **`OATH verification code`** generated from the rogue `SoftwareTokenActivated` authenticator registered during the vishing call.
* **Exchange Mailbox Exposure Scoping:** Quantified REST API `MailItemsAccessed` batch reads across both days from the two external origins, determining that a total of **`229` mailbox items** were accessed—providing Privacy and Legal teams with the exact scope required for breach notification assessment.


---

## 🛡️ Verdict & Remediation Actions

* **Final Classification:** **True Positive – Social Engineering (Help-Desk Vishing) Leading to Rogue Software Token Persistence & Cloud Data Exfiltration**
* **Containment & Response:**
  1. **Revoke Rogue Authentication Method:** Immediately remove the unauthorized **`SoftwareTokenActivated`** entry registered on **`tomas.ferreira`**'s account to cut off `OATH verification code` MFA persistence.
  2. **Session & Credential Containment:** Revoke all active refresh tokens/sessions (`Revoke-MgUserSignInSession`), force a password reset, and require re-registration of legitimate MFA via a verified out-of-band channel.
  3. **Block Infrastructure & Scripted Clients:** Block **`203.0.113[.]154`**, the secondary external source IP, and the vishing lure domain **`northcape.passkeyhelpdesk[.]com`** at the firewall, Conditional Access named locations, and DNS sinkhole, while alerting on non-browser automated user agents such as **`python-httpx/0.27.2`**.
  4. **Data Breach & Scope Assessment:** Provide Privacy and Legal teams with the full inventory of downloaded SharePoint items and the **`229` Exchange mailbox items** accessed via `MailItemsAccessed` batch reads to assess breach notification requirements, and enforce Conditional Access policies restricting security info registration to compliant corporate devices.

---
*Note: Case study sanitized and structured for defensive portfolio demonstration.*
