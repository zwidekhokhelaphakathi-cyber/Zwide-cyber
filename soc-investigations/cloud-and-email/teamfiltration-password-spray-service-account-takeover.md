# 🚨 Incident Investigation: TeamFiltration Password Spray to Forgotten Service Account Takeover

## 📋 Case Overview
* **Category:** Cloud Identity Security / Password Spraying & Service Account Compromise
* **Compromised Principal:** `svc-posreports` (Legacy Service Account lacking MFA registration)
* **Log Sources Analyzed:** Entra ID Sign-In Logs (`cloud-azure-signin`), Entra ID Audit Logs (`cloud-azure-audit`), Microsoft Graph & Cloud Application Telemetry
* **Scenario Context:** Over a three-day window starting on the evening of 14 August, a cloud-hosted password-spray campaign using the **TeamFiltration** framework targeted Microsoft Teams sign-ins across the directory. Although nearly two hundred attempts failed and appeared "blocked," retrospective hunting uncovered a compromised legacy service account (`svc-posreports`) that lacked MFA registration and Conditional Access coverage across non-portal cloud applications.

---

## ⚠️ Triggered SIEM Detection Rules
Four correlated identity detections fired across Entra ID sign-in telemetry:
1. **`Service-Account-Interactive-Success-External-Origin`** *(High)* – A functional/service account completed an interactive single-factor sign-in from an external IP outside its established baseline.
2. **`Conditional-Access-Block-Then-Success-Same-Principal`** *(High)* – A principal was blocked by Conditional Access on one application and subsequently authenticated into a different application from the same source IP minutes later.
3. **`Sign-In-Failure-Burst-Across-Directory`** *(Medium)* – High-volume single-factor authentication failures across numerous directory accounts within a short window.
4. **`Outdated-Desktop-Client-Build-Sign-In`** *(Medium)* – First-party desktop application authentication presenting a stale client build string well behind the current fleet baseline.

---

## 🔍 Investigation Methodology

### 1. Fingerprinting the TeamFiltration Spray Client (`1.3.00.30866`)
* **User-Agent & Client Build Analysis:** Filtered `cloud-azure-signin` records from the evening of **14 August** (`18:52 UTC`) across burst failures targeting Microsoft Teams to isolate the fixed client string used by the **TeamFiltration** framework.
* **Finding:** Identified the hardcoded, outdated Microsoft Teams desktop client version **`1.3.00.30866`** inside the User-Agent string across all cloud-hosted spray attempts, providing a reliable pivot to track the campaign across the three-day window.

### 2. Identifying the Compromised Service Account (`svc-posreports`) & Operator IP (`149.88.104[.]19`)
* **Result Code & Post-Spray Pivot:** Audited all result codes within the TeamFiltration burst rather than dismissing the alert on aggregate failures, uncovering a single successful token issuance (`ResultType == 0`) for the forgotten legacy service account **`svc-posreports`**.
* **Follow-On Operator Origin:** Pivoted from the compromised principal (`svc-posreports`) to subsequent sign-ins within a minute of the spray success, identifying hands-on follow-on access originating from an external non-cloud operator IP: **`149.88.104[.]19`**.

### 3. Conditional Access Gaps (`Azure Portal` Block vs. Silent Microsoft Graph Token)
* **Application-by-Application Access Audit:** Traced the attacker's lateral probing across cloud applications from **`149.88.104[.]19`**:
  * **MFA Enrollment Interruption:** Access to the **`Azure Portal`** was interrupted because the portal enforced a second factor and `svc-posreports` had no MFA method registered, triggering an enrollment prompt rather than issuing a token.
  * **Silent Microsoft Graph Token Issuance:** Despite the `Azure Portal` block, other cloud applications lacked equivalent Conditional Access enforcement—allowing the attacker to reach company documents and silently obtain a **Microsoft Graph** access token via application ID **`08e18876-6177-487e-b8b5-cf950c1e598c`**.

---

## 🛡️ Verdict & Remediation Actions
* **Final Classification:** **True Positive – Automated Password Spray (TeamFiltration) Resulting in Legacy Service Account Takeover & Graph Token Issuance**
* **Containment & Response:**
  1. **Immediate Account Containment:** Disable **`svc-posreports`** (or enforce a high-entropy password reset if business-critical), revoke all active refresh tokens (`Revoke-MgUserSignInSession`), and audit its directory role and group memberships.
  2. **Close Conditional Access Policy Gaps:** Expand Conditional Access MFA and trusted-location policies from covering only `Azure Portal` to **All Cloud Apps**, blocking single-factor authentication from untrusted external IPs (`149.88.104[.]19`).
  3. **Graph API & Data Exposure Audit:** Review audit and access logs tied to application ID **`08e18876-6177-487e-b8b5-cf950c1e598c`** and `svc-posreports` to scope any SharePoint documents, OneDrive files, or mailbox data accessed via the Microsoft Graph token.
  4. **Service Account Lifecycle & Client Hardening:** Decommission forgotten legacy service accounts, migrate automated workloads to Managed Identities, and alert on sign-ins presenting outdated client builds such as Teams **`1.3.00.30866`**.

---
*Note: Case study sanitized and structured for defensive portfolio demonstration.*
