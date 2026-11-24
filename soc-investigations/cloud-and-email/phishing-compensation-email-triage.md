# 🚨 Incident Investigation: Post-Breach Compensation Phishing Campaign

## 📋 Case Overview
* **Category:** Email Security / Phishing Triage
* **Log Sources Analyzed:** Exchange Online (`email-o365` / EXO), Raw Email Headers (`Authentication-Results`), Web Proxy Logs, SIEM Log Viewer.
* **Scenario Context:** Following a widely publicized third-party crypto exchange breach (*Kestovan*), an office manager at *Ardmor Lane Advisory* escalated two suspicious compensation-themed emails sent to staff (including the finance assistant's mailbox) for verification.

---

## 🔍 Investigation Methodology

### 1. Email Header & Authentication Analysis

#### Email #1: Kestovan Reconciliation Desk Lure (`declan.moyles@ardmorlane[.]com`)
* **Display Name Spoofing & Reply-To Check:** Inspected the `From` header (`"Kestovan Reserve Desk" <desk@kestovan-reconciliation[.]com>`) and identified a mismatched `Reply-To` address (`claims@kestovan-settlement[.]net`) used to divert victim responses to a secondary lookalike domain.
* **SPF / DKIM / DMARC Verification:** Reviewed `Authentication-Results` (`203.0.113[.]171` / `mta2.kestovan-reconciliation[.]com`, `d=kestovan-reconciliation[.]com`). Although SPF, DKIM, and DMARC all passed, they only authenticated the attacker-controlled lookalike domain rather than the legitimate Kestovan exchange.

#### Email #2: Orrin Wallet Verification Lure (`aoife.kerrigan@ardmorlane[.]com`)
* **Sender & Domain Mismatch:** Compared the lure (`support@orrinwallet-support[.]com`) against legitimate historical mail logs (`news@orrinwallet[.]com`) to confirm lookalike domain impersonation.
* **Third-Party Mailer Abuse & Alignment Check:** Observed that the message was sent via bulk mailing infrastructure (`out-07.letterwave-mail[.]com` / `198.51.100[.]212`). SPF (`smtp.mailfrom=bnc.letterwave-mail[.]com`) and DKIM (`d=letterwave-mail[.]com`) passed for the mailing service, while DMARC was unaligned (`dmarc=none`), allowing the spoofed `From` header through without a reject policy.
* **HTML Body & Social Engineering Analysis:** Identified urgent account-suspension pressure (*"Unverified accounts will be suspended after November 7, 2026"*) and inspected the HTML `href` attribute behind the **Verify** button to extract the true destination hostname.


### 2. Exchange Online Message Trace (`email-o365`)
* Queried SIEM logs (`source:email-o365`) and pivoted on shared campaign attributes (sender address, subject line, and cluster ID) to determine the organization-wide blast radius.
* Identified all internal recipients who received the lures and verified delivery status (`Inbox` vs. `Junk`/`Quarantine`).
* **Scope Finding:** Confirmed that the wallet verification phishing campaign (`support@orrinwallet-support[.]com`) was delivered directly to **9 distinct mailboxes** across *Ardmor Lane Advisory* (including `aoife.kerrigan@ardmorlane[.]com`), alongside the parallel Kestovan reconciliation lure targeting staff such as `declan.moyles@ardmorlane[.]com` and `grace.mulvey@ardmorlane[.]com`.


### 3. Web Proxy & Click-Through Verification (`network-proxy`)
* Pivoted to web proxy logs (`source:network-proxy` on `ARD-PRX-01`) to determine whether any recipient interacted with the embedded verification URL (`https://verify.orrin-wallet[.]co/secure/recovery`).
* Differentiated between initial page loads (`HTTP GET`) and actual form submissions (`HTTP POST`) across internal client IPs.
* **Impact Finding:** Identified two users who opened the verification page (`GET`) before automated blocklist enforcement refused two later requests. Crucially, proxy telemetry confirmed that **`aoife.kerrigan` (`10.62.30.13`) submitted an `HTTP POST` request** to the page (`form field: recovery_phrase`), exposing a cryptocurrency wallet recovery phrase—though no corporate *Ardmor Lane Advisory* Active Directory credentials were requested or compromised.

---

## 🛡️ Verdict & Remediation Actions
* **Final Classification:** **True Positive – Targeted Phishing / Brand Impersonation**
* **Containment & Response:**
  1. **Purge Malicious Messages:** Hard-delete the phishing emails from all affected Exchange Online mailboxes.
  2. **Block IOCs:** Add the sender address, sending domain, and malicious URLs (`verify.orrin-wallet[.]co`) to the tenant blocklist and web proxy filter.
  3. **Wallet & Credential Remediation:** Because the phishing form harvested a cryptocurrency wallet `recovery_phrase` rather than corporate Active Directory credentials, immediately notify `aoife.kerrigan` to transfer any funds to a newly generated wallet seed phrase, while still auditing sign-in logs as a precaution.
  4. **User Awareness:** Notify the reporting office manager and finance team to confirm the emails are malicious and reinforce reporting procedures.


---
*Note: Case study sanitized and structured for defensive portfolio demonstration.*
