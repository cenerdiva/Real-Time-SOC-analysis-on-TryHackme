# Real-Time-SOC-analysis-on-TryHackme
This report details the analysis performed using the SOC Simulator scenarios on [TryHackMe](https://tryhackme.com). The objective was to conduct real-time monitoring, classify alerts, and determine whether they were True Positives or False Positives. Various tools, including Splunk, VirusTotal, and an Analyst VM, were used in the investigation process.

## **Alert Investigations and Findings**

### **Alert 1000: Suspicious Email from an External Domain**
- **Action Taken:** Assigned the alert to myself for investigation.
- **Analysis Steps:**
  1. Checked for email attachments—none were found.
  2. Verified the sender domain (`boone@hatventuresworldwide.online`) using Splunk.
  3. Extended the search to a one-year window to look for past activity related to the domain.
  4. Conducted additional verification using VirusTotal.
- **Findings:** The domain was not flagged as malicious by any security vendors.
- **Incident Classification:** False Positive
- **Closure Rationale:** No malicious indicators associated with the sender domain.

### **Alert 1001: Suspicious Email from an External Domain**
- **Action Taken:** Followed the same investigation approach as Alert 1000.
- **Findings:** The domain remained unflagged as malicious.
- **Incident Classification:** False Positive

### **Alert 1002: Suspicious Process with an Uncommon Parent-Child Relationship**
- **Context:** A parent-child process relationship was flagged as unusual within the system.
- **Investigation Steps:**
  1. Retrieved details of the process, including ID, parent ID, command-line execution, and working directory.
  2. Used Splunk to search for historical data associated with Process ID `3897`.
  3. Filtered results to examine the process behavior over time.
- **Findings:**
  - The parent process was identified as a standard system process.
  - The working directory was within the core system folder (`System32`), suggesting normal behavior.
- **Incident Classification:** False Positive
- **Closure Rationale:** No anomalies detected in the process execution.

### **Alert 1003: Reply to Suspicious Email**
- **Investigation Steps:**
  1. Identified the sender and recipient domains.
  2. Verified that the recipient was a Yahoo email address, a known trusted provider.
  3. Confirmed no attachments were included in the email.
- **Findings:** The email did not contain malicious indicators.
- **Incident Classification:** False Positive

### **Alert 1004: Suspicious Attachment in an Email**
- **Context:** A file attachment was exchanged within the same organization.
- **Investigation Steps:**
  1. Opened the attachment (`forceupdate.ps1`) using an Analyst VM.
  2. Analyzed the script’s content using Notepad.
  3. Reviewed the script’s execution behavior.
- **Findings:** The script was performing system diagnostics, collecting basic information about the system and network.
- **Incident Classification:** False Positive
- **Closure Rationale:** The script was found to be a legitimate internal diagnostic tool.

### **Alert 1005: Reply to Suspicious Email**
- **Investigation Steps:**
  1. Verified that the recipient was a Gmail address.
  2. Confirmed that no attachments were included.
- **Findings:** No malicious indicators were present.
- **Incident Classification:** False Positive

### **Alert 1006: Suspicious Email from an External Domain**
- **Context:** The same domain from Alert 1001 triggered another alert.
- **Findings:** The domain was already analyzed and confirmed as non-malicious.
- **Incident Classification:** False Positive

### **Alert 1007: Suspicious Attachment in an Email**
- **Context:** An email from `hatmarkereurope.xyz` contained an attachment named `importantinvoice.zip`.
- **Investigation Steps:**
  1. Checked the domain using VirusTotal—some security vendors flagged it as slightly suspicious.
  2. Extracted the attachment and found a PDF file.
  3. Used PowerShell to generate SHA256 and MD5 hashes of the file.
  4. Cross-referenced the hashes with VirusTotal—no existing reports.
  5. Conducted further analysis using Splunk to track activities after the file was received.
  6. Discovered a PowerShell command executed shortly after the email was opened.
  7. Identified the command as an attempt to download `powercat.ps1`, a privilege escalation tool, from an external repository.
- **Findings:** The PowerShell script attempted to connect to a C2 (Command and Control) server.
- **Incident Classification:** True Positive
- **Closure Rationale:** Evidence confirmed malicious activity.
- **Final Action:** Escalated the alert for further action.

---

## **Tools and Technologies Used**
- **Virtual Machine (Analyst VM)**: Used for analyzing suspicious files in an isolated environment.
- **SIEM Tool (Splunk)**: Used for querying logs and correlating security events.
- **Online Sandbox (VirusTotal)**: Used to analyze domains, URLs, and file hashes.
- **PowerShell & Bash Scripting**: Used to generate hashes and perform system-level analysis.
