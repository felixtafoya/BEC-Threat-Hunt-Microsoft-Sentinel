<p align="center">
  <img src="PUT-YOUR-COVER-IMAGE-HERE" width="1200" alt="Threat Hunt Cover"/>
</p>

# 🛡️ Threat Hunt Report – Business Email Compromise (BEC)

---

## 📌 Executive Summary

On February 25, 2026, a Business Email Compromise (BEC) attack was identified within a Microsoft 365 environment. The attacker leveraged credentials obtained via infostealer malware and successfully authenticated using MFA fatigue techniques.

Following access, the attacker established persistence through malicious inbox rules, accessed cloud storage systems, and executed a fraudulent email attack targeting financial personnel.

---

## 🎯 Hunt Objectives

- Identify attacker entry point  
- Track attacker activity across cloud services  
- Detect persistence mechanisms  
- Map behavior to MITRE ATT&CK  
- Identify detection gaps  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft 365 / Azure AD  
- **Data Sources:** SigninLogs, CloudAppEvents, EmailEvents  
- **Timeframe:** 2026-02-25 21:59 → 22:12 UTC  

---

## ⏱️ Attack Timeline

| Time (UTC) | Event |
|-----------|------|
| 21:59 | Initial attacker login from 205.147.16.190 |
| 22:00 | MFA fatigue attempts begin |
| 22:02 | Successful authentication |
| 22:02 | Malicious inbox rules created |
| 22:07 | OneDrive accessed |
| 22:09 | SharePoint accessed |
| 22:12 | BEC email sent |

---

## 🧠 Hunt Overview

1. Credentials stolen via infostealer malware  
2. Successful login from suspicious IP  
3. MFA fatigue used to gain access  
4. Inbox rules created for persistence  
5. OneDrive accessed  
6. SharePoint accessed  
7. BEC email sent  

---

## 🧬 MITRE ATT&CK Summary

| Technique | MITRE ID |
|----------|---------|
| Valid Accounts | T1078 |
| MFA Fatigue | T1621 |
| Account Manipulation | T1098 |
| Email Rule Evasion | T1564.008 |

---

## 🔍 Flag Analysis

---

<details>
<summary>🚩 Flag 1 – Initial Access (Infostealer)</summary>

### 📌 Finding
Successful login from attacker IP

| Field | Value |
|------|------|
| Time | 2026-02-25 21:59 UTC |
| IP | 205.147.16.190 |

### 🧪 KQL Query
SigninLogs  
| where IPAddress == "205.147.16.190"  
| where ResultType == 0  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-SIGNIN-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 2 – MFA Fatigue</summary>

### 📌 Finding
Multiple MFA attempts until approval

| Field | Value |
|------|------|
| Time | 2026-02-25 22:00 – 22:02 UTC |

### 🧪 KQL Query
SigninLogs  
| where IPAddress == "205.147.16.190"  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-MFA-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 3 – Inbox Rule Persistence</summary>

### 📌 Finding
Malicious inbox rules created

| Field | Value |
|------|------|
| Time | 2026-02-25 22:02 UTC |
| Forward | insights@duck.com |

### 🧪 KQL Query
CloudAppEvents  
| where ActionType == "New-InboxRule"  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-INBOX-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 4 – OneDrive Access</summary>

### 📌 Finding
FileAccessed activity detected

| Field | Value |
|------|------|
| Time | 2026-02-25 22:07 UTC |

### 🧪 KQL Query
CloudAppEvents  
| where ActionType == "FileAccessed"  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-ONEDRIVE-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 5 – SharePoint Access</summary>

### 📌 Finding
SharePoint accessed

| Field | Value |
|------|------|
| Time | 2026-02-25 22:09 UTC |

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-SHAREPOINT-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 6 – BEC Email Sent</summary>

### 📌 Finding
Fraudulent invoice email sent

| Field | Value |
|------|------|
| Time | 2026-02-25 22:12 UTC |

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-BEC-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 7 – Session Correlation</summary>

### 📌 Finding
Single session used across activity

### 🧪 KQL Query
CloudAppEvents  
| extend Session = extract("AADSessionId\":\"([^\"]+)", 1, tostring(RawEventData))  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-SESSION-SCREENSHOT" width="900"/>
</p>

</details>

---

<details>
<summary>🚩 Flag 8 – Conditional Access Failure</summary>

### 📌 Finding
Conditional Access not applied

| Field | Value |
|------|------|
| Status | notApplied |

### 🧪 KQL Query
SigninLogs  
| project ConditionalAccessStatus  

### 🖼️ Screenshot
<p align="center">
  <img src="PASTE-CA-SCREENSHOT" width="900"/>
</p>

</details>

---

## 🚨 Detection Gaps & Recommendations

### Gaps
- No Conditional Access enforcement  
- No MFA fatigue detection  
- No inbox rule monitoring  

### Recommendations
- Enforce Conditional Access  
- Enable MFA number matching  
- Monitor inbox rules  
- Alert on suspicious login behavior  

---

## 🧠 Key Takeaways

- MFA fatigue is a common and effective attack technique  
- Conditional Access is critical for identity protection  
- Inbox rules are frequently used for persistence in BEC attacks  
- Cloud services are often targeted after initial compromise  

---

## 🧾 Final Assessment

This attack demonstrates a full identity-based compromise leveraging credential theft, MFA fatigue, and cloud persistence.

---

## 📎 Analyst Notes

- Investigation performed in Microsoft Sentinel  
- MITRE ATT&CK mapping applied  
- Portfolio-ready report  
