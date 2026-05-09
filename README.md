# Detection Query Builder

A multi-SIEM detection engineering tool for generating production-ready security detection queries across:

- Splunk SPL
- Microsoft Sentinel (KQL)
- Wazuh (SIEM/Elastic-based detection queries)

---

##  Overview

This tool helps SOC analysts and detection engineers quickly generate standardized queries for common cybersecurity detection use cases.

It supports dynamic parameter input and outputs ready-to-use queries for multiple security platforms.

---

## ⚙️Features

- Multi-SIEM query generation (Splunk, KQL, Wazuh)
- Pre-built detection templates
- Dynamic field customization
- Copy-to-clipboard functionality
- Lightweight React-based UI
- Offline-compatible (no external dependencies)

---

##  Supported Detection Use Cases

### 1. Authentication Attacks
- Brute force authentication detection
- Failed login spike analysis
- Password spraying patterns

### 2. Privilege Escalation
- Admin role assignment detection
- Suspicious privilege changes

### 3. Endpoint Attacks
- Lateral movement detection
- Suspicious process injection
- PowerShell exploitation patterns

### 4. Network Attacks
- DNS data exfiltration detection

### 5. Email Security
- Phishing email indicators

---

##  Query Outputs

Each detection generates:

- **Splunk SPL Query**
- **Microsoft KQL Query**
- **Wazuh Query**

---

## 🖥️Tech Stack

- React (Vite)
- JavaScript (ES6+)
- Inline CSS styling
- Native browser APIs

---


##  How to Run

```bash
npm install
npm run dev

```bash
http://localhost:5173


## LIVE DEMO

https://abodovic2012.github.io/detection-query-builder/


##💻 Author

MSc Eng Abdul Rahman Hawa

please feel free to suggest any modification or asking for new tools for Cybersecurity
