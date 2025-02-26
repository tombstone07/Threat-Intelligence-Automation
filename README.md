# **Threat Intelligence Analysis - Comprehensive Guide**

## **1. Introduction**
This project is designed to **analyze network traffic**, **detect cyber threats**, and **correlate findings with threat intelligence feeds** to identify malicious activity. It automates security monitoring using **PCAP file analysis** and public **Threat Intelligence APIs** (AbuseIPDB, VirusTotal, and AlienVault OTX).  

This guide provides **step-by-step instructions** for **both technical and non-technical users**.

---

## **2. Project Overview**
### **🎯 Objectives**
✔️ Extract **network metadata** from a captured **PCAP file**.  
✔️ Detect **suspicious activity** such as **malicious IPs, unusual protocols, and security threats**.  
✔️ Query **Threat Intelligence Feeds** to check if **any IP addresses are blacklisted**.  
✔️ Generate a **security report** with findings and recommendations.  

### **📝 Tasks Involved**
1. **PCAP File Analysis** – Extract source and destination IPs, protocols, and traffic patterns.  
2. **Threat Intelligence Correlation** – Compare extracted IPs with **global security databases**.  
3. **Security Report Generation** – Summarize findings and provide **recommendations** for risk mitigation.  

---

## **3. System Requirements**
- **Operating System**: Debian-based Linux (**Debian, Parrot OS, Kali Linux, Ubuntu**).  
- **Python Version**: Python 3.8+  
- **Required Tools**:  
  - `tshark` (Command-line tool for PCAP file analysis).  
  - `scapy`, `pyshark`, `requests`, and `pandas` Python libraries.  

---

## **4. Installation Instructions**
### **🔹 Step 1: Update the System**
Before installing any packages, update the system:
```bash
sudo apt update && sudo apt upgrade -y

