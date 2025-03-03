# **Threat Intelligence & PCAP Analysis Automation**  

## **1. Introduction**  
This project automates **PCAP file analysis, threat intelligence correlation, and file signature checking** to detect potential security threats in network traffic. The final report provides **detailed findings and recommendations** for improving security posture.  

---

## **2. System Requirements**  
### **Supported OS:**  
- **Debian-based Linux** (Parrot OS, Kali Linux, Ubuntu)  

### **Required Dependencies:**  
- **Python 3.8+**  
- **TShark (Wireshark CLI)**  
- **Python Libraries:** `pyshark`, `requests`  

---

## **3. Installation & Setup**  

### **Step 1: Update System**  
```bash
`sudo apt update && sudo apt upgrade -y`

### **Step 2: Install TShark**
```bash
`sudo apt install tshark -y`

### **Step 3: Set Up Python Virtual Environment**
```bash
'sudo apt install python3-venv -y 
python3 -m venv my_env  
source my_env/bin/activate'
 
### **Step 4: Install Required Python Libraries**
```bash
'pip install --break-system-packages pyshark requests'


## **4. How to Run the Project**
### **Step 1: Place PCAP Files in the Directory**
Ensure your .pcap files are stored in the working directory.

### **Step 2: Execute the Python Script**
```bash
`python threat_analysis.py`
The script will list all available PCAP files in the folder.
Select a file by entering the corresponding index number.

### **Step 3: View the Generated Security Report**
```bash
'cat security_report.md'


## **5. How the Analysis Works**
**1️⃣ Extracts Network Metadata from PCAP
Top Source & Destination IPs
Protocols Used in Network Traffic
2️⃣ Detects Suspicious HTTP Activity
Extracts User-Agent Strings
Identifies Unusual HTTP Requests
3️⃣ Correlates with Threat Intelligence Feeds
Queries AbuseIPDB, VirusTotal, and AlienVault OTX
Identifies blacklisted & malicious IPs
4️⃣ Extracts Files & Performs File Signature Checks
Identifies transferred files via SMB, FTP, HTTP
Computes SHA256 hashes and checks against VirusTotal
5️⃣ Generates ('security_report.md')
Includes all findings, threat intelligence results, and recommendations.**


6. Sample Output (security_report.md)
markdown
Copy
Edit
# **Security Report: Threat Intelligence & Network Analysis**  

## **1. Network Findings**  
### **Top 10 Source & Destination IPs**  
- 10.5.31.139: 1774 occurrences  
- 45.133.1.126: 475 occurrences  
- 20.50.80.209: 61 occurrences  

### **Protocols Observed**  
- TCP: 769 packets  
- SMB2: 180 packets  
- DNS: 74 packets  

---

## **2. Threat Intelligence Correlation**  
| IP Address       | AbuseIPDB | VirusTotal            | AlienVault OTX         | Risk Level |
|-----------------|-----------|----------------------|------------------------|------------|
| **45.133.1.126** | Confidence Score: 0 | **Malicious Engines: 5** | **Found in 29 threat pulses** | **High-Risk** |
| **204.79.197.200** | Confidence Score: 0 | Clean | **Found in 50 threat pulses** | **Medium** |
| **20.50.80.209** | Confidence Score: 0 | Clean | **Found in 7 threat pulses** | **Suspicious** |
| **40.83.240.146** | Confidence Score: 8 | Clean | **Found in 5 threat pulses** | **Requires Further Analysis** |

---

## **3. File & Signature Analysis**  
| File Hash (SHA256) | VirusTotal Analysis |  
|---------------------|---------------------|  
| **No suspicious files detected** | — |  

---

## **4. Security Recommendations**  
✔️ **Block the following high-risk IPs** at the firewall:  
   - `45.133.1.126`  
   - `204.79.197.200`  
   - `20.50.80.209`  
✔️ **Monitor DNS traffic** for anomalies (possible DNS tunneling).  
✔️ **Restrict SMB file sharing** to prevent lateral movement.  
✔️ **Deploy endpoint security solutions** to prevent malware execution.  
✔️ **Update threat intelligence feeds regularly** to stay ahead of new threats.  

---

## **5. Conclusion**  
✔️ This project successfully **automates cybersecurity threat detection**.  
✔️ **Threat intelligence correlation** identified **malicious and suspicious IPs**.  
✔️ **The final security report** provides **detailed analysis & actionable recommendations**.  
✔️ The tool can be used in **incident response, forensic investigations, and proactive security monitoring**.  

---

## **7. Troubleshooting**  

### **PCAP File Not Processing**  
✔️ Ensure **TShark is installed**:  
```bash
tshark -v
✔️ If pyshark fails, reinstall TShark:

bash
Copy
Edit
sudo apt install tshark -y
Permission Errors While Running Scripts
✔️ Run with sudo if needed:

bash
Copy
Edit
sudo python threat_analysis.py
Virtual Environment Not Activating
✔️ Use:

bash
Copy
Edit
source my_env/bin/activate
8. Summary of Commands
Task	Command
Run the script	python threat_analysis.py
View results	cat security_report.md
Check installed dependencies	pip list
Activate virtual environment	source my_env/bin/activate
9. Next Steps & Recommendations
✔️ Block malicious IPs identified in threat feeds
✔️ Monitor network activity for unusual behavior
✔️ Regularly update threat feeds & re-run analysis

10. Conclusion
This project provides a fully automated cybersecurity tool for PCAP traffic analysis, threat intelligence correlation, and file signature verification.

🚀 By following this guide, users can detect cyber threats, analyze network activity, and take proactive security measures.

💯 @BUMI TECH 💯
