# **Threat Intelligence Automation - README**

## **1. Introduction**
This project is a **Python security analysis tool** designed to:  
✔️ Extract & analyze **PCAP network traffic** for suspicious activity.  
✔️ Detect potential **threats from logs** (e.g., malicious User-Agent strings, unusual IPs).  
✔️ Query **Threat Intelligence Feeds (AbuseIPDB, VirusTotal, AlienVault OTX)** to correlate security risks.  
✔️ Generate a **detailed security report (`threat_results.txt`)** for further investigation.

---

## **2. System Requirements**
This project runs on **Debian-based Linux** (e.g., Parrot OS, Kali Linux, Ubuntu).  

### **2.1 Required Tools**
Ensure you have the following installed:
- **Python 3.8+**
- **TShark** (Wireshark command-line tool)
- **Python Libraries** (`pyshark`, `requests`)

### **2.2 Installation**
#### **Step 1: Update Your System**
Before installing any packages, update your system:
```bash
sudo apt update && sudo apt upgrade -y

Step 2: Install TShark
bash
sudo apt install tshark -y


Step 3: Install Python Virtual Environment
bash
sudo apt install python3-venv -y


Step 4: Set Up Virtual Environment
bash
python3 -m venv my_env
source my_env/bin/activate


Step 5: Install Python Dependencies
bash
pip install pyshark requests
3. How to Run the Project


Step 1: Place the PCAP File
Ensure you have the PCAP file to analyze.
Rename it to sample.pcap (2022-MTA-workshop-exercise-5-of-5.pcap) in our case, or update the script with the correct filename.

Step 2: Run the Python Script
bash
python threat_analysis.py


Step 3: View the Results
The analysis is saved in a detailed text file:
bash
cat threat_results.txt



4. How the Project Works
The script performs the following tasks:

1️⃣ Extracts network metadata from the PCAP file:

Top Source & Destination IPs
Protocols used
2️⃣ Detects suspicious HTTP activity:

Unusual User-Agent strings
HTTP requests to suspicious domains
3️⃣ Performs Threat Intelligence Correlation:

Queries AbuseIPDB, VirusTotal, AlienVault OTX
Identifies high-risk IPs (Safe, Suspicious, Malicious)

4️⃣ Generates threat_results.txt with:
Detailed threat intelligence reports
A short-form summary for quick risk assessment


5. Sample Output (threat_results.txt)
yaml
### Threat Intelligence Analysis Report ###

[+] Top Source & Destination IPs:
10.5.31.139: 1774 occurrences
45.133.1.126: 475 occurrences
20.50.80.209: 61 occurrences

[+] Protocols Used:
TCP: 769 packets
SMB2: 180 packets
DNS: 74 packets

[+] Suspicious User-Agents Detected:
None detected.

[+] Unique HTTP Requests:
example.com
malicious-site.com

[+] Threat Intelligence Correlation:

[SUMMARY] IP: 45.133.1.126 - Risk Level: ⚠️ Malicious
AbuseIPDB: {"reported": true, "confidence_score": 85}
VirusTotal: {"malicious": true, "sources": ["Kaspersky", "CyRadar"]}
AlienVault OTX: {"found": true, "description": "Involved in malware attacks"}

[SUMMARY] IP: 20.50.80.209 - Risk Level: 🔶 Suspicious
AbuseIPDB: {"blacklist": true}
VirusTotal: {"malicious": false}
AlienVault OTX: {"found": false}

✅ Analysis Complete! Report saved to threat_results.txt



6. Troubleshooting
PCAP File Not Processing
✔️ Ensure TShark is installed:
bash
tshark -v

✔️ If pyshark fails, reinstall tshark:
bash
sudo apt install tshark -y

Permission Errors While Running Scripts
✔️ Run with sudo:
bash
sudo python threat_analysis.py

Virtual Environment Not Activating
✔️ Use:
bash
source my_env/bin/activate


How Often Should I Run This Analysis?
✔️ Weekly for continuous monitoring.
✔️ Update threat feeds before running:
bash
pip install --upgrade requests



7. Summary of Tasks
Task	Command
Analyze PCAP file	python threat_analysis.py
View Results	cat threat_results.txt
Check Installed Dependencies	pip list
Activate Virtual Environment	source my_env/bin/activate


8. Next Steps & Recommendations
✔️ Block malicious IPs identified in threat feeds.
✔️ Monitor network activity for unusual behavior.
✔️ Regularly update and re-run this analysis to stay ahead of threats.

9. Conclusion
This project provides a complete automated solution for PCAP traffic analysis and threat intelligence correlation.

By following this guide, all users can detect cyber threats, analyze network activity, and take preventive actions. 🚀


---

🚀 **Project is complete!** 😊


💯️@BUMI TECH@💯️


