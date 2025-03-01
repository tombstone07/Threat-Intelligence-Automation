# **Security Report: Threat Intelligence & Network Analysis**

## **1. Network Findings**
### **Top 10 IPs**
- 10.5.31.139: 1774 occurrences
- 10.5.31.5: 925 occurrences
- 45.133.1.126: 475 occurrences
- 204.79.197.200: 84 occurrences
- 20.50.80.209: 61 occurrences
- 40.90.64.61: 31 occurrences
- 10.5.31.255: 30 occurrences
- 20.189.173.10: 29 occurrences
- 204.79.197.203: 24 occurrences
- 40.83.240.146: 24 occurrences

### **Protocols Observed**
- TCP: 769 packets
- DATA: 285 packets
- SMB2: 180 packets
- TLS: 129 packets
- DNS: 74 packets
- LDAP: 53 packets
- KERBEROS: 44 packets
- NBNS: 36 packets
- DRSUAPI: 36 packets
- SAMR: 30 packets
- DCERPC: 28 packets
- SMB: 26 packets
- CLDAP: 18 packets
- EPM: 12 packets
- IGMP: 11 packets
- RPC_NETLOGON: 8 packets
- LANMAN: 8 packets
- MDNS: 7 packets
- BROWSER: 7 packets
- LLMNR: 5 packets
- DHCP: 4 packets
- NBSS: 4 packets
- NTP: 2 packets

## **2. Threat Intelligence Correlation**
### 🚨 10.5.31.139
- **AbuseIPDB**: Confidence Score: 0 | Reports: 0
- **VirusTotal**: Clean
- **AlienVault OTX**: Error 400

### 🚨 10.5.31.5
- **AbuseIPDB**: Confidence Score: 0 | Reports: 0
- **VirusTotal**: Clean
- **AlienVault OTX**: Error 400

### 🚨 45.133.1.126
- **AbuseIPDB**: Confidence Score: 0 | Reports: 0
- **VirusTotal**: Malicious Engines: 5
- **AlienVault OTX**: Found in 29 threat pulses

### 🚨 204.79.197.200
- **AbuseIPDB**: Confidence Score: 0 | Reports: 1
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 50 threat pulses

### 🚨 20.50.80.209
- **AbuseIPDB**: Confidence Score: 0 | Reports: 2
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 7 threat pulses

### 🚨 40.90.64.61
- **AbuseIPDB**: Confidence Score: 0 | Reports: 0
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 5 threat pulses

### 🚨 10.5.31.255
- **AbuseIPDB**: Confidence Score: 0 | Reports: 0
- **VirusTotal**: Clean
- **AlienVault OTX**: Error 400

### 🚨 20.189.173.10
- **AbuseIPDB**: Confidence Score: 0 | Reports: 1
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 16 threat pulses

### 🚨 204.79.197.203
- **AbuseIPDB**: Confidence Score: 0 | Reports: 3
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 50 threat pulses

### 🚨 40.83.240.146
- **AbuseIPDB**: Confidence Score: 8 | Reports: 2
- **VirusTotal**: Clean
- **AlienVault OTX**: Found in 5 threat pulses

## **3. File & Signature Analysis**
- No suspicious files detected.

## **4. Findings**
- **45.133.1.126** is flagged as **Malicious** by VirusTotal.
- **204.79.197.200** is flagged in **AlienVault OTX**.
- **20.50.80.209** is flagged in **AlienVault OTX**.
- **40.90.64.61** is flagged in **AlienVault OTX**.
- **20.189.173.10** is flagged in **AlienVault OTX**.
- **204.79.197.203** is flagged in **AlienVault OTX**.
- **40.83.240.146** is flagged in **AlienVault OTX**.
- High SMB2 traffic detected, indicating possible lateral movement.
- Unusual DNS traffic detected, indicating possible data exfiltration.

## **5. Recommendations**
✔️ **Block malicious IPs** at the firewall.
✔️ **Monitor DNS and SMB traffic** for unusual activity.
✔️ **Restrict SMB file-sharing protocols** to limit lateral movement.

## **6. Conclusion**
The analysis has identified **multiple potential threats** in the network traffic.
Immediate actions are recommended to mitigate these risks.
