import pyshark
import requests
import os
import datetime
import hashlib
import time
from collections import Counter

# API Keys
ABUSE_IPDB_API_KEY = "88b1a25ba6764d18f88410d07fbc779da8b6e4a6db03dba3fefddf4121589d933df53403fa8f22fb"
VIRUSTOTAL_API_KEY = "1cbad388ce42d2edb9a99d63bb7e9b68f2d8f02239f140a619c54d1131e970e1"
ALIENVAULT_OTX_KEY = "0676c8ba1546668ef776943082675abb9c7f64a813ae45bba15f019f9865c9b3"

# Function to list PCAP files and allow selection by index
def select_pcap_file():
    files = [f for f in os.listdir() if f.endswith('.pcap')]
    if not files:
        print("No PCAP files found in the current directory.")
        exit()

    print("\nAvailable PCAP files:")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")

    while True:
        try:
            choice = int(input("\nSelect a PCAP file by entering its number: "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

# Function to analyze PCAP and extract network metadata
def analyze_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    src_ips, dst_ips, protocols = [], [], []

    for packet in cap:
        if "IP" in packet:
            src_ips.append(packet.ip.src)
            dst_ips.append(packet.ip.dst)
        if hasattr(packet, "highest_layer"):
            protocols.append(packet.highest_layer)

    cap.close()
    return Counter(src_ips + dst_ips), Counter(protocols)

# Function to extract files and check signatures
def extract_files_and_check_signatures(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="smb or ftp or http")
    file_hashes = {}

    for packet in cap:
        try:
            if hasattr(packet, "file_data"):
                file_data = packet.file_data.binary_value
                file_hash = hashlib.sha256(file_data).hexdigest()
                file_hashes[file_hash] = file_data[:20]  # Store first 20 bytes as sample
        except AttributeError:
            continue

    cap.close()

    # Check file hashes against VirusTotal
    file_results = {}
    for file_hash in file_hashes.keys():
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
            )
            if response.status_code == 200:
                data = response.json()
                malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                file_results[file_hash] = f"Malicious: {malicious_count} detections" if malicious_count > 0 else "Clean"
            else:
                file_results[file_hash] = f"Error {response.status_code}"
        except requests.RequestException as e:
            file_results[file_hash] = f"Request Failed: {e}"

    return file_results

# Function to check an IP against threat intelligence feeds
def check_threat_feeds(ip):
    results = {}

    # AbuseIPDB
    try:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": ABUSE_IPDB_API_KEY, "Accept": "application/json"},
        )
        if response.status_code == 200:
            data = response.json()
            results["AbuseIPDB"] = f"Confidence Score: {data['data']['abuseConfidenceScore']} | Reports: {data['data']['totalReports']}"
        else:
            results["AbuseIPDB"] = f"Error {response.status_code}"
    except requests.RequestException as e:
        results["AbuseIPDB"] = f"Request Failed: {e}"

    # VirusTotal
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
        )
        if response.status_code == 200:
            data = response.json()
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            results["VirusTotal"] = f"Malicious Engines: {malicious_count}" if malicious_count > 0 else "Clean"
        else:
            results["VirusTotal"] = f"Error {response.status_code}"
    except requests.RequestException as e:
        results["VirusTotal"] = f"Request Failed: {e}"

    # AlienVault OTX
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": ALIENVAULT_OTX_KEY},
        )
        if response.status_code == 200:
            data = response.json()
            pulse_count = len(data["pulse_info"]["pulses"])
            results["AlienVault OTX"] = f"Found in {pulse_count} threat pulses" if pulse_count > 0 else "Not Found"
        else:
            results["AlienVault OTX"] = f"Error {response.status_code}"
    except requests.RequestException as e:
        results["AlienVault OTX"] = f"Request Failed: {e}"

    time.sleep(1)  # Prevent API rate limit issues
    return results

# Function to generate security report
def generate_security_report(ip_counts, protocol_counts, threat_results, file_results):
    output_file = "security_report.md"
    with open(output_file, "w") as f:
        f.write("# **Security Report: Threat Intelligence & Network Analysis**\n\n")
        f.write("## **1. Network Findings**\n")

        f.write("### **Top 10 IPs**\n")
        for ip, count in ip_counts.most_common(10):
            f.write(f"- {ip}: {count} occurrences\n")
        f.write("\n")

        f.write("### **Protocols Observed**\n")
        for proto, count in protocol_counts.most_common():
            f.write(f"- {proto}: {count} packets\n")
        f.write("\n")

        f.write("## **2. Threat Intelligence Correlation**\n")
        for ip, details in threat_results.items():
            f.write(f"### 🚨 {ip}\n")
            for source, result in details.items():
                f.write(f"- **{source}**: {result}\n")
            f.write("\n")

        f.write("## **3. File & Signature Analysis**\n")
        if file_results:
            for file_hash, result in file_results.items():
                f.write(f"- **File Hash:** `{file_hash}` | **Result:** {result}\n")
        else:
            f.write("- No suspicious files detected.\n")
        
        # Automate Findings, Recommendations, and Conclusion
        f.write("\n## **4. Findings**\n")
        findings = []
        
        # Findings based on IP Threats
        for ip, details in threat_results.items():
            if "Malicious" in details.get("VirusTotal", ""):
                findings.append(f"**{ip}** is flagged as **Malicious** by VirusTotal.")
            elif "Found" in details.get("AlienVault OTX", ""):
                findings.append(f"**{ip}** is flagged in **AlienVault OTX**.")
        
        # Findings based on Protocols
        if protocol_counts.get("SMB2", 0) > 100:
            findings.append("High SMB2 traffic detected, indicating possible lateral movement.")
        if protocol_counts.get("DNS", 0) > 50:
            findings.append("Unusual DNS traffic detected, indicating possible data exfiltration.")
        
        if findings:
            for finding in findings:
                f.write(f"- {finding}\n")
        else:
            f.write("- No major threats detected in the traffic.\n")
        
        # Recommendations
        f.write("\n## **5. Recommendations**\n")
        f.write("✔️ **Block malicious IPs** at the firewall.\n")
        f.write("✔️ **Monitor DNS and SMB traffic** for unusual activity.\n")
        f.write("✔️ **Restrict SMB file-sharing protocols** to limit lateral movement.\n")
        
        # Conclusion
        f.write("\n## **6. Conclusion**\n")
        if findings:
            f.write("The analysis has identified **multiple potential threats** in the network traffic.\n")
            f.write("Immediate actions are recommended to mitigate these risks.\n")
        else:
            f.write("No significant threats were identified during the analysis.\n")
		
    print("✅ Security report (by Bumi Tech-Threat Intelligence Automation) saved as security_report.md")

# Main function
def main():
    pcap_file = select_pcap_file()
    ip_counts, protocol_counts = analyze_pcap(pcap_file)
    threat_results = {ip: check_threat_feeds(ip) for ip, _ in ip_counts.most_common(10)}
    file_results = extract_files_and_check_signatures(pcap_file)
    
    generate_security_report(ip_counts, protocol_counts, threat_results, file_results)

if __name__ == "__main__":
    main()

