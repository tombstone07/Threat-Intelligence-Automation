import pyshark
import requests
from collections import Counter

# API Keys (Updated as provided)
ABUSE_IPDB_API_KEY = "88b1a25ba6764d18f88410d07fbc779da8b6e4a6db03dba3fefddf4121589d933df53403fa8f22fb"
VIRUSTOTAL_API_KEY = "1cbad388ce42d2edb9a99d63bb7e9b68f2d8f02239f140a619c54d1131e970e1"
ALIENVAULT_OTX_KEY = "0676c8ba1546668ef776943082675abb9c7f64a813ae45bba15f019f9865c9b3"

# Choose PCAP file name
PCAP_FILE = "2022-MTA-workshop-exercise-5-of-5.pcap"  # Change this to any PCAP file in the folder

# Output file for results
OUTPUT_FILE = "threat_results.txt"

# Function to analyze PCAP file
def analyze_pcap(pcap_file):
    print("🔍 Extracting network metadata from PCAP file...")
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

# Function to detect suspicious HTTP traffic
def detect_suspicious_http(pcap_file):
    print("🚨 Detecting suspicious HTTP requests...")
    cap = pyshark.FileCapture(pcap_file, display_filter="http")

    suspicious_agents, http_requests = [], []
    for packet in cap:
        try:
            if hasattr(packet.http, "user_agent"):
                user_agent = packet.http.user_agent
                http_requests.append(packet.http.host)
                if "curl" in user_agent.lower() or "wget" in user_agent.lower():
                    suspicious_agents.append(user_agent)
        except AttributeError:
            continue

    cap.close()
    return suspicious_agents, set(http_requests)

# Function to check Threat Intelligence Feeds
def check_threat_feeds(ip):
    print(f"🔗 Checking {ip} in Threat Intelligence Feeds...")
    urls = {
        "AbuseIPDB": f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
        "VirusTotal": f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        "AlienVault OTX": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    }
    headers = {
        "AbuseIPDB": {"Key": ABUSE_IPDB_API_KEY, "Accept": "application/json"},
        "VirusTotal": {"x-apikey": VIRUSTOTAL_API_KEY},
        "AlienVault OTX": {"X-OTX-API-KEY": ALIENVAULT_OTX_KEY}
    }
    
    results = {}
    for name, url in urls.items():
        try:
            response = requests.get(url, headers=headers.get(name, {}))
            if response.status_code == 200:
                results[name] = response.json()
            else:
                results[name] = f"Error {response.status_code}"
        except Exception as e:
            results[name] = f"Error: {str(e)}"
    
    return results

# Function to generate a short-form interpretation of threat intelligence results
def interpret_threat_results(results):
    # Default risk level
    risk_level = "Safe"
    
    # Check indicators
    if "malicious" in str(results).lower() or "blacklist" in str(results).lower():
        risk_level = "⚠️ Malicious"
    elif "suspicious" in str(results).lower() or "found in threat" in str(results).lower():
        risk_level = "🔶 Suspicious"
    
    return risk_level

# Main execution function
def main():
    # Open output file to save results
    with open(OUTPUT_FILE, "w") as f:
        f.write("### Threat Intelligence Analysis Report ###\n\n")

        # Step 1: Analyze PCAP file
        ip_counts, protocol_counts = analyze_pcap(PCAP_FILE)
        f.write("[+] Top Source & Destination IPs:\n")
        for ip, count in ip_counts.most_common(10):
            f.write(f"{ip}: {count} occurrences\n")

        f.write("\n[+] Protocols Used:\n")
        for proto, count in protocol_counts.most_common():
            f.write(f"{proto}: {count} packets\n")

        # Step 2: Detect Suspicious HTTP Activity
        suspicious_agents, http_requests = detect_suspicious_http(PCAP_FILE)
        f.write("\n[+] Suspicious User-Agents Detected:\n")
        f.write("\n".join(suspicious_agents) + "\n" if suspicious_agents else "None detected.\n")

        f.write("\n[+] Unique HTTP Requests:\n")
        f.write("\n".join(http_requests) + "\n" if http_requests else "None detected.\n")

        # Step 3: Threat Intelligence Correlation
        f.write("\n[+] Threat Intelligence Correlation:\n")
        for ip, count in ip_counts.most_common(5):  # Check top 5 IPs
            results = check_threat_feeds(ip)
            risk_rating = interpret_threat_results(results)

            # Short-form summary (for easy interpretation)
            f.write(f"\n[SUMMARY] IP: {ip} - Risk Level: {risk_rating}\n")

            # Full detailed threat intelligence results
            f.write(f"AbuseIPDB: {results.get('AbuseIPDB', 'No Data')}\n")
            f.write(f"VirusTotal: {results.get('VirusTotal', 'No Data')}\n")
            f.write(f"AlienVault OTX: {results.get('AlienVault OTX', 'No Data')}\n")

        f.write("\n✅ Analysis Complete! Report saved to threat_results.txt\n")

# Run the script
if __name__ == "__main__":
    main()

