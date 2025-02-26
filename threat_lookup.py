import requests

# Add your API keys here
ABUSE_IPDB_API_KEY = "88b1a25ba6764d18f88410d07fbc779da8b6e4a6db03dba3fefddf4121589d933df53403fa8f22fb"
VIRUSTOTAL_API_KEY = "1cbad388ce42d2edb9a99d63bb7e9b68f2d8f02239f140a619c54d1131e970e1"
ALIENVAULT_OTX_KEY = "0676c8ba1546668ef776943082675abb9c7f64a813ae45bba15f019f9865c9b3"

# List of top IPs extracted from the PCAP file
suspicious_ips = [
    "10.5.31.139", "10.5.31.5", "45.133.1.126", "204.79.197.200",
    "20.50.80.209", "40.90.64.61", "10.5.31.255", "20.189.173.10",
    "204.79.197.203", "40.83.240.146"
]

# Function to check IP in AbuseIPDB
def check_abuse_ipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSE_IPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to check IP in VirusTotal
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to check IP in AlienVault OTX
def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_OTX_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

# Check top suspicious IPs
for ip in suspicious_ips:
    print(f"\nChecking {ip} in threat feeds...")
    print("AbuseIPDB:", check_abuse_ipdb(ip))
    print("VirusTotal:", check_virustotal(ip))
    print("AlienVault OTX:", check_alienvault(ip))

