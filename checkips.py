import openpyxl
from openpyxl.styles import PatternFill
import requests
import time
from tqdm import tqdm
import os
import msoffcrypto
import zipfile
import io

# === CONFIGURATION ===
API_KEY = "1cbad388ce42d2edb9a99d63bb7e9b68f2d8f02239f140a619c54d1131e970e1"

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

# Highlight style
highlight_fill = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")

# === FUNCTIONS ===

def select_workbook():
    files = [f for f in os.listdir() if f.endswith(".xlsx")]
    if not files:
        print("No Excel files found in this folder!")
        exit()

    print("\nAvailable Excel files:")
    for idx, file in enumerate(files, 1):
        print(f"{idx}. {file}")

    choice = int(input("\nEnter the number of the workbook you want to scan: "))
    selected_file = files[choice - 1]
    print(f"\n✅ Selected: {selected_file}\n")
    return selected_file

def prompt_for_password():
    return input("Please enter the password to decrypt the workbook: ")

def decrypt_workbook(filename, password):
    # Open the encrypted file with msoffcrypto
    with open(filename, "rb") as file:
        file_decrypted = msoffcrypto.OfficeFile(file)
        file_decrypted.load_key(password=password)
        
        # Decrypting and saving the workbook as a new file in memory
        decrypted_file = "decrypted_workbook.xlsx"
        with open(decrypted_file, "wb") as decrypted:
            file_decrypted.decrypt(decrypted)
    
    return decrypted_file

def check_ip_virustotal(ip):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(VT_URL + ip, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']

        total_reports = sum(stats.values())
        malicious = stats.get('malicious', 0)
        
        if total_reports == 0:
            return False  # avoid division by zero

        malicious_ratio = (malicious / total_reports) * 100

        if malicious > 30 and malicious_ratio > 50:
            return True
        else:
            return False
    else:
        print(f"Failed to fetch {ip}: Status {response.status_code}")
        return False

def is_valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def encrypt_workbook_with_password(input_filename, output_filename, password):
    # Zip the decrypted file, and then add password protection to it
    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(input_filename):
            for file in files:
                zipf.write(os.path.join(root, file), arcname=file)
    # Encrypt the workbook after modification
    msoffcrypto.encrypt_file(input_filename, output_filename, password)

# === MAIN ===

def main():
    workbook_name = select_workbook()

    # Prompt for the password to decrypt the workbook
    password = prompt_for_password()

    # Decrypt workbook first using msoffcrypto
    decrypted_file = decrypt_workbook(workbook_name, password)

    # Load the decrypted workbook with openpyxl
    wb = openpyxl.load_workbook(decrypted_file, read_only=False, keep_vba=False, data_only=True)

    all_ips = []

    # Collect all IPs from all sheets
    for sheetname in wb.sheetnames:
        ws = wb[sheetname]
        for row in ws.iter_rows():
            for cell in row:
                if cell.value and isinstance(cell.value, str):
                    value = cell.value.strip()
                    if is_valid_ip(value):
                        all_ips.append((ws, cell))

    print(f"Found {len(all_ips)} IPs to check.")

    # Progress bar
    for ws, cell in tqdm(all_ips, desc="Checking IPs"):
        ip = cell.value.strip()
        if check_ip_virustotal(ip):
            cell.fill = highlight_fill
        time.sleep(15)  # to respect free API tier

    # Build new filename
    base_name = os.path.splitext(workbook_name)[0]
    new_filename = f"{base_name}_highlighted.xlsx"

    wb.save(new_filename)

    # Reapply password protection
    encrypt_workbook_with_password(new_filename, new_filename, password)

    # Clean up temporary files
    os.remove("decrypted_workbook.xlsx")

    print(f"\n✅ Finished! Saved highlighted workbook as: {new_filename}")

if __name__ == "__main__":
    main()
