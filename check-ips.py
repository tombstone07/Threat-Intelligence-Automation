import os
import datetime
import shutil
import win32com.client as win32
from tkinter import Tk, filedialog, simpledialog
import requests
from tqdm import tqdm

# === CONFIG ===
BLOCKLIST_URLS = {
    'firehol_level1': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    'abuse_threatfox': 'https://threatfox.abuse.ch/downloads/ipblocklist/',
}
BLOCKLIST_DIR = 'blocklists'
LAST_UPDATE_FILE = os.path.join(BLOCKLIST_DIR, 'last_update.txt')
ANALYZED_BASE_DIR = 'Analyzed'
SUSPICIOUS_KEYWORDS = [
    'MsSense.exe', 'winexesvc.exe', 'INVALID', 'SYSTEM', 'CDRB1',
    'Unauthorized', 'Malicious', 'infected', 'invisible host'
]

os.makedirs(BLOCKLIST_DIR, exist_ok=True)

# === Download blocklists ===
def download_blocklists():
    today = datetime.date.today().isoformat()
    update_needed = True

    if os.path.exists(LAST_UPDATE_FILE):
        with open(LAST_UPDATE_FILE, 'r') as f:
            if f.read().strip() == today:
                update_needed = False

    if update_needed:
        print("Downloading latest blocklists...")
        for name, url in BLOCKLIST_URLS.items():
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    with open(os.path.join(BLOCKLIST_DIR, f'{name}.txt'), 'w') as f:
                        f.write(response.text)
                    print(f"Downloaded {name}")
                else:
                    print(f"Failed to download {name}: {response.status_code}")
            except Exception as e:
                print(f"Error downloading {name}: {e}")
        with open(LAST_UPDATE_FILE, 'w') as f:
            f.write(today)
    else:
        print("Blocklists are already up to date.")

# === Load blocklists into memory ===
def load_blocklists():
    bad_ips = set()
    try:
        for file in os.listdir(BLOCKLIST_DIR):
            if file.endswith('.txt') and file != 'last_update.txt':
                with open(os.path.join(BLOCKLIST_DIR, file), 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            bad_ips.add(line)
        print(f"Loaded {len(bad_ips):,} unique bad IPs.")
    except Exception as e:
        print(f"Error loading blocklists: {e}")
    return bad_ips

# === Prepare analyzed folder ===
def prepare_analyzed_folder():
    today_str = datetime.date.today().isoformat()
    analyzed_folder = os.path.join(ANALYZED_BASE_DIR, today_str)
    os.makedirs(analyzed_folder, exist_ok=True)
    return analyzed_folder

# === Scan Excel Workbooks ===
def scan_excel_workbooks(bad_ips):
    root = Tk()
    root.withdraw()
    files = filedialog.askopenfilenames(
        title="Select Excel Workbooks", filetypes=[("Excel files", "*.xlsx")]
    )
    if not files:
        print("No files selected. Exiting.")
        return

    analyzed_folder = prepare_analyzed_folder()

    for file in files:
        print(f"\nProcessing workbook: {file}")
        password = simpledialog.askstring("Password", f"Enter password for:\n{os.path.basename(file)}", show='*')
        if password is None:
            print("No password provided. Skipping file.")
            continue

        try:
            excel = win32.gencache.EnsureDispatch('Excel.Application')
            excel.Visible = False
            wb = excel.Workbooks.Open(file, Password=password)

            flagged_cells = 0
            for sheet in wb.Sheets:
                if sheet.Name.strip().lower() == 'cover page':
                    continue

                used_range = sheet.UsedRange
                rows = used_range.Rows.Count
                cols = used_range.Columns.Count

                for row in tqdm(range(1, rows + 1), desc=f"Scanning {sheet.Name}"):
                    for col in range(1, cols + 1):
                        cell = sheet.Cells(row, col)
                        val = str(cell.Value).strip() if cell.Value else ''
                        if val in bad_ips or any(keyword.lower() in val.lower() for keyword in SUSPICIOUS_KEYWORDS):
                            cell.Interior.Color = 65535  # Yellow
                            flagged_cells += 1

            # Add recommendations
            try:
                cover_sheet = wb.Sheets('Cover Page')
                cover_sheet.Cells(30, 2).Value = (
                    f"Automated review completed on {datetime.date.today().isoformat()}.\n"
                    f"Total anomalies flagged: {flagged_cells:,}. Please review highlighted items in yellow."
                )
            except Exception as e:
                print(f"Could not write to Cover Page: {e}")

            # Save analyzed file
            save_path = os.path.join(analyzed_folder, os.path.basename(file))
            wb.SaveAs(save_path, Password=password)
            wb.Close(False)
            excel.Quit()
            print(f"Saved analyzed workbook to: {save_path}\n")
        except Exception as e:
            print(f"Error processing workbook: {e}")

# === MAIN ===
if __name__ == '__main__':
    try:
        download_blocklists()
        bad_ips = load_blocklists()
        if not bad_ips:
            print("No bad IPs loaded. Exiting.")
        else:
            scan_excel_workbooks(bad_ips)
    except Exception as e:
        print(f"Unexpected error: {e}")
