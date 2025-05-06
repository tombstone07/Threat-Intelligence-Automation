import os
import requests
import win32com.client as win32
from tqdm import tqdm
import datetime
import shutil

# === CONFIG ===
BLOCKLIST_URLS = {
    'firehol_level1': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    'abuse_threatfox': 'https://threatfox.abuse.ch/downloads/ipblocklist/',
}
BLOCKLIST_DIR = 'blocklists'
LAST_UPDATE_FILE = os.path.join(BLOCKLIST_DIR, 'last_update.txt')
ANALYZED_BASE_DIR = 'Analyzed'

# === Ensure blocklist directory exists ===
os.makedirs(BLOCKLIST_DIR, exist_ok=True)

# === Download blocklists ===
def download_blocklists():
    try:
        print("Checking if blocklists need updating...")
        today = datetime.date.today().isoformat()
        update_needed = True

        if os.path.exists(LAST_UPDATE_FILE):
            with open(LAST_UPDATE_FILE, 'r') as f:
                last_update = f.read().strip()
                if last_update == today:
                    update_needed = False

        if update_needed:
            print("Downloading latest blocklists...")
            for name, url in BLOCKLIST_URLS.items():
                response = requests.get(url, timeout=20)
                if response.status_code == 200:
                    path = os.path.join(BLOCKLIST_DIR, f'{name}.txt')
                    with open(path, 'w') as f:
                        f.write(response.text)
                    print(f"Downloaded {name}")
                else:
                    print(f"Failed to download {name}: {response.status_code}")
            with open(LAST_UPDATE_FILE, 'w') as f:
                f.write(today)
        else:
            print("Blocklists are already up to date today.")
    except Exception as e:
        print(f"Error downloading blocklists: {e}")

# === Load blocklists into memory ===
def load_blocklists():
    print("Loading blocklists into memory...")
    bad_ips = set()
    try:
        for filename in os.listdir(BLOCKLIST_DIR):
            if filename.endswith('.txt') and filename != 'last_update.txt':
                with open(os.path.join(BLOCKLIST_DIR, filename), 'r') as f:
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

    if not os.path.exists(ANALYZED_BASE_DIR):
        os.makedirs(analyzed_folder)
        print(f"Created new analyzed folder: {analyzed_folder}")
    else:
        if not os.path.exists(analyzed_folder):
            try:
                shutil.rmtree(ANALYZED_BASE_DIR)
                print(f"Deleted old analyzed folder: {ANALYZED_BASE_DIR}")
            except Exception as e:
                print(f"Error deleting old analyzed folder: {e}")
            os.makedirs(analyzed_folder)
            print(f"Created new analyzed folder: {analyzed_folder}")
        else:
            print(f"Today's analyzed folder already exists: {analyzed_folder}")
    return analyzed_folder

# === Scan workbook ===
def scan_workbook(bad_ips):
    from tkinter import Tk, filedialog, simpledialog

    root = Tk()
    root.withdraw()

    filepath = filedialog.askopenfilename(title="Select the Excel workbook", filetypes=[("Excel files", "*.xlsx;*.xlsm;*.xlsb;*.xls")])
    if not filepath:
        print("No file selected. Exiting.")
        return

    password = simpledialog.askstring("Password", "Enter the password for the workbook:", show='*')
    if password is None:
        print("No password entered. Exiting.")
        return

    analyzed_folder = prepare_analyzed_folder()
    filename = os.path.basename(filepath)
    save_path = os.path.join(analyzed_folder, filename)

    print(f"Opening workbook: {filepath}")
    try:
        excel = win32.gencache.EnsureDispatch('Excel.Application')
        excel.Visible = False

        workbook = excel.Workbooks.Open(
            os.path.abspath(filepath),
            Password=password
        )

        sheet = workbook.Sheets(1)
        used_range = sheet.UsedRange
        rows = used_range.Rows.Count
        cols = used_range.Columns.Count

        print(f"Scanning {rows} rows x {cols} columns...")

        for row in tqdm(range(1, rows + 1)):
            for col in range(1, cols + 1):
                cell = sheet.Cells(row, col)
                value = str(cell.Value) if cell.Value is not None else ''
                if value in bad_ips:
                    cell.Interior.Color = 65535  # Yellow highlight

        print(f"Saving analyzed workbook to {save_path}...")
        workbook.SaveAs(os.path.abspath(save_path), Password=password)
        workbook.Close()
        excel.Quit()
    except Exception as e:
        print(f"Error scanning workbook: {e}")

# === Main ===
if __name__ == '__main__':
    try:
        download_blocklists()
        bad_ips = load_blocklists()

        if not bad_ips:
            print("No bad IPs loaded. Exiting.")
        else:
            scan_workbook(bad_ips)
            print("Scan complete.")
    except Exception as e:
        print(f"Unexpected error: {e}")
