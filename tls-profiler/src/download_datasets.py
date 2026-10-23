import sys
import os
import urllib.request
import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from src.config import DATASET_DIR, SSLBL_JA3_CSV
except ModuleNotFoundError:
    from config import DATASET_DIR, SSLBL_JA3_CSV

SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

def download_ja3_blacklist(output_path=SSLBL_JA3_CSV):
    """
    Downloads the live abuse.ch SSLBL JA3 fingerprint blacklist CSV (< 5 MB).
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    print(f"[*] Downloading abuse.ch SSLBL JA3 Fingerprint Blacklist from: {SSLBL_JA3_URL}...")
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req = urllib.request.Request(SSLBL_JA3_URL, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response, open(output_path, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
            print(f"[+] Download complete: {output_path} ({len(data) / 1024:.2f} KB)")
            
        df = pd.read_csv(output_path, comment='#', names=["ja3_md5", "first_seen", "last_seen", "threat"], on_bad_lines='skip')
        print(f"[+] Loaded {len(df)} malicious JA3 fingerprints from abuse.ch SSLBL feed.")
        return df
    except Exception as e:
        print(f"[!] Warning: Could not download live SSLBL feed ({e}). Will proceed with offline fallback rules.")
        return pd.DataFrame(columns=["ja3_md5", "first_seen", "last_seen", "threat"])

if __name__ == "__main__":
    download_ja3_blacklist()
