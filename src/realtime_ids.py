import json
import os
import pickle
import subprocess
import time
import urllib.parse
import warnings
from pathlib import Path

from dotenv import load_dotenv

warnings.filterwarnings("ignore")

# ================== PATH ==================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "model" / "sqli_model.pkl"

# ================== ENVIRONMENT ==================

load_dotenv(BASE_DIR / ".env")

PFSENSE_IP = os.getenv("PFSENSE_IP")
PFSENSE_USER = os.getenv("PFSENSE_USER", "admin")
INTERFACE = os.getenv("PFSENSE_INTERFACE", "lan")

EVE_LOG = os.getenv(
    "EVE_LOG_PATH",
    str(BASE_DIR / "logs" / "eve.json")
)

# ================== VALIDATE CONFIG ==================

if not PFSENSE_IP:
    print("Loi: Chua cau hinh PFSENSE_IP trong file .env")
    exit(1)
# ================== START ==================

print("1. Dang khoi dong He Thong IPS AI Thoi Gian Thuc...")
# ================== LOAD AI MODEL ==================

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print(">> AI Model da load thanh cong!")

except FileNotFoundError:
    print(f"Loi: Khong tim thay model: {MODEL_PATH}")
    exit(1)


# ================== BLOCKED IP ==================

blocked_ips = set()


# ================== BLOCK FUNCTION ==================

def block_attacker(ip):
    if ip in blocked_ips or ip == "Unknown":
        return

    print(f"[*] IPS dang chan IP: {ip} ...")

    ssh_cmd = [
        "ssh",
        f"{PFSENSE_USER}@{PFSENSE_IP}",
        f"easyrule block {INTERFACE} {ip} && pfctl -k {ip}"
    ]

    try:
        subprocess.run(ssh_cmd, check=True)

        print(f"[+] DA CHAN THANH CONG: {ip}\n")

        blocked_ips.add(ip)

    except subprocess.CalledProcessError as e:
        print(f"[-] Loi chan IP {ip}: {e}\n")


# ================== MONITOR LOG ==================

print(f"2. Dang lang nghe log: {EVE_LOG}...")
print("====================================================")
print(" HE THONG IPS DANG HOAT DONG (AI + pfSense)")
print("====================================================\n")

try:

    with open(EVE_LOG, "r") as f:

        # Bat dau doc tu cuoi file
        f.seek(0, 2)

        while True:

            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:

                event = json.loads(line)

                if event.get("event_type") != "http":
                    continue

                http_data = event.get("http", {})

                url = http_data.get("url", "")

                src_ip = event.get("src_ip", "Unknown")

                if not url:
                    continue

                # Decode URL
                url_decoded = urllib.parse.unquote(url)

                # AI prediction
                prediction = model

                if prediction == 1:

                    print("\n[!!! SQLi DETECTED !!!]")
                    print(f"IP: {src_ip}")
                    print(f"Payload: {url_decoded}")

                    # Block attacker
                    block_attacker(src_ip)

            except json.JSONDecodeError:
                continue

except FileNotFoundError:

    print(f"Loi: Khong tim thay file log: {EVE_LOG}")

except KeyboardInterrupt:

    print("\n[+] Da dung he thong IPS AI.")
