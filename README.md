# RedTeamC2 — Snake Eyes C2 Framework

A red team Command & Control (C2) framework that operates over HTTPS (port 443). A Flask-based backend server exposes a web dashboard for issuing commands to agents. Traffic is routed through a network of 10 Nginx reverse-proxy relays, providing operational security through domain-fronting and failover. All agent-to-server communications are encrypted end-to-end with Fernet (AES-128-CBC + HMAC-SHA256). The full infrastructure is deployed and configured via an Ansible playbook.

> **Note:** All production code lives in `c2-setup-ansible/files/`. The `HTTPS C2 (Windows)/` folder contains an earlier, standalone prototype.

---

## Architecture

```
  [ Operator Dashboard ]
         |
    [ server.py ]  ← Flask C2 backend (port 5000, internal)
         ↑
  ×10 [ Nginx Relay ]  ← HTTPS reverse proxies (port 443, public)
         ↑
   [ agent.py ]  ← Deployed on target hosts (Linux + Windows)
```

- **Backend (`snake_server`)** — Flask application (`server.py`) + web dashboard (`index.html`). Stores agent registrations, issued tasks, and command output in a SQLite database (`c2.db`). Runs as a systemd service on the operator's Kali machine.
- **Relays (`snake_relay`)** — 10 Nginx reverse proxies, each behind a separate domain name, that terminate TLS and forward all traffic to the backend's internal IP. Provide domain failover and obscure the true backend address.
- **Agents (`snake_agent`)** — Lightweight Python beacons (`agent.py`) deployed to target machines. On check-in, each agent encrypts system metadata and sends a heartbeat; it then receives and executes any queued command, returning encrypted output. Agents iterate through the full relay domain list on failure for resilience.

### Agent Persistence

| Platform | Mechanism | Installed Path |
|---|---|---|
| Linux | systemd service (`network-check.service`) | `/etc/qemu/system-check.py` |
| Windows | Scheduled Task (`WindowsSystemUpdate`, trigger: boot, user: SYSTEM) | `C:\ProgramData\Microsoft\Network\Settings\win-update-check.py` |

---

## Repository Structure

```
RedTeamC2/
├── c2-setup-ansible/          # Primary deployment (Ansible)
│   ├── deploy.yml             # Main playbook
│   ├── inventory.ini          # Target hosts (backend, relays, agents)
│   ├── ansible.cfg            # Ansible configuration
│   ├── files/                 # Deployable source code
│   │   ├── server.py          # Flask C2 server + API
│   │   ├── agent.py           # Agent beacon
│   │   └── index.html         # Operator dashboard UI
│   ├── group_vars/
│   │   ├── all.yml            # Shared vars (relay IPs/domains, credentials, paths)
│   │   ├── relays.yml         # Relay-specific vars
│   │   └── agents.yml         # Agent-specific vars
│   └── roles/
│       ├── common_net/        # Hosts-file provisioning (all hosts)
│       ├── snake_server/      # C2 backend deployment
│       ├── snake_relay/       # Nginx relay configuration
│       └── snake_agent/       # Agent drop + persistence
└── HTTPS C2 (Windows)/        # Standalone prototype (single relay)
    ├── server.py
    ├── agent.py
    └── index.html
```

---

## Prerequisites

**Control machine (Ansible controller):**
- Ansible ≥ 2.12
- `community.windows` and `ansible.windows` Ansible collections
- Python 3 with `pywinrm` (for Windows agent targets)

**Backend / relay hosts:**
- Debian/Ubuntu Linux
- Python 3, `pip`, `flask`, `cryptography`
- Nginx (installed automatically by the relay role)

**Agent targets:**
- Linux: Python 3 + `cryptography` + `requests`
- Windows: Python 3 + `cryptography` + `requests`; WinRM enabled over HTTPS (port 5986)

---

## Configuration

All shared configuration is in `c2-setup-ansible/group_vars/all.yml`:

| Variable | Description |
|---|---|
| `backend_internal_ip` | Internal IP of the C2 backend host |
| `relay_infrastructure` | List of `{ip, domain}` objects for each relay |
| `agent_dest_lin` / `agent_dest_win` | Drop paths for the agent on Linux/Windows |
| `ansible_user` / `ansible_password` | SSH credentials for Linux hosts |
| `ansible_winrm_user` / `ansible_winrm_password` | WinRM credentials for Windows hosts |

**Before deploying:**
1. Update `inventory.ini` with real IP addresses for your backend, relays, and agent targets.
2. Update `group_vars/all.yml` with the correct `backend_internal_ip`, relay domains/IPs, and credentials.
3. Replace the Fernet `SECRET_KEY` in both `server.py` and `agent.py` with a freshly generated key. Generate one with:
   ```python
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"
   ```
4. Place your TLS certificates in the `c2-setup-ansible/files/` directory:
   - `linux-selfsigned.crt` / `linux-selfsigned.key` — for relay Nginx
   - `linux-selfsigned.crt` — agent cert bundle (Linux targets verify against this)
   - `win-selfsigned.crt` — agent cert bundle (Windows targets)

---

## Deployment

Install required Ansible collections (first time only):
```bash
ansible-galaxy collection install ansible.windows community.windows
```

Run the full playbook:
```bash
cd c2-setup-ansible
ansible-playbook -i inventory.ini deploy.yml
```

The playbook runs four plays in order:
1. **`common_net`** — Populates `/etc/hosts` (Linux) or the Windows hosts store on every host with relay domain-to-IP mappings.
2. **`snake_server`** — Copies `server.py` + `index.html` to `/opt/snake_eyes/` and starts the `c2-server` systemd service.
3. **`snake_relay`** — Installs Nginx, deploys TLS certs, and templates the reverse-proxy config on each of the 10 relay nodes.
4. **`snake_agent`** — Drops `agent.py` and the cert to the target path on each agent host and installs persistence.

To run a single role against its host group:
```bash
ansible-playbook -i inventory.ini deploy.yml --tags snake_agent
```

---

## Dashboard & API

The dashboard is served at `http://127.0.0.1:5000` once deployed.

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Operator web dashboard |
| `/checkin` | POST | Agent heartbeat / command poll (encrypted body) |
| `/result` | POST | Agent command output submission (encrypted body) |

Agent status thresholds (based on last check-in time):

| Status | Condition |
|---|---|
| `ONLINE` | Last seen < 45 seconds ago |
| `STALE` | Last seen 45 – 180 seconds ago |
| `OFFLINE` | Last seen > 180 seconds ago |

---

## Target Inventory

The default inventory covers two blue-team subnets (`10.1.x.x` Whiterun, `10.2.x.x` Morthal), each with 9 hosts spanning Windows (IIS, SMB, DNS) and Linux (GitLab, IRC, Nginx, Docker, MySQL, Apache) services.
