import time
import json
import urllib.request
import urllib.error
import uuid
import threading
import re
import os
import paramiko
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from prometheus_client import start_http_server, Gauge, REGISTRY

# =====================================================================
# LOGGING
# =====================================================================
def log_msg(mesaj):
    print(mesaj, flush=True)

def log_err(context, exc):
    tip = type(exc).__name__
    log_msg(f"{context} ❌ EROARE [{tip}]: {exc}")

# =====================================================================
# INFISICAL — SMART FETCHER
# =====================================================================
def load_secrets_from_infisical():
    secrets = {}
    infisical_url = os.environ.get("INFISICAL_URL", "")
    client_id     = os.environ.get("INFISICAL_CLIENT_ID", "")
    client_secret = os.environ.get("INFISICAL_CLIENT_SECRET", "")
    project_id    = os.environ.get("INFISICAL_PROJECT_ID", "")
    env_from_var  = os.environ.get("INFISICAL_ENV", "production")

    if all([infisical_url, client_id, client_secret, project_id]):
        try:
            login_req = urllib.request.Request(
                f"{infisical_url}/api/v1/auth/universal-auth/login",
                data=json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode('utf-8'),
                headers={'Content-Type': 'application/json'}, method='POST'
            )
            login_resp = json.loads(urllib.request.urlopen(login_req, timeout=10).read().decode())
            token = login_resp["accessToken"]
            log_msg("[INFISICAL] ✅ Autentificare reusita. Cautam secretele...")

            envs_to_try = [env_from_var, "prod", "dev", "production", "development"]
            envs_to_try = list(dict.fromkeys(envs_to_try))

            infisical_secrets = []
            found_env = ""

            for env in envs_to_try:
                try:
                    secrets_url = f"{infisical_url}/api/v3/secrets/raw?workspaceId={project_id}&environment={env}&secretPath=/"
                    secrets_req = urllib.request.Request(secrets_url, headers={'Authorization': f'Bearer {token}'})
                    secrets_resp = json.loads(urllib.request.urlopen(secrets_req, timeout=5).read().decode())

                    temp_secrets = secrets_resp.get("secrets", [])
                    if len(temp_secrets) > 0:
                        infisical_secrets = temp_secrets
                        found_env = env
                        break
                except Exception:
                    pass

            if len(infisical_secrets) == 0:
                log_msg("[INFISICAL] ⚠️ Infisical a returnat 0 secrete in toate mediile. Fallback pe env vars.")
            else:
                for s in infisical_secrets:
                    secrets[s["secretKey"]] = s["secretValue"]
                log_msg(f"[INFISICAL] ✅ {len(secrets)} secrete incarcate cu succes din mediul '{found_env}'.")
                return secrets

        except Exception as e:
            log_msg(f"[INFISICAL] ⚠️ Eroare conectare API: {e}. Fallback pe env vars.")
    else:
        log_msg("[INFISICAL] ⚠️ Variabile lipsa in docker-compose. Folosesc env vars direct.")

    for name in ["DISCORD_WEBHOOK", "HOST_UBUNTU_IP", "HOST_UBUNTU_USER", "HOST_UBUNTU_PASS", "GVMD_USER", "GVMD_PASS", "MRBENNY_ADMIN_KEY", "MRBENNY_HARDWARE_UUID"]:
        val = os.environ.get(name)
        if val: secrets[name] = val
    log_msg(f"[INFISICAL] ⚠️ Fallback activ: {len(secrets)} secrete locale incarcate.")
    return secrets

_SECRETS = load_secrets_from_infisical()
def secret(name, default=""): return _SECRETS.get(name, default)

# =====================================================================
# METRICI PROMETHEUS
# =====================================================================
def create_gauge(name, desc, labels=()):
    if name in REGISTRY._names_to_collectors: return REGISTRY._names_to_collectors[name]
    return Gauge(name, desc, labels)

VULN_HIGH   = create_gauge('openvas_vulnerabilities_high_total',   'Vulnerabilitati Unice High')
VULN_MEDIUM = create_gauge('openvas_vulnerabilities_medium_total', 'Vulnerabilitati Unice Medium')
VULN_LOW    = create_gauge('openvas_vulnerabilities_low_total',    'Vulnerabilitati Unice Low')
DEVICE_RISK = create_gauge('soc_device_risk_level',                'Nivel de risc activ per IP', ['ip'])
VULN_KEV    = create_gauge('openvas_kev_exploited_total',          'Vulnerabilitati Exploatate Activ (CISA KEV)')

# =====================================================================
# INCARCARE MODUL SOAR
# =====================================================================
SOAR_LOADED = False
try:
    import soar_engine
    SOAR_LOADED = True
    log_msg("[STARTUP] ✅ Modulul SOAR a fost incarcat cu succes in memorie!")
except Exception as e:
    log_msg(f"[STARTUP] ❌ ATENTIE: Modulul soar_engine nu a putut fi incarcat! Motiv: {e}")

# =====================================================================
# CONFIGURARE
# =====================================================================
SOCKET_PATH = '/run/gvmd/gvmd.sock'
GVMD_USER   = secret("GVMD_USER",   "admin")
GVMD_PASS   = secret("GVMD_PASS",   "admin")
DISCORD_WEBHOOK   = secret("DISCORD_WEBHOOK", "")
HOST_UBUNTU_IP   = secret("HOST_UBUNTU_IP",   "192.168.128.181")
HOST_UBUNTU_USER = secret("HOST_UBUNTU_USER", "ubuntu24")
HOST_UBUNTU_PASS = secret("HOST_UBUNTU_PASS", "")
MRBENNY_BASE_URL      = "https://projects.opti.ro/tuiasimrbenny/api/v1"
MRBENNY_ADMIN_KEY     = secret("MRBENNY_ADMIN_KEY",     "adm-tui-311")
MRBENNY_HARDWARE_UUID = secret("MRBENNY_HARDWARE_UUID", "ov2-master-ubuntu-007")
MRBENNY_SESSION_TOKEN = None

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_LIST = set()
LOCAL_DEVICE_MAP = {}
ALREADY_ALERTED  = {}
IS_FIRST_RUN     = True
AGENT_START_TIME = time.time()
DISCORD_LAST_SEND    = 0
DISCORD_LOCK         = threading.Lock()
DISCORD_MIN_INTERVAL = 1.5

# =====================================================================
# MODUL: MR. BENNY INTEGRATION
# =====================================================================
def authenticate_mrbenny():
    global MRBENNY_SESSION_TOKEN
    try:
        req_token = urllib.request.Request(
            f"{MRBENNY_BASE_URL}/install_tokens/generate",
            data=json.dumps({"agent_type": "OV2", "label": "SOC OV2 Master Ubuntu", "allowed_modes": ["B2"], "notes": "Auto-install"}).encode('utf-8'),
            headers={'X-Mrbenny-Mode': 'A', 'X-Admin-Key': MRBENNY_ADMIN_KEY, 'Content-Type': 'application/json'}
        )
        res_token     = json.loads(urllib.request.urlopen(req_token, timeout=10).read().decode())
        install_token = res_token["data"]["install_token"]

        req_sess = urllib.request.Request(
            f"{MRBENNY_BASE_URL}/auth/session",
            data=json.dumps({"agent_type": "OV2", "hardware_uuid": MRBENNY_HARDWARE_UUID, "install_token": install_token, "agent_version": "2.0", "host_label": "ov2-master"}).encode('utf-8'),
            headers={'X-Mrbenny-Mode': 'B2', 'Content-Type': 'application/json'}
        )
        res_sess = json.loads(urllib.request.urlopen(req_sess, timeout=10).read().decode())
        MRBENNY_SESSION_TOKEN = res_sess["data"]["session_token"]
        log_msg("[AUTH] ✅ Autentificare B2 REUSITA!")
        return True
    except Exception as e: return False

def mrbenny_request(endpoint, method="GET", payload=None):
    if not MRBENNY_SESSION_TOKEN: return None
    url     = f"{MRBENNY_BASE_URL}{endpoint}"
    headers = {'Content-Type': 'application/json', 'User-Agent': 'SOC-OV2-Agent/2.0', 'X-Mrbenny-Mode': 'B2', 'Authorization': f'Bearer {MRBENNY_SESSION_TOKEN}'}
    data = json.dumps(payload).encode('utf-8') if payload else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response: return json.loads(response.read().decode())
    except: return None

def mrbenny_heartbeat_loop():
    while True:
        if MRBENNY_SESSION_TOKEN:
            uptime  = int(time.time() - AGENT_START_TIME)
            payload = {"client_event_id": f"hb-ov2-{int(time.time())}", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "status": "online", "metrics": {"queue_size": 0, "uptime_seconds": uptime, "version": "2.0"}}
            mrbenny_request("/heartbeat", method="POST", payload=payload)
        time.sleep(30)

def mrbenny_ontology_loop():
    global LOCAL_DEVICE_MAP
    while True:
        try:
            res = mrbenny_request("/ontology", method="GET")
            if res and res.get("ok"):
                devices = res.get("data", {}).get("devices", [])
                new_map = {}
                for dev in devices:
                    dev_id = dev.get("mrbenny_device_id")
                    for ident in dev.get("identifiers", []):
                        if ident.get("type") in ["ip", "ipv4", "ipv6"]: new_map[ident.get("value")] = dev_id
                for k, v in LOCAL_DEVICE_MAP.items():
                    if k not in new_map: new_map[k] = v
                LOCAL_DEVICE_MAP = new_map
        except: pass
        time.sleep(120)

def get_or_create_mrbenny_id(ip):
    global LOCAL_DEVICE_MAP
    if ip in LOCAL_DEVICE_MAP and LOCAL_DEVICE_MAP[ip] != "N/A": return LOCAL_DEVICE_MAP[ip]
    payload = {"client_event_id": f"ov2-boot-{uuid.uuid4().hex[:8]}", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event_type": "bootstrap_identify", "observations": [{"observation_ref": f"obs-{ip.replace('.', '')}", "identifiers": [{"type": "ip", "value": ip}]}]}
    try:
        res = mrbenny_request("/ingest/data", method="POST", payload=payload)
        if res and res.get("ok"):
            id_map = res.get("data", {}).get("id_map", {})
            if id_map:
                new_id = list(id_map.values())[0]
                LOCAL_DEVICE_MAP[ip] = new_id
                return new_id
    except: pass
    LOCAL_DEVICE_MAP[ip] = "N/A"
    return "N/A"

# =====================================================================
# MODUL: DISCORD ALERTS
# =====================================================================
def _discord_send(payload_dict, retry_count=0):
    global DISCORD_LAST_SEND
    if not DISCORD_WEBHOOK: return False
    if retry_count >= 3: return False
    with DISCORD_LOCK:
        wait = DISCORD_MIN_INTERVAL - (time.time() - DISCORD_LAST_SEND)
        if wait > 0: time.sleep(wait)
        DISCORD_LAST_SEND = time.time()
    try:
        req = urllib.request.Request(DISCORD_WEBHOOK, json.dumps(payload_dict).encode('utf-8'), {'Content-Type': 'application/json', 'User-Agent': 'SOC-OV2-Agent/2.0'})
        urllib.request.urlopen(req, timeout=8)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 429:
            time.sleep(2.0)
            return _discord_send(payload_dict, retry_count + 1)
        return False
    except: return False

def send_discord_alert(host, name, severity, cve, is_high, mrbenny_id, solution, is_kev_exploited, soar_action=None):
    try: score = float(severity)
    except: score = 0.0
    color        = 0x000000 if is_kev_exploited else (0xFF0000 if score >= 7.0 else 0xFF8C00)
    host_display = f"`{host}`" + (f"\n🔖 MrBenny ID: `{mrbenny_id}`" if mrbenny_id != "N/A" else "")
    payload = {
        "content": "🚨 **VULNERABILITATE NOUĂ DETECTATĂ**" if not is_kev_exploited else "☠️ **CRITICAL KEV MATCH!**",
        "embeds": [{
            "title": f"🔍 {name}",
            "color": color,
            "fields": [
                {"name": "🖥️ Host",   "value": host_display,                                      "inline": True},
                {"name": "⚠️ CVSS",   "value": f"**{severity}**",                                 "inline": True},
                {"name": "🏷️ CVE",   "value": f"`{cve}`",                                        "inline": False},
                {"name": "🛡️ SOAR" if soar_action else "🛠️ Soluție", "value": soar_action if soar_action else f"*{solution[:500]}*", "inline": False}
            ],
            "footer": {"text": "SOC OV2 Agent | Trusted Mode B2 | Infisical"}
        }]
    }
    _discord_send(payload)

def send_discord_resolved(host, name, cve, mrbenny_id):
    payload = {
        "content": "✅ **VULNERABILITATE REMEDIATĂ / ÎNCHISĂ**",
        "embeds": [{
            "title": f"✅ {name}",
            "color": 0x00C853,
            "fields": [
                {"name": "🖥️ Host",   "value": f"`{host}`",      "inline": True},
                {"name": "📋 Status", "value": "Rezolvat/Șters", "inline": True}
            ],
            "footer": {"text": "SOC OV2 Agent | Incident Închis | Infisical"}
        }]
    }
    _discord_send(payload)

def send_startup_message():
    sursa = "✅ Infisical API" if "DISCORD_WEBHOOK" in _SECRETS and os.environ.get("INFISICAL_CLIENT_ID") else "⚠️ Env vars"
    soar_status = "✅ ACTIV" if SOAR_LOADED else "❌ EROARE"
    _discord_send({"content": (
        "🟢 **SOC OV2 — SISTEM PORNIT (vFINAL - Port Quarantine Fix)**\n"
        f"Secrete: **{sursa}** ({len(_SECRETS)} incarcate)\n"
        f"Status SOAR: **{soar_status}**"
    )})

# =====================================================================
# MODUL: OPENVAS SYNC
# =====================================================================
def fetch_cisa_kev():
    global CISA_KEV_LIST
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            CISA_KEV_LIST = {vuln["cveID"] for vuln in data.get("vulnerabilities", [])}
    except: pass

def get_openvas_data():
    global IS_FIRST_RUN
    connection = UnixSocketConnection(path=SOCKET_PATH, timeout=300.0)
    try:
        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(GVMD_USER, GVMD_PASS)
            results = gmp.get_results(filter_string="rows=-1 ignore_pagination=1 trash=0 apply_overrides=1")

            unique_high, unique_med, unique_low, unique_kev = set(), set(), set(), set()
            current_signatures = set()

            for res in results.xpath('result'):
                try:
                    host_elem = res.find('host')
                    host      = host_elem.text if host_elem is not None else "unknown"
                    if not host or host == "unknown": continue

                    nvt_node = res.find('nvt')
                    oid      = nvt_node.get('oid')
                    name     = res.find('name').text or nvt_node.find('name').text
                    cve_node = nvt_node.find('cve')
                    cve      = cve_node.text if cve_node is not None else "N/A"
                    sev      = float(res.find('severity').text)
                    sol      = "Vezi OpenVAS"
                    sig      = f"{host}|{oid}"

                    if sev >= 4.0:
                        current_signatures.add(sig)
                        if sev >= 7.0: unique_high.add(sig)
                        else: unique_med.add(sig)

                        is_kev = (cve in CISA_KEV_LIST and cve != "N/A")
                        if is_kev: unique_kev.add(sig)

                        if sig not in ALREADY_ALERTED:
                            mb_id = get_or_create_mrbenny_id(host)
                            ALREADY_ALERTED[sig] = {
                                "host": host, "name": name,
                                "cve": cve,   "mrbenny_id": mb_id
                            }

                            if not IS_FIRST_RUN:
                                soar_action = None
                                if SOAR_LOADED:
                                    try:
                                        soar_action = soar_engine.trigger_remediation(host, name)
                                    except Exception as e:
                                        log_err("[SOAR]", e)

                                send_discord_alert(host, name, str(sev), cve, (sev >= 7.0), mb_id, sol, is_kev, soar_action)
                                DEVICE_RISK.labels(ip=host).set(1)
                    elif sev > 0:
                        unique_low.add(sig)
                except: continue

            resolved = set(ALREADY_ALERTED.keys()) - current_signatures
            for s in resolved:
                v = ALREADY_ALERTED.pop(s)
                if not IS_FIRST_RUN:
                    send_discord_resolved(v["host"], v["name"], v["cve"], v["mrbenny_id"])
                    DEVICE_RISK.labels(ip=v["host"]).set(0)

            IS_FIRST_RUN = False
            VULN_HIGH.set(len(unique_high))
            VULN_MEDIUM.set(len(unique_med))
            VULN_LOW.set(len(unique_low))
            VULN_KEV.set(len(unique_kev))

    except Exception as e: pass

# =====================================================================
# MODUL: HIDS & SOAR (Blocaj DOAR pe portul 22 - Salveaza reteaua WSL)
# =====================================================================
atacatori_cunoscuti = {}

def execute_quarantine(ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=HOST_UBUNTU_IP, port=22, username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5)
        
        # CRITIC FIX: Blocăm DOAR portul 22 (SSH) ca să nu picăm router-ul intern al WSL!
        stdin, stdout, stderr = client.exec_command(f"echo '{HOST_UBUNTU_PASS}' | sudo -S iptables -A INPUT -p tcp --dport 22 -s {ip} -j DROP")
        stdout.channel.recv_exit_status()
        
        client.close()
        log_msg(f"[SOAR] 🧱 Accesul SSH pt IP {ip} blocat in firewall.")
    except Exception as e: log_err(f"[SOAR] Blocare {ip}", e)

    time.sleep(60)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=HOST_UBUNTU_IP, port=22, username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5)
        
        # Unblock garantat cu while loop DOAR pentru portul 22
        unblock_cmd = f"echo '{HOST_UBUNTU_PASS}' | sudo -S sh -c 'while iptables -D INPUT -p tcp --dport 22 -s {ip} -j DROP 2>/dev/null; do true; done'"
        
        stdin, stdout, stderr = client.exec_command(unblock_cmd)
        stdout.channel.recv_exit_status()
        
        client.close()
        log_msg(f"[SOAR] 🟢 Accesul SSH pt IP {ip} deblocat GARANTAT.")
    except Exception as e: log_err(f"[SOAR] Deblocare {ip}", e)
    atacatori_cunoscuti[ip] = 0

def monitor_hids_logs():
    log_file = "/host_logs/auth.log"
    while not os.path.exists(log_file): time.sleep(5)

    f = open(log_file, "r", errors="replace")
    f.seek(0, os.SEEK_END)

    fail_patterns = [
        re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+) port'),
        re.compile(r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'error: maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)')
    ]

    WHITELIST_EXACTE  = {"192.168.128.181", "127.0.0.1", "::1"}
    WHITELIST_PREFIXE = ["172.17.", "172.18.", "172.19."]

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue

        ip = None
        for pattern in fail_patterns:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                break

        if not ip and "message repeated" in line:
            m_ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if m_ip: ip = m_ip.group(1)

        if not ip: continue
        if (ip in WHITELIST_EXACTE or any(ip.startswith(p) for p in WHITELIST_PREFIXE)): continue
        if atacatori_cunoscuti.get(ip) == "BLOCKED": continue

        inc = 1
        if "repeated" in line:
            rm = re.search(r'repeated (\d+) times', line)
            if rm: inc = int(rm.group(1))

        current_count = atacatori_cunoscuti.get(ip, 0)

        for step in range(inc):
            current_count += 1
            if current_count <= 3:
                log_msg(f"[HIDS] Detectie Brute-Force: {ip} ({current_count}/3)")
                if inc > 1 and current_count < 3:
                    time.sleep(0.8)

            if current_count == 3:
                atacatori_cunoscuti[ip] = "BLOCKED"
                mb_id = get_or_create_mrbenny_id(ip)
                msg   = f"🛡️ **SOAR HIDS:** Portul SSH pt IP `{ip}` blocat in firewall 60s."
                send_discord_alert("Ubuntu Host", "SSH Brute Force (HIDS)", "10.0", "N/A", True, mb_id, "Carantina SSH (60s)", False, msg)
                threading.Thread(target=execute_quarantine, args=(ip,), daemon=True).start()
                break

        if atacatori_cunoscuti.get(ip) != "BLOCKED":
            atacatori_cunoscuti[ip] = current_count

# =====================================================================
# MAIN
# =====================================================================
if __name__ == '__main__':
    authenticate_mrbenny()
    threading.Thread(target=mrbenny_heartbeat_loop, daemon=True).start()
    threading.Thread(target=mrbenny_ontology_loop,  daemon=True).start()
    threading.Thread(target=monitor_hids_logs,       daemon=True).start()

    fetch_cisa_kev()
    send_startup_message()

    try: start_http_server(8000)
    except Exception as e: log_err("[PROMETHEUS]", e)

    loop = 0
    while True:
        get_openvas_data()
        if loop % 720 == 0 and loop > 0: fetch_cisa_kev()
        loop += 1
        time.sleep(5)
