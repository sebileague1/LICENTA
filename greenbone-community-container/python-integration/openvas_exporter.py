import warnings
warnings.filterwarnings("ignore")

import time
import json
import urllib.request
import urllib.error
import uuid
import threading
import re
import os
import queue
import paramiko
import socketserver
import sys
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from prometheus_client import start_http_server, Gauge, REGISTRY

# =====================================================================
# SUPRIMARE ERORI
# =====================================================================
def silent_handle_error(self, request, client_address):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    if issubclass(exc_type, (ConnectionResetError, BrokenPipeError)):
        return  
    print(f"Eroare minora server HTTP: {exc_value}", file=sys.stderr)

socketserver.BaseServer.handle_error = silent_handle_error

# =====================================================================
# LOGGING ATOMIC CURATAT
# =====================================================================
PRINT_LOCK = threading.Lock()

def log_msg(mesaj):
    if not mesaj: return
    mesaj_curat = str(mesaj).strip().replace('\n', ' ').replace('\r', '')
    if mesaj_curat:
        with PRINT_LOCK:
            sys.stdout.write(mesaj_curat + '\n')
            sys.stdout.flush()

def log_err(context, exc):
    log_msg(f"{context} ❌ EROARE [{type(exc).__name__}]: {exc}")

# =====================================================================
# INFISICAL & CONFIGURARI GLOBALE
# =====================================================================
def load_secrets_from_infisical():
    secrets = {}
    infisical_url = os.environ.get("INFISICAL_URL", "")
    client_id     = os.environ.get("INFISICAL_CLIENT_ID", "")
    client_secret = os.environ.get("INFISICAL_CLIENT_SECRET", "")
    project_id    = os.environ.get("INFISICAL_PROJECT_ID", "")
    
    if all([infisical_url, client_id, client_secret, project_id]):
        try:
            login_req = urllib.request.Request(
                f"{infisical_url}/api/v1/auth/universal-auth/login",
                data=json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode('utf-8'),
                headers={'Content-Type': 'application/json'}, method='POST'
            )
            login_resp = json.loads(urllib.request.urlopen(login_req, timeout=10).read().decode())
            token = login_resp["accessToken"]
            
            secrets_url = f"{infisical_url}/api/v3/secrets/raw?workspaceId={project_id}&environment=production&secretPath=/"
            secrets_req = urllib.request.Request(secrets_url, headers={'Authorization': f'Bearer {token}'})
            secrets_resp = json.loads(urllib.request.urlopen(secrets_req, timeout=5).read().decode())
            for s in secrets_resp.get("secrets", []):
                secrets[s["secretKey"]] = s["secretValue"]
            return secrets
        except: pass
    
    for name in ["DISCORD_WEBHOOK", "HOST_UBUNTU_IP", "HOST_UBUNTU_USER", "HOST_UBUNTU_PASS", "GVMD_USER", "GVMD_PASS"]:
        val = os.environ.get(name)
        if val: secrets[name] = val
    return secrets

_SECRETS = load_secrets_from_infisical()
def secret(name, default=""): return _SECRETS.get(name, default)

VULN_HIGH   = Gauge('openvas_vulnerabilities_high_total', 'Vulnerabilitati High')
VULN_MEDIUM = Gauge('openvas_vulnerabilities_medium_total', 'Vulnerabilitati Medium')
VULN_LOW    = Gauge('openvas_vulnerabilities_low_total', 'Vulnerabilitati Low')
DEVICE_RISK = Gauge('soc_device_risk_level', 'Nivel de risc per IP', ['ip'])
VULN_KEV    = Gauge('openvas_kev_exploited_total', 'Vulnerabilitati CISA KEV')

SOAR_LOADED = False
try:
    import soar_engine
    SOAR_LOADED = True
except Exception as e:
    log_msg(f"[STARTUP] ❌ Eroare SOAR: {e}")

SOCKET_PATH = '/run/gvmd/gvmd.sock'
GVMD_USER   = secret("GVMD_USER", "admin")
GVMD_PASS   = secret("GVMD_PASS", "admin")
DISCORD_WEBHOOK = secret("DISCORD_WEBHOOK", "")
MRBENNY_BASE_URL = "https://projects.opti.ro/tuiasimrbenny/api/v1"
MRBENNY_ADMIN_KEY = secret("MRBENNY_ADMIN_KEY", "adm-tui-311")
MRBENNY_HARDWARE_UUID = secret("MRBENNY_HARDWARE_UUID", "ov2-master-ubuntu-007")

CISA_KEV_LIST = set()
LOCAL_DEVICE_MAP = {}
IS_FIRST_RUN = True
AGENT_START_TIME = time.time()

# =====================================================================
# STATE PERSISTENT 
# =====================================================================
STATE_DIR = "/app/state"
ALERTED_FILE = os.path.join(STATE_DIR, "alerted.json")
os.makedirs(STATE_DIR, exist_ok=True)

def load_alert_state():
    if os.path.exists(ALERTED_FILE):
        try:
            with open(ALERTED_FILE, "r") as f:
                return json.load(f)
        except: pass
    return {}

def save_alert_state():
    try:
        with open(ALERTED_FILE, "w") as f:
            json.dump(ALREADY_ALERTED, f)
    except Exception as e:
        log_msg(f"⚠️ Eroare la salvare state: {e}")

ALREADY_ALERTED = load_alert_state()

# =====================================================================
# DISCORD QUEUE & WORKER
# =====================================================================
DISCORD_QUEUE        = queue.Queue(maxsize=5000)
DISCORD_MIN_INTERVAL = 0.5
DISCORD_LOCK         = threading.Lock()
DISCORD_LAST_SEND    = 0

def _discord_send_raw(payload_dict, retry_count=0):
    global DISCORD_LAST_SEND
    if not DISCORD_WEBHOOK: return False
    if retry_count >= 3: return False
    
    with DISCORD_LOCK:
        wait = DISCORD_MIN_INTERVAL - (time.time() - DISCORD_LAST_SEND)
        if wait > 0: time.sleep(wait)
        DISCORD_LAST_SEND = time.time()
        
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK, data=json.dumps(payload_dict).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'SOC-OV2-Agent/2.0'}
        )
        urllib.request.urlopen(req, timeout=8)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 429:
            time.sleep(1.0)
            return _discord_send_raw(payload_dict, retry_count + 1)
        return False
    except Exception as e:
        return False

def discord_worker():
    while True:
        try:
            payload = DISCORD_QUEUE.get(timeout=5)
            _discord_send_raw(payload)
            DISCORD_QUEUE.task_done()
        except queue.Empty: continue

def send_discord_alert(host, name, severity, cve, mb_id, sol, desc, is_kev, soar_action=None):
    if not DISCORD_WEBHOOK: return
    color = 0x000000 if is_kev else (0xFF0000 if float(severity) >= 7.0 else 0xFF8C00)
    
    desc_clean = desc[:300].replace('\n', ' ') + "..." if len(desc) > 300 else desc.replace('\n', ' ')
    sol_clean = sol[:300].replace('\n', ' ') + "..." if len(sol) > 300 else sol.replace('\n', ' ')
    act_clean = soar_action.replace('\n', ' ') if soar_action else f"*{sol_clean}*"

    payload = {
        "content": "🚨 **VULNERABILITATE NOUĂ DETECTATĂ**",
        "embeds": [{
            "title": f"🔍 {name}",
            "color": color,
            "fields": [
                {"name": "🖥️ Host", "value": f"`{host}`", "inline": True},
                {"name": "⚠️ CVSS", "value": f"**{severity}**", "inline": True},
                {"name": "🏷️ CVE", "value": f"`{cve}`", "inline": False},
                {"name": "📖 Descriere", "value": f"_{desc_clean}_", "inline": False},
                {"name": "🛡️ SOAR / Soluție", "value": act_clean, "inline": False}
            ],
            "footer": {"text": "SOC OV2 Agent | Trusted Mode B2"}
        }]
    }
    DISCORD_QUEUE.put_nowait(payload)
    log_msg(f"[DISCORD] 🚀 Alerta noua trimisa pentru: {name}")

def send_discord_resolved(host, name, cve):
    if not DISCORD_WEBHOOK: return
    payload = {
        "content": "✅ **VULNERABILITATE REMEDIATĂ / ÎNCHISĂ**",
        "embeds": [{
            "title": f"✅ {name}",
            "color": 0x00C853,
            "fields": [
                {"name": "🖥️ Host", "value": f"`{host}`", "inline": True},
                {"name": "📋 Status", "value": "Rezolvat/Șters din Raport", "inline": True}
            ],
            "footer": {"text": "SOC OV2 Agent | Incident Închis"}
        }]
    }
    DISCORD_QUEUE.put_nowait(payload)
    log_msg(f"[DISCORD] 🟢 Notificare de REZOLVARE trimisa pentru: {name}")

def get_or_create_mrbenny_id(ip):
    return "N/A"

# =====================================================================
# CORE SYNC LOGIC (GLOBAL - FARA BLOCAJ PE TASK ID)
# =====================================================================
def fetch_cisa_kev():
    global CISA_KEV_LIST
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            CISA_KEV_LIST = {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e: pass

def run_soar_async(host, name, sev, cve, mb_id, sol, desc, is_kev):
    try:
        soar_action = soar_engine.trigger_remediation(host, name) if SOAR_LOADED else None
        send_discord_alert(host, name, str(sev), cve, mb_id, sol, desc, is_kev, soar_action)
        DEVICE_RISK.labels(ip=host).set(1)
    except Exception as e: log_err(f"[SOAR Async]", e)

def get_openvas_data():
    global IS_FIRST_RUN
    connection = UnixSocketConnection(path=SOCKET_PATH, timeout=300.0)
    try:
        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(GVMD_USER, GVMD_PASS)
            
            # Scanam global TOATE rezultatele active
            results = gmp.get_results(filter_string="rows=-1 ignore_pagination=1 trash=0 apply_overrides=1 details=1")

            unique_high, unique_med, unique_low, unique_kev = set(), set(), set(), set()
            current_signatures = set()
            new_alerts = []

            for res in results.xpath('result'):
                try:
                    host = res.find('host').text or "unknown"
                    if host == "unknown": continue

                    nvt = res.find('nvt')
                    oid = nvt.get('oid')
                    name = res.find('name').text or nvt.find('name').text
                    cve = nvt.find('cve').text if nvt.find('cve') is not None else "N/A"
                    sev = float(res.find('severity').text)
                    sig = f"{host}|{oid}"

                    desc_node = res.find('description')
                    desc = desc_node.text.strip() if desc_node is not None and desc_node.text else "Nicio descriere detaliata."
                    
                    sol = "Investigatie manuala."
                    tags = nvt.find('tags')
                    if tags is not None and tags.text:
                        m_sol = re.search(r'solution=([^|]+)', tags.text)
                        if m_sol: sol = m_sol.group(1).strip()

                    if sev >= 4.0:
                        current_signatures.add(sig)
                        if sev >= 7.0: unique_high.add(sig)
                        else: unique_med.add(sig)
                        if cve in CISA_KEV_LIST and cve != "N/A": unique_kev.add(sig)

                        if sig not in ALREADY_ALERTED:
                            mb_id = get_or_create_mrbenny_id(host)
                            ALREADY_ALERTED[sig] = {"host": host, "name": name, "cve": cve, "missing_count": 0}
                            if not IS_FIRST_RUN:
                                new_alerts.append((host, name, sev, cve, mb_id, sol, desc, False))
                        else:
                            ALREADY_ALERTED[sig]["missing_count"] = 0 # Reset
                    elif sev > 0:
                        unique_low.add(sig)
                except: continue

            for a in new_alerts:
                threading.Thread(target=run_soar_async, args=a, daemon=True).start()

            # --- LOGICA DEBOUNCE (ASTEPTARE) VIZIBILA ---
            resolved_to_remove = []
            for s in list(ALREADY_ALERTED.keys()):
                if s not in current_signatures:
                    ALREADY_ALERTED[s]["missing_count"] += 1
                    miss_cnt = ALREADY_ALERTED[s]["missing_count"]
                    
                    if miss_cnt == 1:
                        log_msg(f"[DEBOUNCE] ⏳ Alerta '{ALREADY_ALERTED[s]['name']}' a disparut! Asteptam confirmarea (1/3)...")
                    elif miss_cnt >= 3:
                        log_msg(f"[DEBOUNCE] 🗑️ Confirmare: Alerta '{ALREADY_ALERTED[s]['name']}' stearsa definitiv!")
                        resolved_to_remove.append(s)

            for s in resolved_to_remove:
                v = ALREADY_ALERTED.pop(s)
                if not IS_FIRST_RUN:
                    send_discord_resolved(v["host"], v["name"], v["cve"])
                    DEVICE_RISK.labels(ip=v["host"]).set(0)

            IS_FIRST_RUN = False
            VULN_HIGH.set(len(unique_high)); VULN_MEDIUM.set(len(unique_med))
            VULN_LOW.set(len(unique_low)); VULN_KEV.set(len(unique_kev))
            save_alert_state()

    except Exception as e: log_err("[OpenVAS]", e)

# =====================================================================
# HIDS & MAIN
# =====================================================================
QUARANTINE_LOCK = threading.Lock()
atacatori_cunoscuti = {}

def execute_quarantine(ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=HOST_UBUNTU_IP, port=22, username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5)
        stdin, stdout, stderr = client.exec_command(f"echo '{HOST_UBUNTU_PASS}' | sudo -S iptables -I INPUT 1 -p tcp --dport 22 -s {ip} -j DROP")
        if stdout.channel.recv_exit_status() == 0: log_msg(f"[SOAR] 🧱 IP {ip} BLOCAT pe SSH. Deblocare in 60s.")
        client.close()
    except Exception as e: pass
    
    time.sleep(60)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=HOST_UBUNTU_IP, port=22, username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5)
        client.exec_command(f"echo '{HOST_UBUNTU_PASS}' | sudo -S sh -c 'while iptables -D INPUT -p tcp --dport 22 -s {ip} -j DROP 2>/dev/null; do true; done'")
        client.close()
        log_msg(f"[SOAR] 🟢 IP {ip} DEBLOCAT GARANTAT dupa 60s.")
    except Exception as e: pass
    finally:
        with QUARANTINE_LOCK: atacatori_cunoscuti[ip] = 0

def monitor_hids_logs():
    log_file = "/host_logs/auth.log"
    while not os.path.exists(log_file): time.sleep(5)
    log_msg(f"[HIDS] ✅ Monitorizare activa pe {log_file}")
    
    f = open(log_file, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    fail_patterns = [re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'), re.compile(r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)')]
    
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        
        ip = None
        for p in fail_patterns:
            m = p.search(line)
            if m: ip = m.group(1); break
        if not ip: continue
        if ip in {"192.168.128.181", "127.0.0.1"} or ip.startswith("172."): continue

        with QUARANTINE_LOCK:
            if atacatori_cunoscuti.get(ip, 0) == "BLOCKED": continue
            atacatori_cunoscuti[ip] = atacatori_cunoscuti.get(ip, 0) + 1
            nou_count = atacatori_cunoscuti[ip]
            log_msg(f"[HIDS] ⚠️ Tentativa SSH de la {ip} ({nou_count}/3)")

            if nou_count >= 3:
                atacatori_cunoscuti[ip] = "BLOCKED"
                msg = f"🛡️ **SOAR HIDS:** IP `{ip}` blocat SSH 60s. (Tentative: **{nou_count}**)"
                log_msg(f"[SOAR] 🚨 BLOCARE INITIATA pentru {ip}")
                send_discord_alert("Ubuntu Host", "SSH Brute Force (HIDS)", "10.0", "N/A", "N/A", "Carantina SSH", "Atac Brute Force detectat pe portul 22.", False, msg)
                threading.Thread(target=execute_quarantine, args=(ip,), daemon=True).start()

if __name__ == '__main__':
    threading.Thread(target=discord_worker, daemon=True).start()  
    threading.Thread(target=monitor_hids_logs, daemon=True).start()

    fetch_cisa_kev()
    try: start_http_server(8000)
    except: pass

    loop = 0
    while True:
        get_openvas_data()
        if loop % 720 == 0 and loop > 0: fetch_cisa_kev()
        loop += 1
        time.sleep(15)
