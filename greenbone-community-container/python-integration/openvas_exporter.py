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
                log_msg("[INFISICAL] ⚠️ Infisical a returnat 0 secrete. Fallback pe env vars.")
            else:
                for s in infisical_secrets:
                    secrets[s["secretKey"]] = s["secretValue"]
                log_msg(f"[INFISICAL] ✅ {len(secrets)} secrete incarcate din mediul '{found_env}'.")
                return secrets

        except Exception as e:
            log_msg(f"[INFISICAL] ⚠️ Eroare conectare API: {e}. Fallback pe env vars.")
    else:
        log_msg("[INFISICAL] ⚠️ Variabile lipsa. Folosesc env vars direct.")

    for name in ["DISCORD_WEBHOOK", "HOST_UBUNTU_IP", "HOST_UBUNTU_USER", "HOST_UBUNTU_PASS",
                 "GVMD_USER", "GVMD_PASS", "MRBENNY_ADMIN_KEY", "MRBENNY_HARDWARE_UUID"]:
        val = os.environ.get(name)
        if val:
            secrets[name] = val
    log_msg(f"[INFISICAL] ⚠️ Fallback activ: {len(secrets)} secrete locale.")
    return secrets

_SECRETS = load_secrets_from_infisical()
def secret(name, default=""): return _SECRETS.get(name, default)

# =====================================================================
# METRICI PROMETHEUS
# =====================================================================
def create_gauge(name, desc, labels=()):
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
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
    log_msg("[STARTUP] ✅ Modulul SOAR a fost incarcat cu succes!")
except Exception as e:
    log_msg(f"[STARTUP] ❌ soar_engine nu a putut fi incarcat! Motiv: {e}")

# =====================================================================
# CONFIGURARE
# =====================================================================
SOCKET_PATH = '/run/gvmd/gvmd.sock'
GVMD_USER   = secret("GVMD_USER",   "admin")
GVMD_PASS   = secret("GVMD_PASS",   "admin")
DISCORD_WEBHOOK      = secret("DISCORD_WEBHOOK", "")
HOST_UBUNTU_IP       = secret("HOST_UBUNTU_IP",   "192.168.128.181")
HOST_UBUNTU_USER     = secret("HOST_UBUNTU_USER", "ubuntu24")
HOST_UBUNTU_PASS     = secret("HOST_UBUNTU_PASS", "")
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

# ✅ FIX: Cache pentru report IDs valide (previne phantom alerts)
VALID_REPORTS_CACHE = set()
LAST_REPORTS_CHECK = 0

# =====================================================================
# DISCORD QUEUE - OPTIMIZED
# =====================================================================
DISCORD_QUEUE        = queue.Queue(maxsize=100)
DISCORD_MIN_INTERVAL = 1.0
DISCORD_LOCK         = threading.Lock()
DISCORD_LAST_SEND    = 0

def _discord_send_raw(payload_dict, retry_count=0):
    global DISCORD_LAST_SEND
    if not DISCORD_WEBHOOK:
        return False
    if retry_count >= 3:
        return False
    with DISCORD_LOCK:
        wait = DISCORD_MIN_INTERVAL - (time.time() - DISCORD_LAST_SEND)
        if wait > 0:
            time.sleep(wait)
        DISCORD_LAST_SEND = time.time()
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK,
            json.dumps(payload_dict).encode('utf-8'),
            {'Content-Type': 'application/json', 'User-Agent': 'SOC-OV2-Agent/2.0'}
        )
        urllib.request.urlopen(req, timeout=8)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                body = json.loads(e.read().decode())
                wait_time = float(body.get("retry_after", 2.0))
            except:
                wait_time = 2.0
            log_msg(f"[DISCORD] ⏳ Rate limited. Astept {wait_time}s...")
            time.sleep(wait_time)
            return _discord_send_raw(payload_dict, retry_count + 1)
        return False
    except Exception as e:
        log_err("[DISCORD]", e)
        return False

def discord_worker():
    log_msg("[DISCORD] ✅ Worker Discord pornit.")
    while True:
        try:
            payload = DISCORD_QUEUE.get(timeout=5)
            _discord_send_raw(payload)
            DISCORD_QUEUE.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            log_err("[DISCORD Worker]", e)

def _discord_send(payload_dict):
    """Non-blocking — adauga in coada, nu blocheza loop-ul principal."""
    if not DISCORD_WEBHOOK:
        return
    try:
        DISCORD_QUEUE.put_nowait(payload_dict)
    except queue.Full:
        log_msg("[DISCORD] ⚠️ Coada plina, mesaj ignorat.")

# =====================================================================
# DISCORD ALERTS - EXTENDED VERSION
# =====================================================================
def send_discord_alert_extended(host, name, severity, cve, is_high, mrbenny_id,
                                solution, is_kev_exploited, soar_action=None,
                                description="N/A", impact="N/A", affected="N/A"):
    """Alerta Discord cu informatii EXTINSE despre vulnerabilitate."""
    try:
        score = float(severity)
    except:
        score = 0.0
    
    color = 0x000000 if is_kev_exploited else (0xFF0000 if score >= 7.0 else 0xFF8C00)
    host_display = f"`{host}`"
    if mrbenny_id != "N/A":
        host_display += f"\n🔖 MrBenny ID: `{mrbenny_id}`"
    
    fields = [
        {"name": "🖥️ Host", "value": host_display, "inline": True},
        {"name": "⚠️ CVSS", "value": f"**{severity}**", "inline": True},
        {"name": "🏷️ CVE", "value": f"`{cve}`", "inline": False}
    ]
    
    if description and description != "N/A" and len(description) > 10:
        fields.append({
            "name": "📝 Descriere",
            "value": f"*{description}*",
            "inline": False
        })
    
    if impact and impact != "N/A" and len(impact) > 5:
        fields.append({
            "name": "💥 Impact",
            "value": f"*{impact[:300]}*",
            "inline": False
        })
    
    if affected and affected != "N/A" and len(affected) > 5:
        fields.append({
            "name": "🎯 Sisteme Afectate",
            "value": f"*{affected[:200]}*",
            "inline": False
        })
    
    if soar_action:
        fields.append({
            "name": "🛡️ SOAR Remediation",
            "value": soar_action,
            "inline": False
        })
    else:
        sol_display = solution[:600] if len(solution) > 600 else solution
        if len(solution) > 600:
            sol_display += "\n*...vezi OpenVAS pentru detalii complete*"
        
        fields.append({
            "name": "🛠️ Soluție Recomandată",
            "value": f"*{sol_display}*",
            "inline": False
        })
    
    payload = {
        "content": "🚨 **VULNERABILITATE NOUĂ DETECTATĂ**" if not is_kev_exploited else "☠️ **CRITICAL KEV MATCH!**",
        "embeds": [{
            "title": f"🔍 {name[:200]}",
            "color": color,
            "fields": fields,
            "footer": {
                "text": "SOC OV2 Agent | B2 Mode | Enhanced Intel"
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }]
    }
    
    _discord_send(payload)

def send_startup_message():
    sursa = ("✅ Infisical API"
             if "DISCORD_WEBHOOK" in _SECRETS and os.environ.get("INFISICAL_CLIENT_ID")
             else "⚠️ Env vars")
    soar_status = "✅ ACTIV" if SOAR_LOADED else "❌ EROARE"
    _discord_send({"content": (
        "🟢 **SOC OV2 — SISTEM PORNIT (v2.1 - Anti-Phantom)**\n"
        f"Secrete: **{sursa}** ({len(_SECRETS)} incarcate)\n"
        f"Status SOAR: **{soar_status}**\n"
        f"⚡ Polling interval: **10s**\n"
        f"🛡️ Phantom alerts: **PREVENTED**"
    )})

# =====================================================================
# MODUL: MR. BENNY INTEGRATION
# =====================================================================
def authenticate_mrbenny():
    global MRBENNY_SESSION_TOKEN
    try:
        req_token = urllib.request.Request(
            f"{MRBENNY_BASE_URL}/install_tokens/generate",
            data=json.dumps({
                "agent_type": "OV2",
                "label": "SOC OV2 Master Ubuntu",
                "allowed_modes": ["B2"],
                "notes": "Auto-install"
            }).encode('utf-8'),
            headers={
                'X-Mrbenny-Mode': 'A',
                'X-Admin-Key': MRBENNY_ADMIN_KEY,
                'Content-Type': 'application/json'
            }
        )
        res_token     = json.loads(urllib.request.urlopen(req_token, timeout=10).read().decode())
        install_token = res_token["data"]["install_token"]

        req_sess = urllib.request.Request(
            f"{MRBENNY_BASE_URL}/auth/session",
            data=json.dumps({
                "agent_type": "OV2",
                "hardware_uuid": MRBENNY_HARDWARE_UUID,
                "install_token": install_token,
                "agent_version": "2.1",
                "host_label": "ov2-master"
            }).encode('utf-8'),
            headers={'X-Mrbenny-Mode': 'B2', 'Content-Type': 'application/json'}
        )
        res_sess = json.loads(urllib.request.urlopen(req_sess, timeout=10).read().decode())
        MRBENNY_SESSION_TOKEN = res_sess["data"]["session_token"]
        log_msg("[AUTH] ✅ Autentificare B2 REUSITA!")
        return True
    except Exception as e:
        log_err("[AUTH]", e)
        return False

def mrbenny_request(endpoint, method="GET", payload=None):
    if not MRBENNY_SESSION_TOKEN:
        return None
    url = f"{MRBENNY_BASE_URL}{endpoint}"
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'SOC-OV2-Agent/2.1',
        'X-Mrbenny-Mode': 'B2',
        'Authorization': f'Bearer {MRBENNY_SESSION_TOKEN}'
    }
    data = json.dumps(payload).encode('utf-8') if payload else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except:
        return None

def mrbenny_heartbeat_loop():
    while True:
        if MRBENNY_SESSION_TOKEN:
            uptime  = int(time.time() - AGENT_START_TIME)
            payload = {
                "client_event_id": f"hb-ov2-{int(time.time())}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "online",
                "metrics": {
                    "queue_size": DISCORD_QUEUE.qsize(),
                    "uptime_seconds": uptime,
                    "version": "2.1-antiphantom"
                }
            }
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
                        if ident.get("type") in ["ip", "ipv4", "ipv6"]:
                            new_map[ident.get("value")] = dev_id
                for k, v in LOCAL_DEVICE_MAP.items():
                    if k not in new_map:
                        new_map[k] = v
                LOCAL_DEVICE_MAP = new_map
        except:
            pass
        time.sleep(120)

MRBENNY_ID_QUEUE = queue.Queue()

def get_or_create_mrbenny_id(ip):
    if ip in LOCAL_DEVICE_MAP:
        return LOCAL_DEVICE_MAP[ip]
    LOCAL_DEVICE_MAP[ip] = "N/A"
    MRBENNY_ID_QUEUE.put(ip)
    return "N/A"

def mrbenny_id_worker():
    while True:
        try:
            ip = MRBENNY_ID_QUEUE.get(timeout=5)
            payload = {
                "client_event_id": f"ov2-boot-{uuid.uuid4().hex[:8]}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": "bootstrap_identify",
                "observations": [{
                    "observation_ref": f"obs-{ip.replace('.', '')}",
                    "identifiers": [{"type": "ip", "value": ip}]
                }]
            }
            res = mrbenny_request("/ingest/data", method="POST", payload=payload)
            if res and res.get("ok"):
                id_map = res.get("data", {}).get("id_map", {})
                if id_map:
                    LOCAL_DEVICE_MAP[ip] = list(id_map.values())[0]
            MRBENNY_ID_QUEUE.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            log_err("[MrBenny ID Worker]", e)

# =====================================================================
# ✅ FIX: VALIDARE REPORTS ACTIVI
# =====================================================================
def refresh_valid_reports_cache(gmp):
    """Refresh cache-ul de report IDs valide (non-trash)."""
    global VALID_REPORTS_CACHE, LAST_REPORTS_CHECK
    
    # Refresh la fiecare 60 secunde
    if time.time() - LAST_REPORTS_CHECK < 60:
        return
    
    try:
        reports = gmp.get_reports(filter_string="rows=-1 trash=0")
        new_cache = set()
        
        for report in reports.xpath('report'):
            report_id = report.get('id')
            if report_id:
                new_cache.add(report_id)
        
        VALID_REPORTS_CACHE = new_cache
        LAST_REPORTS_CHECK = time.time()
        log_msg(f"[REPORTS] 🔄 Cache refresh: {len(VALID_REPORTS_CACHE)} rapoarte active")
        
    except Exception as e:
        log_err("[REPORTS Cache]", e)

def is_result_from_valid_report(result_elem):
    """Verifică dacă rezultatul provine dintr-un raport valid (non-deleted)."""
    try:
        # Extrage report ID din structura result
        report = result_elem.find('.//report')
        if report is None:
            # Fallback: caută în părinte
            task = result_elem.find('.//task')
            if task is not None:
                last_report = task.find('.//last_report/report')
                if last_report is not None:
                    report = last_report
        
        if report is not None:
            report_id = report.get('id')
            if report_id:
                # Verifică în cache
                return report_id in VALID_REPORTS_CACHE
        
        # Dacă nu găsim report ID, acceptăm rezultatul (safe default)
        return True
        
    except Exception as e:
        # În caz de eroare, acceptăm rezultatul
        return True

# =====================================================================
# MODUL: OPENVAS SYNC - ENHANCED cu ANTI-PHANTOM
# =====================================================================
def fetch_cisa_kev():
    global CISA_KEV_LIST
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            CISA_KEV_LIST = {vuln["cveID"] for vuln in data.get("vulnerabilities", [])}
        log_msg(f"[KEV] ✅ {len(CISA_KEV_LIST)} CVE-uri KEV incarcate.")
    except Exception as e:
        log_err("[KEV]", e)

def run_soar_async(vuln_details):
    """SOAR async cu date extinse."""
    try:
        host = vuln_details['host']
        name = vuln_details['name']
        sev = vuln_details['sev']
        cve = vuln_details['cve']
        mb_id = vuln_details['mb_id']
        sol = vuln_details['solution']
        is_kev = vuln_details['is_kev']
        description = vuln_details.get('description', 'N/A')
        impact = vuln_details.get('impact', 'N/A')
        affected = vuln_details.get('affected', 'N/A')
        
        soar_action = None
        if SOAR_LOADED:
            soar_action = soar_engine.trigger_remediation(host, name)
        
        send_discord_alert_extended(
            host, name, str(sev), cve, (sev >= 7.0),
            mb_id, sol, is_kev, soar_action, 
            description, impact, affected
        )
        DEVICE_RISK.labels(ip=host).set(1)
    except Exception as e:
        log_err(f"[SOAR Async]", e)

def get_openvas_data():
    """✅ ENHANCED: Anti-phantom alerts - validare strictă reports."""
    global IS_FIRST_RUN
    connection = UnixSocketConnection(path=SOCKET_PATH, timeout=300.0)
    try:
        with Gmp(connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(GVMD_USER, GVMD_PASS)
            
            # ✅ Refresh cache reports valide
            refresh_valid_reports_cache(gmp)
            
            results = gmp.get_results(
                filter_string="rows=-1 ignore_pagination=1 trash=0 apply_overrides=1"
            )

            unique_high, unique_med, unique_low, unique_kev = set(), set(), set(), set()
            current_signatures = set()
            new_alerts_sorted = []
            
            skipped_phantom = 0  # Counter pentru rezultate phantom

            for res in results.xpath('result'):
                try:
                    # ✅ FIX PRINCIPAL: Validare raport activ
                    if not is_result_from_valid_report(res):
                        skipped_phantom += 1
                        continue  # SKIP - provine din raport șters
                    
                    host_elem = res.find('host')
                    host      = host_elem.text if host_elem is not None else "unknown"
                    if not host or host == "unknown":
                        continue

                    nvt_node = res.find('nvt')
                    oid      = nvt_node.get('oid')
                    name     = res.find('name').text or nvt_node.find('name').text
                    cve_node = nvt_node.find('cve')
                    cve      = cve_node.text if cve_node is not None else "N/A"
                    sev      = float(res.find('severity').text)
                    
                    # Extragere info detaliate
                    description_elem = res.find('description')
                    description = description_elem.text if description_elem is not None else ""
                    
                    sol = "Vezi OpenVAS pentru detalii"
                    impact = ""
                    affected = ""
                    
                    if description:
                        if "Solution:" in description:
                            parts = description.split("Solution:")
                            if len(parts) > 1:
                                sol_text = parts[1].split("\n\n")[0].strip()
                                sol_text = sol_text.replace("Solution type: ", "")
                                sol = sol_text[:500] if sol_text else "Nicio soluție specificată"
                        
                        if "Impact:" in description:
                            impact_parts = description.split("Impact:")
                            if len(impact_parts) > 1:
                                impact = impact_parts[1].split("\n\n")[0].strip()[:300]
                        
                        if "Affected Software/OS:" in description:
                            affected_parts = description.split("Affected Software/OS:")
                            if len(affected_parts) > 1:
                                affected = affected_parts[1].split("\n\n")[0].strip()[:200]
                        elif "Affected:" in description:
                            affected_parts = description.split("Affected:")
                            if len(affected_parts) > 1:
                                affected = affected_parts[1].split("\n\n")[0].strip()[:200]
                    
                    desc_summary = description[:250].replace("\n", " ").strip() if description else "N/A"
                    
                    sig = f"{host}|{oid}"

                    if sev >= 4.0:
                        current_signatures.add(sig)
                        if sev >= 7.0:
                            unique_high.add(sig)
                        else:
                            unique_med.add(sig)

                        is_kev = (cve in CISA_KEV_LIST and cve != "N/A")
                        if is_kev:
                            unique_kev.add(sig)

                        if sig not in ALREADY_ALERTED:
                            mb_id = get_or_create_mrbenny_id(host)
                            ALREADY_ALERTED[sig] = {
                                "host": host, "name": name,
                                "cve": cve,   "mrbenny_id": mb_id
                            }
                            if not IS_FIRST_RUN:
                                priority = 100 if is_kev else (10 if sev >= 7.0 else 1)
                                
                                vuln_details = {
                                    'host': host,
                                    'name': name,
                                    'sev': sev,
                                    'cve': cve,
                                    'mb_id': mb_id,
                                    'solution': sol,
                                    'is_kev': is_kev,
                                    'description': desc_summary,
                                    'impact': impact,
                                    'affected': affected
                                }
                                new_alerts_sorted.append((priority, vuln_details))

                    elif sev > 0:
                        unique_low.add(sig)
                        
                except Exception as parse_err:
                    log_err("[Parse Result]", parse_err)
                    continue

            # ✅ FIX: NU trimite alerte "resolved" pentru rezultate phantom
            # Doar curăță cache-ul ALREADY_ALERTED fără notificări
            resolved = set(ALREADY_ALERTED.keys()) - current_signatures
            if resolved and not IS_FIRST_RUN:
                log_msg(f"[OV] 🗑️ Cleanup: {len(resolved)} rezultate vechi eliminate din cache (fără alerte)")
                for s in resolved:
                    ALREADY_ALERTED.pop(s, None)
                    # NU trimitem send_discord_resolved - previne spam

            # Sortare și lansare SOAR
            new_alerts_sorted.sort(reverse=True, key=lambda x: x[0])
            
            for alert_data in new_alerts_sorted:
                priority = alert_data[0]
                vuln_details = alert_data[1]
                threading.Thread(
                    target=run_soar_async,
                    args=(vuln_details,),
                    daemon=True
                ).start()
                time.sleep(0.1)

            IS_FIRST_RUN = False
            VULN_HIGH.set(len(unique_high))
            VULN_MEDIUM.set(len(unique_med))
            VULN_LOW.set(len(unique_low))
            VULN_KEV.set(len(unique_kev))

            log_msg(f"[OV] 📊 H:{len(unique_high)} M:{len(unique_med)} L:{len(unique_low)} KEV:{len(unique_kev)} | Noi:{len(new_alerts_sorted)} | Phantom skip:{skipped_phantom}")

    except Exception as e:
        log_err("[OpenVAS]", e)

# =====================================================================
# MODUL: HIDS
# =====================================================================
QUARANTINE_LOCK     = threading.Lock()
atacatori_cunoscuti = {}

def execute_quarantine(ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=HOST_UBUNTU_IP, port=22,
            username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5
        )
        cmd_block = (
            f"echo '{HOST_UBUNTU_PASS}' | sudo -S iptables -I INPUT 1 "
            f"-p tcp --dport 22 -s {ip} -j DROP"
        )
        stdin, stdout, stderr = client.exec_command(cmd_block)
        exit_code = stdout.channel.recv_exit_status()
        client.close()
        if exit_code == 0:
            log_msg(f"[SOAR] 🧱 IP {ip} BLOCAT pe SSH. Deblocare in 60s.")
    except Exception as e:
        log_err(f"[SOAR] Blocare SSH {ip}", e)
        time.sleep(60)
        with QUARANTINE_LOCK:
            atacatori_cunoscuti[ip] = 0
        return

    time.sleep(60)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=HOST_UBUNTU_IP, port=22,
            username=HOST_UBUNTU_USER, password=HOST_UBUNTU_PASS, timeout=5
        )
        unblock_cmd = (
            f"echo '{HOST_UBUNTU_PASS}' | sudo -S sh -c "
            f"'while iptables -D INPUT -p tcp --dport 22 -s {ip} -j DROP 2>/dev/null; do true; done'"
        )
        stdin, stdout, stderr = client.exec_command(unblock_cmd)
        stdout.channel.recv_exit_status()
        client.close()
        log_msg(f"[SOAR] 🟢 IP {ip} DEBLOCAT dupa 60s.")
    except Exception as e:
        log_err(f"[SOAR] Deblocare SSH {ip}", e)
    finally:
        with QUARANTINE_LOCK:
            atacatori_cunoscuti[ip] = 0

def monitor_hids_logs():
    log_file = "/host_logs/auth.log"
    while not os.path.exists(log_file):
        time.sleep(5)
    log_msg(f"[HIDS] ✅ Monitorizare activa pe {log_file}")

    f = open(log_file, "r", errors="replace")
    f.seek(0, os.SEEK_END)

    fail_patterns = [
        re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+) port'),
        re.compile(r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)'),
        re.compile(r'error: maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)')
    ]

    WHITELIST_EXACTE  = {"192.168.128.181", "127.0.0.1", "::1"}
    WHITELIST_PREFIXE = ["172.17.", "172.18.", "172.19.", "10.0."]

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
            if m_ip:
                ip = m_ip.group(1)

        if not ip:
            continue
        if ip in WHITELIST_EXACTE or any(ip.startswith(p) for p in WHITELIST_PREFIXE):
            continue

        with QUARANTINE_LOCK:
            stare_curenta = atacatori_cunoscuti.get(ip, 0)
            if stare_curenta == "BLOCKED":
                continue

            inc = 1
            if "repeated" in line:
                rm = re.search(r'repeated (\d+) times', line)
                if rm:
                    inc = int(rm.group(1))

            nou_count = stare_curenta + inc
            log_msg(f"[HIDS] ⚠️ Tentativa SSH de la {ip} ({nou_count}/3)")

            if nou_count >= 3:
                atacatori_cunoscuti[ip] = "BLOCKED"
                mb_id = get_or_create_mrbenny_id(ip)
                
                vuln_details = {
                    'host': "Ubuntu Host",
                    'name': "SSH Brute Force (HIDS)",
                    'sev': 10.0,
                    'cve': "N/A",
                    'mb_id': mb_id,
                    'solution': f"IP {ip} blocat automat 60s",
                    'is_kev': False,
                    'description': f"Detectate {nou_count} tentative SSH esuate",
                    'impact': "Acces neautorizat potential la sistem",
                    'affected': f"SSH port 22 de la {ip}"
                }
                
                send_discord_alert_extended(
                    vuln_details['host'],
                    vuln_details['name'],
                    str(vuln_details['sev']),
                    vuln_details['cve'],
                    True,
                    vuln_details['mb_id'],
                    vuln_details['solution'],
                    False,
                    f"🛡️ SOAR ACTIV: Blocare automată {ip}",
                    vuln_details['description'],
                    vuln_details['impact'],
                    vuln_details['affected']
                )
                
                threading.Thread(target=execute_quarantine, args=(ip,), daemon=True).start()
            else:
                atacatori_cunoscuti[ip] = nou_count

# =====================================================================
# MAIN
# =====================================================================
if __name__ == '__main__':
    authenticate_mrbenny()

    threading.Thread(target=discord_worker,         daemon=True).start()
    threading.Thread(target=mrbenny_id_worker,      daemon=True).start()
    threading.Thread(target=mrbenny_heartbeat_loop, daemon=True).start()
    threading.Thread(target=mrbenny_ontology_loop,  daemon=True).start()
    threading.Thread(target=monitor_hids_logs,      daemon=True).start()

    fetch_cisa_kev()
    send_startup_message()

    try:
        start_http_server(8000)
        log_msg("[PROMETHEUS] ✅ Server HTTP pornit pe :8000")
    except Exception as e:
        log_err("[PROMETHEUS]", e)

    log_msg("[MAIN] ⚡ Loop principal pornit (interval 10s) - Anti-Phantom ACTIVE")
    loop = 0
    while True:
        get_openvas_data()

        if loop % 2160 == 0 and loop > 0:
            fetch_cisa_kev()

        loop += 1
        time.sleep(10)
