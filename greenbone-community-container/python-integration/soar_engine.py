import paramiko
import time

# =====================================================================
# CONFIGURARE RETEA
# =====================================================================
VALID_TRIGGER_IPS = [
    "172.17.0.1", "172.17.0.2", "172.19.0.1", 
    "192.168.128.181", "172.19.0.100"
]

SSH_HOST    = "172.19.0.100"
SSH_PORT    = 22
TARGET_USER = "msfadmin"
TARGET_PASS = "msfadmin"

# =====================================================================
# FUNCTII SOAR
# =====================================================================
def log_soar(msg):
    print(msg, flush=True)

def verify_ftp_stopped(client):
    stdin, stdout, stderr = client.exec_command("netstat -tuln | grep ':21 '")
    return stdout.read().decode('utf-8').strip() == ""

def execute_ftp_mitigation(target_ip):
    log_soar(f"[SOAR] 🛡️ INITIERE PROTOCOL: Oprire Port 21 pe {target_ip}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conexiune perfect compatibila datorita paramiko==2.11.0
        client.connect(
            hostname=SSH_HOST, port=SSH_PORT,
            username=TARGET_USER, password=TARGET_PASS,
            timeout=10, look_for_keys=False, allow_agent=False
        )

        if verify_ftp_stopped(client):
            log_soar(f"[SOAR] ℹ️ Portul 21 este deja inactiv.")
            client.close()
            return "✅ **STATUT:** Portul 21 (FTP) este deja inactiv pe Metasploitable2."

        log_soar("[SOAR] ⚙️ Lansare comenzi AGRESIVE de mitigare pe Metasploitable2...")
        
        # Comanda combinata pentru a forta oprirea oricarui serviciu FTP
        kill_cmd = f"echo '{TARGET_PASS}' | sudo -S sh -c 'fuser -k -9 21/tcp; killall -9 vsftpd proftpd inetd xinetd; /etc/init.d/vsftpd stop'"
        
        try:
            stdin, stdout, stderr = client.exec_command(kill_cmd)
            stdout.channel.recv_exit_status() 
        except Exception as cmd_err:
            log_soar(f"[SOAR] ⚠️ Comanda esuata (continuam): {cmd_err}")

        time.sleep(4) 

        if verify_ftp_stopped(client):
            log_soar(f"[SOAR] ✅ CONFIRMAT: Portul 21 eliberat pe {target_ip}.")
            client.close()
            return (
                "🛡️ **SOAR MITIGARE REUSITA:**\n"
                f"Procesele FTP au fost oprite pe `{target_ip}` pentru a bloca atacul."
            )
        else:
            client.close()
            log_soar(f"[SOAR] ❌ Portul 21 refuza sa se inchida pe {target_ip}.")
            return "❌ **SOAR EROARE:** Portul 21 refuza sa se inchida."

    except Exception as e:
        msg = f"⚠️ **SOAR ESEC TEHNIC:** {type(e).__name__}: {str(e)}"
        log_soar(f"[SOAR] {msg}")
        return msg

def trigger_remediation(ip_sursa_alerta, vuln_name):
    vuln_lower = vuln_name.lower()
    log_soar(f"[SOAR] 🔍 Evaluare: ip={ip_sursa_alerta} | vuln={vuln_name[:60]}")

    if ip_sursa_alerta not in VALID_TRIGGER_IPS:
        log_soar(f"[SOAR] ⏭️ IP {ip_sursa_alerta} ignorat (nu e in lista VALID_TRIGGER_IPS).")
        return None

    if "ftp" in vuln_lower and ("brute force" in vuln_lower or "default credentials" in vuln_lower):
        log_soar(f"[SOAR] 🎯 TINTA CONFIRMATA: FTP Brute Force pe {ip_sursa_alerta}!")
        return execute_ftp_mitigation(ip_sursa_alerta)
    elif "ftp" in vuln_lower:
        return None
    elif "ssh" in vuln_lower:
        return "🛡️ **POLITICA SOAR:** Automatizarea pe portul 22 dezactivata."
    
    return None
