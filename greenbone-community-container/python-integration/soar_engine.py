import paramiko
import time

# =====================================================================
# CONFIGURARE RETEA — PC NOU
# =====================================================================
VALID_TRIGGER_IPS = [
    "172.17.0.1",       # Gateway bridge docker0
    "172.17.0.2",       # Metasploitable2 direct
    "172.19.0.1",       # Gateway bridge retea Greenbone (NOU)
    "192.168.128.181",  # Ubuntu host fizic PC nou
]

# === Conectare DIRECTA la Metasploitable2 ===
SSH_HOST    = "192.168.128.181"
SSH_PORT    = 2222
TARGET_USER = "msfadmin"
TARGET_PASS = "msfadmin"

# =====================================================================
# FUNCTII SOAR
# =====================================================================
def log_soar(msg):
    print(msg, flush=True)

def verify_ftp_stopped(client):
    """Verifica daca portul 21 mai este deschis ascultand conexiuni."""
    stdin, stdout, stderr = client.exec_command("netstat -tuln | grep ':21 '")
    output = stdout.read().decode('utf-8')
    return output.strip() == ""

def execute_ftp_mitigation(target_ip):
    log_soar(f"[SOAR] 🛡️ INITIERE PROTOCOL: Oprire Port 21 pe {target_ip}")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT,
            username=TARGET_USER,
            password=TARGET_PASS,
            timeout=10,
            disabled_algorithms={'pubkeys': []}
        )

        if verify_ftp_stopped(client):
            log_soar(f"[SOAR] ℹ️ Portul 21 este deja blocat pe {target_ip}.")
            client.close()
            return "✅ **STATUT:** Portul 21 (FTP) este deja inactiv pe Metasploitable2."

        log_soar("[SOAR] ⚙️ Lansare comenzi AGRESIVE de mitigare pe Metasploitable2...")

        mitigation_commands = [
            f"echo '{TARGET_PASS}' | sudo -S service vsftpd stop",
            f"echo '{TARGET_PASS}' | sudo -S service proftpd stop",
            f"echo '{TARGET_PASS}' | sudo -S killall -9 vsftpd proftpd inetd xinetd",
            f"echo '{TARGET_PASS}' | sudo -S fuser -k -9 21/tcp",
            f"echo '{TARGET_PASS}' | sudo -S lsof -t -i:21 | xargs -r sudo kill -9" # GLONTUL DE ARGINT
        ]

        for cmd in mitigation_commands:
            try:
                client.exec_command(cmd)
                time.sleep(0.5)
            except Exception as cmd_err:
                log_soar(f"[SOAR] ⚠️ Comanda esuata (continuam): {cmd_err}")

        time.sleep(3) # Asteptam nitel sa se elibereze portul

        if verify_ftp_stopped(client):
            log_soar(f"[SOAR] ✅ CONFIRMAT: Portul 21 eliberat pe {target_ip}.")
            client.close()
            return (
                "🛡️ **SOAR MITIGARE REUSITA:**\n"
                f"Procesele de pe portul 21 (FTP) au fost oprite pe `{target_ip}` "
                "pentru a bloca atacul Brute Force."
            )
        else:
            client.close()
            log_soar(f"[SOAR] ❌ Portul 21 refuza sa se inchida pe {target_ip}.")
            return "❌ **SOAR EROARE:** Portul 21 refuza sa se inchida. Interventie manuala necesara."

    except Exception as e:
        msg = f"⚠️ **SOAR ESEC TEHNIC:** {type(e).__name__}: {str(e)}"
        log_soar(f"[SOAR] {msg}")
        return msg

def trigger_remediation(ip_sursa_alerta, vuln_name):
    vuln_lower = vuln_name.lower()
    log_soar(f"[SOAR] 🔍 Evaluare: ip={ip_sursa_alerta} | vuln={vuln_name[:60]}")

    if ip_sursa_alerta not in VALID_TRIGGER_IPS:
        log_soar(f"[SOAR] ⏭️ IP {ip_sursa_alerta} nu e in VALID_TRIGGER_IPS. Ignorat.")
        return None

    if "ftp brute force logins with default credentials reporting" in vuln_lower:
        log_soar(f"[SOAR] 🎯 TINTA CONFIRMATA: FTP Brute Force pe {ip_sursa_alerta}!")
        return execute_ftp_mitigation(ip_sursa_alerta)

    elif "ftp" in vuln_lower:
        log_soar("[SOAR] ℹ️ Alerta FTP minora ignorata.")
        return None

    elif "ssh" in vuln_lower:
        log_soar("[SOAR] 🔒 Politica SSH: automatizarea dezactivata (Anti-Lockout).")
        return "🛡️ **POLITICA SOAR:** Automatizarea pe portul 22 dezactivata (Anti-Lockout)."

    return None

