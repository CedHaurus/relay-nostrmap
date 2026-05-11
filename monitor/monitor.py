#!/usr/bin/env python3
"""
Nostr Map Relay — Système de monitoring
Envoie des rapports et alertes en DM Nostr chiffré (NIP-04)
Adapté pour stack native systemd (strfry binaire + DB /var/lib/strfry/)
"""

import os
import sys
import json
import time
import subprocess
import psutil
from datetime import datetime, timezone
from pathlib import Path

try:
    from pynostr.key import PrivateKey, PublicKey
    from pynostr.encrypted_dm import EncryptedDirectMessage
    from pynostr.event import Event
    from pynostr.relay_manager import RelayManager
except ImportError:
    print("ERREUR: pynostr non installé. Lancez: pip3 install pynostr --break-system-packages")
    sys.exit(1)

# ─── Configuration ────────────────────────────────────────────────────────────

KEYS_FILE  = "/etc/strfry/monitor/keys.json"
STATE_FILE = "/etc/strfry/monitor/state.json"
LOG_FILE   = "/var/log/strfry-monitor.log"

# Relays pour envoyer les DMs (fallback si le relay principal est down)
DM_RELAYS = [
    "wss://relay.nostrmap.net",
    "wss://relay.damus.io",
    "wss://nos.lol",
]

STRFRY_DB   = "/var/lib/strfry/"
CADDY_LOG   = "/var/log/caddy/relay-access.log"
STRFRY_CONF = "/etc/strfry/strfry.conf"

# Seuils d'alerte
DISK_WARN        = 80
DISK_CRITICAL    = 90
RAM_WARN         = 85
CONN_WARN        = 500
REJECT_RATE_WARN = 50
SSH_BRUTE_WARN   = 100
FLOOD_MULTIPLIER = 10

# Anti-spam : délai minimum entre deux alertes du même type (secondes)
ALERT_COOLDOWN = {
    "strfry_down":  300,
    "caddy_down":   300,
    "disk_warn":    3600,
    "disk_crit":    1800,
    "ram_warn":     3600,
    "conn_warn":    1800,
    "reject_warn":  3600,
    "flood":        3600,
    "restarts":     1800,
    "oom":          1800,
    "isolated":     3600,
    "tls_warn":     86400,
    "ssh_brute":    3600,
    "fail2ban":     3600,
    "backup":       21600,
}

# ─── Utilitaires ──────────────────────────────────────────────────────────────

def load_keys():
    with open(KEYS_FILE) as f:
        return json.load(f)

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{now_str()}] {msg}\n")

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

def cooldown_ok(state, key):
    """Retourne True si l'alerte peut être renvoyée (cooldown écoulé)."""
    last = state.get(f"alert_last_{key}", 0)
    delay = ALERT_COOLDOWN.get(key, 3600)
    return (time.time() - last) >= delay

def mark_alert_sent(state, key):
    state[f"alert_last_{key}"] = time.time()

# ─── Envoi DM Nostr ───────────────────────────────────────────────────────────

def _ws_send_event(host: str, port: int, event_dict: dict, timeout: int = 8) -> bool:
    """Envoi bas niveau d'un event Nostr via WebSocket (sans dépendance RelayManager)."""
    import ssl, socket, base64, os as _os
    ctx = ssl.create_default_context()
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    try:
        ws_key = base64.b64encode(_os.urandom(16)).decode()
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n")
        sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += sock.recv(1024)
        if b"101" not in resp:
            return False

        payload = json.dumps(["EVENT", event_dict]).encode()
        if len(payload) < 126:
            frame = bytes([0x81, 0x80 | len(payload)])
        else:
            frame = bytes([0x81, 0x80 | 126, len(payload) >> 8, len(payload) & 0xff])
        mask = _os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        sock.sendall(frame + mask + masked)

        sock.settimeout(4)
        try:
            data = sock.recv(4096)
            if data and data[0] & 0x0f == 1:
                plen = data[1] & 0x7f
                body = data[2:2 + plen].decode(errors="replace")
                parsed = json.loads(body)
                return parsed[0] == "OK" and parsed[2] is True
        except Exception:
            pass
        return True  # event envoyé, pas de réponse OK explicite
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_dm(message: str, keys: dict) -> bool:
    try:
        private_key = PrivateKey.from_nsec(keys["nsec_relay"])
        recipient_pubkey = PublicKey.from_npub(keys["npub_operator"]).hex()

        dm = EncryptedDirectMessage(
            recipient_pubkey=recipient_pubkey,
            cleartext_content=message,
        )
        dm.encrypt(private_key.hex())
        event = dm.to_event()
        event.sign(private_key.hex())
        event_dict = event.to_dict()

        sent_count = 0
        for relay_url in DM_RELAYS:
            try:
                host = relay_url.replace("wss://", "").replace("ws://", "").rstrip("/")
                port = 443 if relay_url.startswith("wss://") else 80
                if _ws_send_event(host, port, event_dict):
                    log(f"DM envoyé via {relay_url}")
                    sent_count += 1
                else:
                    log(f"Relay {relay_url} n'a pas confirmé")
            except Exception as e:
                log(f"Échec relay {relay_url}: {e}")

        if sent_count == 0:
            log(f"ERREUR: tous les relays ont échoué. Message: {message[:200]}")
            return False
        return True

    except Exception as e:
        log(f"ERREUR send_dm: {e}")
        log(f"Message non envoyé: {message[:200]}")
        return False

# ─── Collecte des métriques ───────────────────────────────────────────────────

def get_disk():
    usage = psutil.disk_usage("/")
    return {
        "total_gb": round(usage.total / 1e9, 1),
        "used_gb":  round(usage.used  / 1e9, 1),
        "pct":      usage.percent,
    }

def get_db_size():
    try:
        size = sum(f.stat().st_size for f in Path(STRFRY_DB).rglob("*") if f.is_file())
        return round(size / 1e9, 3)
    except Exception:
        return -1

def get_ram():
    m = psutil.virtual_memory()
    return {
        "total_gb": round(m.total / 1e9, 1),
        "used_gb":  round(m.used  / 1e9, 1),
        "pct":      m.percent,
    }

def get_cpu():
    return psutil.cpu_percent(interval=3)

def get_load():
    return round(psutil.getloadavg()[0], 2)

def get_container_status(name):
    """Vérifie si l'unité systemd est active (stack bare metal)."""
    rc = subprocess.call(["systemctl", "is-active", "--quiet", name])
    return rc == 0

def get_container_restarts(name):
    out = run(f"systemctl show -p NRestarts --value {name}")
    try:
        return int(out)
    except ValueError:
        return 0

def get_connections():
    """Connexions actives sur le port 443 (côté Caddy)."""
    out = run("ss -tn | grep ':443' | grep ESTAB | wc -l")
    try:
        return int(out)
    except ValueError:
        return 0

def get_events_count():
    """Nombre d'events dans la DB strfry (binaire local)."""
    out = run("/usr/local/bin/strfry --config /etc/strfry/strfry.conf scan '{}' 2>/dev/null | wc -l")
    try:
        return int(out)
    except ValueError:
        return -1

def get_reject_rate():
    """Taux de rejet abusif depuis journalctl strfry sur 1h.
    Filtre cote journald (--grep) pour eviter de scanner tout le log.
    Compte 'Inserted event' = accepte. Exclut les rejets NORMAUX strfry
    (ephemeral expired, duplicate, replaced) qui ne sont pas du spam."""
    accepted = run(
        "journalctl -u strfry --since '1h ago' --no-pager --grep 'Inserted event' 2>/dev/null | wc -l"
    )
    rejected = run(
        "journalctl -u strfry --since '1h ago' --no-pager --grep 'Rejected' 2>/dev/null "
        "| grep -vE 'ephemeral event expired|duplicate: have this event|replaced: have newer event' "
        "| wc -l"
    )
    try:
        a = int(accepted); r = int(rejected)
    except ValueError:
        return 0
    total = a + r
    if total == 0:
        return 0
    return round(r / total * 100, 1)

def get_top_pubkeys(n=5):
    """Top N pubkeys actives sur 12h via strfry export (streaming, sans charger les logs)."""
    import subprocess, json, time
    from collections import Counter
    since_ts = int(time.time()) - 43200
    cmd = ["/usr/local/bin/strfry", "--config", "/etc/strfry/strfry.conf",
           "export", f"--since={since_ts}"]
    counts = Counter()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                pk = json.loads(line).get("pubkey")
                if pk:
                    counts[pk] += 1
            except Exception:
                continue
        proc.stdout.close()
        proc.wait()
    except Exception:
        return "—"
    if not counts:
        return "—"
    top = counts.most_common(n)
    return "\n".join(f"  {pk[:16]}… ({count})" for pk, count in top)

def get_ssh_failures():
    out = run("journalctl _SYSTEMD_UNIT=ssh.service --since '1 hour ago' --no-pager 2>/dev/null | grep -c 'Failed password'")
    try:
        return int(out)
    except ValueError:
        return 0

def get_recent_inserts(window_minutes: int = 15):
    """Compte les events 'Inserted event' dans les N dernieres minutes."""
    out = run(
        f"journalctl -u strfry --since '{window_minutes}min ago' --no-pager 2>/dev/null "
        f"| grep -c 'Inserted event'"
    )
    try:
        return int(out)
    except ValueError:
        return 0

def get_last_backup_status():
    """Retourne (heures_depuis_dernier_backup_ok, ok_bool).
    Lit /var/log/server-backup.log pour 'FIN BACKUP OK'."""
    out = run("grep 'FIN BACKUP OK' /var/log/server-backup.log 2>/dev/null | tail -1")
    if not out:
        return (-1, False)
    # Format: [2026-05-02 04:01:21] === FIN BACKUP OK ===
    import re
    m = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', out)
    if not m:
        return (-1, False)
    try:
        last = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        delta_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
        return (round(delta_hours, 1), True)
    except Exception:
        return (-1, False)

def get_tls_expiry():
    out = run(
        "echo | openssl s_client -connect relay.nostrmap.net:443 "
        "-servername relay.nostrmap.net 2>/dev/null "
        "| openssl x509 -noout -enddate 2>/dev/null"
    )
    if not out:
        return -1
    try:
        date_str = out.split("=")[1].strip()
        expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except Exception:
        return -1

def get_uptime():
    return run("uptime -p") or "inconnu"

def get_banned_ips():
    """IPs actuellement bannies par fail2ban."""
    ssh_banned = run("fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $NF}'") or "0"
    caddy_banned = run("fail2ban-client status caddy-bad-requests 2>/dev/null | grep 'Currently banned' | awk '{print $NF}'") or "0"
    return int(ssh_banned), int(caddy_banned)

# ─── Rapport 12h ──────────────────────────────────────────────────────────────

def build_report(state):
    disk     = get_disk()
    ram      = get_ram()
    cpu      = get_cpu()
    load     = get_load()
    db_size  = get_db_size()
    events   = get_events_count()
    conns    = get_connections()
    rejects  = get_reject_rate()
    tls_days = get_tls_expiry()
    restarts_strfry = get_container_restarts("strfry")
    restarts_caddy  = get_container_restarts("caddy")
    top_keys = get_top_pubkeys()
    uptime   = get_uptime()
    ssh_fail = get_ssh_failures()
    banned_ssh, banned_caddy = get_banned_ips()

    strfry_ok = "✅" if get_container_status("strfry") else "❌"
    caddy_ok  = "✅" if get_container_status("caddy")  else "❌"

    disk_flag = " ⚠️" if disk["pct"] >= DISK_WARN else ""
    ram_flag  = " ⚠️" if ram["pct"]  >= RAM_WARN  else ""
    tls_flag  = " ⚠️" if 0 < tls_days < 14        else ""

    msg = f"""📊 Rapport relay.nostrmap.net
{now_str()}

🖥 Système
• Uptime : {uptime}
• CPU : {cpu}%  |  Load 1min : {load}
• RAM : {ram['used_gb']} / {ram['total_gb']} GB ({ram['pct']}%){ram_flag}
• Disque : {disk['used_gb']} / {disk['total_gb']} GB ({disk['pct']}%){disk_flag}

⚡ Relay
• strfry : {strfry_ok}  |  Caddy : {caddy_ok}
• DB strfry : {db_size} GB
• Events total : {events}
• Connexions actives (443) : {conns}
• Taux de rejet (12h) : {rejects}%
• Redémarrages strfry : {restarts_strfry}  |  Caddy : {restarts_caddy}

🔐 Sécurité
• Cert TLS expire dans : {tls_days} jours{tls_flag}
• Tentatives SSH échouées (1h) : {ssh_fail}
• IPs bannies — SSH : {banned_ssh}  |  Caddy : {banned_caddy}

👤 Top pubkeys actives (12h)
{top_keys}"""

    new_state = {
        "events_last": events,
        "restarts_strfry_last": restarts_strfry,
        "restarts_caddy_last":  restarts_caddy,
    }
    return msg, new_state

# ─── Alertes immédiates ───────────────────────────────────────────────────────

def check_alerts(state, keys):
    alerts_sent = 0

    # strfry down
    if not get_container_status("strfry") and cooldown_ok(state, "strfry_down"):
        logs = run("journalctl -u strfry --no-pager -n 20 2>&1")
        send_dm(f"🚨 ALERTE : strfry est DOWN\n\nDerniers logs :\n{logs[-800:]}", keys)
        mark_alert_sent(state, "strfry_down")
        alerts_sent += 1

    # Caddy down
    if not get_container_status("caddy") and cooldown_ok(state, "caddy_down"):
        send_dm("🚨 ALERTE : Caddy est DOWN — relay inaccessible", keys)
        mark_alert_sent(state, "caddy_down")
        alerts_sent += 1

    # Disque
    disk = get_disk()
    if disk["pct"] >= DISK_CRITICAL and cooldown_ok(state, "disk_crit"):
        send_dm(f"🚨 DISQUE CRITIQUE : {disk['pct']}% ({disk['used_gb']}/{disk['total_gb']} GB)", keys)
        mark_alert_sent(state, "disk_crit")
        alerts_sent += 1
    elif disk["pct"] >= DISK_WARN and cooldown_ok(state, "disk_warn"):
        send_dm(f"⚠️ Disque à {disk['pct']}% ({disk['used_gb']}/{disk['total_gb']} GB)", keys)
        mark_alert_sent(state, "disk_warn")
        alerts_sent += 1

    # RAM
    ram = get_ram()
    if ram["pct"] >= RAM_WARN and cooldown_ok(state, "ram_warn"):
        send_dm(f"⚠️ RAM à {ram['pct']}% ({ram['used_gb']}/{ram['total_gb']} GB)", keys)
        mark_alert_sent(state, "ram_warn")
        alerts_sent += 1

    # Connexions flood
    conns = get_connections()
    if conns >= CONN_WARN and cooldown_ok(state, "conn_warn"):
        send_dm(f"⚠️ {conns} connexions simultanées — possible flood", keys)
        mark_alert_sent(state, "conn_warn")
        alerts_sent += 1

    # Taux de rejet
    rejects = get_reject_rate()
    if rejects >= REJECT_RATE_WARN and cooldown_ok(state, "reject_warn"):
        send_dm(f"⚠️ Taux de rejet {rejects}% — vérifier policy.py", keys)
        mark_alert_sent(state, "reject_warn")
        alerts_sent += 1

    # Flood d'events
    events_now = get_events_count()
    events_last = state.get("events_last", 0)
    if events_last > 0 and events_now > events_last * FLOOD_MULTIPLIER and cooldown_ok(state, "flood"):
        delta = events_now - events_last
        send_dm(f"⚠️ Flood détecté — +{delta} events depuis le dernier rapport", keys)
        mark_alert_sent(state, "flood")
        alerts_sent += 1

    # Redémarrages inattendus strfry
    # NRestarts (systemd) est peu fiable car remis a 0 par certains kills externes.
    # On utilise journalctl + count des "Started strfry.service" sur 1h, soustrait 1 pour le 1er start.
    starts_1h = run("journalctl -u strfry --since '1h ago' --no-pager 2>/dev/null | grep -c 'Started strfry.service'")
    try:
        starts_1h = max(0, int(starts_1h) - 1)
    except ValueError:
        starts_1h = 0
    if starts_1h >= 1 and cooldown_ok(state, "restarts"):
        logs = run("journalctl -u strfry --no-pager -n 15 2>&1")
        send_dm(f"⚠️ strfry a redémarré {starts_1h} fois sur la dernière heure\n\nDerniers logs :\n{logs[-500:]}", keys)
        mark_alert_sent(state, "restarts")
        alerts_sent += 1

    # OOM-kill du processus strfry (kernel)
    # Le kernel logue 'Out of memory: Killed process ... (strfry)' sur OOM global.
    oom_count = run("journalctl -k --since '15m ago' --no-pager 2>/dev/null | grep -c 'Killed process.*(strfry)'")
    try:
        oom_count = int(oom_count)
    except ValueError:
        oom_count = 0
    if oom_count > 0 and cooldown_ok(state, "oom"):
        send_dm(f"🚨 OOM-KILL : strfry a été tué par le kernel {oom_count} fois sur 15 min.\nLa RAM systeme est saturee. Verifier MemoryHigh/MemoryMax + swap.", keys)
        mark_alert_sent(state, "oom")
        alerts_sent += 1

    # TLS expiration
    tls_days = get_tls_expiry()
    if 0 < tls_days < 14 and cooldown_ok(state, "tls_warn"):
        send_dm(f"⚠️ Certificat TLS expire dans {tls_days} jours — vérifier Caddy", keys)
        mark_alert_sent(state, "tls_warn")
        alerts_sent += 1

    # Brute force SSH
    ssh_fail = get_ssh_failures()
    if ssh_fail >= SSH_BRUTE_WARN and cooldown_ok(state, "ssh_brute"):
        send_dm(f"🚨 {ssh_fail} tentatives SSH échouées en 1h — brute force en cours", keys)
        mark_alert_sent(state, "ssh_brute")
        alerts_sent += 1

    # Relay isole : strfry actif mais ne recoit RIEN (events stagnants ET 0 conn)
    # Symptome : DNS cassé, IP bannie ailleurs, route reseau perdue, etc.
    if get_container_status("strfry"):
        recent_inserts = get_recent_inserts(window_minutes=15)
        conns = get_connections()
        if recent_inserts == 0 and conns == 0 and cooldown_ok(state, "isolated"):
            send_dm(
                "🚨 RELAY ISOLE : strfry actif mais 0 events reçus et 0 connexions "
                "sur 15 min. Verifier DNS, firewall, route reseau, IP non bannie ailleurs.",
                keys,
            )
            mark_alert_sent(state, "isolated")
            alerts_sent += 1

    # fail2ban down
    if not get_container_status("fail2ban") and cooldown_ok(state, "fail2ban"):
        send_dm("⚠️ fail2ban est DOWN — protection brute-force inactive", keys)
        mark_alert_sent(state, "fail2ban")
        alerts_sent += 1

    # Backup vieillissant : pas de "FIN BACKUP OK" depuis > 25h
    backup_age, backup_ok = get_last_backup_status()
    if backup_ok and backup_age > 25 and cooldown_ok(state, "backup"):
        send_dm(
            f"⚠️ Aucun backup réussi depuis {backup_age}h. "
            f"Verifier /var/log/server-backup.log et le cron /etc/cron.d/server-backup.",
            keys,
        )
        mark_alert_sent(state, "backup")
        alerts_sent += 1

    if alerts_sent == 0:
        log(f"Alertes vérifiées — RAS")
    else:
        log(f"Alertes vérifiées — {alerts_sent} alerte(s) envoyée(s)")

    return alerts_sent

# ─── Point d'entrée ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: monitor.py [report|alert|test]")
        sys.exit(1)

    mode = sys.argv[1]
    keys = load_keys()

    if keys.get("nsec_relay") == "NSEC_A_RENSEIGNER":
        print("=" * 60)
        print("ACTION REQUISE")
        print("=" * 60)
        print("La nsec_relay n'a pas été renseignée.")
        print("Éditez le fichier : /etc/strfry/monitor/keys.json")
        print('Remplacez "NSEC_A_RENSEIGNER" par la nsec correspondant à :')
        print(f"  {keys['npub_relay']}")
        print("=" * 60)
        sys.exit(1)

    state = load_state()

    if mode == "test":
        # Envoie un DM de test sans toucher à l'état
        msg = f"🔧 Test monitoring relay.nostrmap.net\n{now_str()}\nSi tu reçois ce message, le système fonctionne."
        ok = send_dm(msg, keys)
        print("DM test envoyé ✅" if ok else "Échec envoi DM ❌ — voir /var/log/strfry-monitor.log")

    elif mode == "report":
        msg, new_state = build_report(state)
        state.update(new_state)
        save_state(state)
        ok = send_dm(msg, keys)
        print("Rapport envoyé ✅" if ok else "Échec envoi ❌")
        print(msg)

    elif mode == "alert":
        check_alerts(state, keys)
        save_state(state)
        print("Alertes vérifiées.")

if __name__ == "__main__":
    main()
