#!/usr/bin/env python3
"""
Nostr Map Relay — Publication de stats publiques
Publie une note kind 1 quotidienne sur le compte du relay
"""

import json
import time
import os
import ssl
import socket
import base64
import subprocess
import argparse
from datetime import datetime, timezone
from typing import Iterator

try:
    from pynostr.key import PrivateKey
    from pynostr.event import Event, EventKind
except ImportError:
    print("ERREUR: pynostr non installé")
    exit(1)

# ─── Configuration ────────────────────────────────────────────────────────────

KEYS_FILE  = "/etc/strfry/monitor/keys.json"
STATE_FILE = "/etc/strfry/monitor/state.json"
PUBLISH_RELAYS = [
    "wss://relay.nostrmap.net",
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
]
HUMAN_ACTIVITY_KINDS = {1, 6, 7, 20, 1111, 30023, 9802}

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

def run(cmd):
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        return ""

def iter_events_since(since_ts: int) -> Iterator[dict]:
    """Parcourt les events JSONL de strfry depuis un timestamp Unix donné."""
    cmd = [
        "/usr/local/bin/strfry",
        "--config",
        "/etc/strfry/strfry.conf",
        "export",
        f"--since={since_ts}",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return

    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
    finally:
        proc.stdout.close()
        proc.wait()

def is_strfry_active() -> bool:
    """Indique si strfry est actuellement actif (systemd)."""
    return subprocess.call(
        ["systemctl", "is-active", "--quiet", "strfry"]
    ) == 0

# ─── Envoi WebSocket direct (sans RelayManager) ───────────────────────────────

def _ws_publish(host: str, event_dict: dict, timeout: int = 8) -> bool:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((host, 443), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    try:
        ws_key = base64.b64encode(os.urandom(16)).decode()
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
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        sock.sendall(frame + mask + masked)

        sock.settimeout(4)
        try:
            data = sock.recv(4096)
            if data and data[0] & 0x0f == 1:
                plen = data[1] & 0x7f
                body = json.loads(data[2:2 + plen].decode(errors="replace"))
                return body[0] == "OK" and body[2] is True
        except Exception:
            pass
        return True
    finally:
        try:
            sock.close()
        except Exception:
            pass

# ─── Collecte des métriques ───────────────────────────────────────────────────

def collect_24h_stats():
    """Un seul scan strfry, calcule en streaming : nombre d'events, pubkeys
    distinctes vues, pubkeys distinctes actives (activité humaine).
    Materialiser la liste complete saturait la RAM en periode de flood 1059."""
    since_ts = int(time.time()) - 86400
    count = 0
    seen = set()
    active = set()
    for event in iter_events_since(since_ts):
        count += 1
        pk = event.get("pubkey")
        if not pk:
            continue
        seen.add(pk)
        if event.get("kind") in HUMAN_ACTIVITY_KINDS:
            active.add(pk)
    return count, len(seen), len(active)

def format_duration(seconds):
    """Durée lisible, limitée aux jours/heures/minutes."""
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60

    parts = []
    if days:
        parts.append(f"{days}j")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}min")
    return " ".join(parts[:3])

def get_relay_launch_ts(state):
    """Timestamp de mise en service initiale du relay (persistee dans state)."""
    launch_iso = state.get("relay_launch_date")
    if launch_iso:
        try:
            return datetime.fromisoformat(launch_iso).timestamp()
        except (ValueError, TypeError):
            pass

    # Fallback : timestamp du plus vieux event durable en DB.
    # On exclut les ephemeres (kinds 20000-29999) qui n'auraient pas de sens.
    cmd = [
        "/usr/local/bin/strfry",
        "--config", "/etc/strfry/strfry.conf",
        "scan", '{"limit":1, "kinds":[0,1,3,7]}',
    ]
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, text=True, timeout=30
        ).strip().splitlines()
        if out:
            event = json.loads(out[0])
            ts = float(event.get("created_at", 0))
            if ts > 0:
                created_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                state["relay_launch_date"] = created_dt.isoformat()
                return ts
    except Exception:
        pass
    return None

def get_relay_runtime(state):
    """Duree depuis la mise en service initiale du relay."""
    launch_ts = get_relay_launch_ts(state)
    if launch_ts is None:
        return "inconnu"

    if not is_strfry_active():
        return "arrêté"

    return format_duration(time.time() - launch_ts)

def _active_since_ts():
    """Timestamp Unix du début du streak actif courant de strfry (ou None)."""
    raw = run(
        'date -d "$(systemctl show strfry -p ActiveEnterTimestamp --value)" +%s 2>/dev/null'
    )
    try:
        return int(raw)
    except ValueError:
        return None

def get_uptime_pct():
    """Uptime strfry réel sur la fenêtre 24h glissante.

    Mesuré via les transitions d'état systemd, et NON via un compteur cumulatif
    (NRestarts), qui n'a aucun rapport avec les dernières 24h et restait figé.

    - strfry down maintenant : 0%.
    - actif sans interruption depuis avant la fenêtre : 100% (cas courant, aucun
      parsing de journal nécessaire).
    - sinon (≥1 redémarrage dans la fenêtre) : on somme le downtime réel à partir
      des transitions Started/Stopped du journal systemd.
    """
    if not is_strfry_active():
        return 0.0

    window = 86400
    now = int(time.time())
    win_start = now - window

    # Cas courant : streak actif démarré avant la fenêtre → 100% sur 24h.
    active_since = _active_since_ts()
    if active_since is not None and active_since <= win_start:
        return 100.0

    # Sinon : au moins une transition dans la fenêtre. On reconstruit la
    # timeline à partir des messages systemd (et non des logs applicatifs).
    out = run(
        'journalctl -u strfry --since "24 hours ago" -o short-unix --no-pager 2>/dev/null'
    )
    transitions = []
    for line in out.splitlines():
        if "systemd[" not in line:  # ignore le stdout applicatif de strfry
            continue
        try:
            ts = int(float(line.split(maxsplit=1)[0]))
        except (ValueError, IndexError):
            continue
        if ts < win_start:
            continue
        low = line.lower()
        if "started strfry" in low:
            transitions.append((ts, "up"))
        elif any(k in low for k in (
            "stopped strfry", "failed", "main process exited", "deactivated",
        )):
            transitions.append((ts, "down"))
    transitions.sort()

    # État au début de fenêtre, inféré de la 1re transition observée.
    state = "down" if (transitions and transitions[0][1] == "up") else "up"
    last_ts = win_start
    downtime = 0
    for ts, ev in transitions:
        if state == "down":
            downtime += ts - last_ts
        state = ev
        last_ts = ts
    if state == "down":  # ne devrait pas arriver : strfry est actif maintenant
        downtime += now - last_ts

    uptime_pct = max(0.0, min(100.0, 100 - (downtime / window) * 100))
    return round(uptime_pct, 2)

def get_total_events():
    """Nombre total d'events en base. Utilise `scan --count` natif strfry :
    parcourt l'index sans materialiser les events en JSONL (3-4s pour 1.4M
    events au lieu de 2-3 min avec `scan | wc -l`)."""
    out = run(
        "/usr/local/bin/strfry --config /etc/strfry/strfry.conf scan --count '{}' 2>/dev/null"
    )
    try:
        return int(out)
    except ValueError:
        return 0

# ─── Construction et publication ──────────────────────────────────────────────

def build_post(events_24h, seen_pubkeys_24h, active_pubkeys_24h, uptime, runtime, total_events):
    return (
        f"📡 relay.nostrmap.net — stats 24h\n\n"
        f"⚡ {events_24h:,} events reçus\n"
        f"👀 {seen_pubkeys_24h:,} clés vues\n"
        f"🔑 {active_pubkeys_24h:,} clés actives\n"
        f"🗄 {total_events:,} events en base\n"
        f"⏱ Uptime : {uptime}%\n"
        f"🚀 Lancé depuis : {runtime}\n\n"
        f"Relay Nostr public francophone — https://nostrmap.fr\n\n"
        f"#nostr #relay #nostrfr"
    ).replace(",", "\u202f")  # espace fine pour les milliers

def publish(content: str, keys: dict) -> str:
    private_key = PrivateKey.from_nsec(keys["nsec_relay"])

    event = Event(
        content=content,
        pubkey=private_key.public_key.hex(),
        kind=EventKind.TEXT_NOTE,
        tags=[
            ["t", "nostr"],
            ["t", "relay"],
            ["t", "nostrfr"],
        ],
    )
    event.sign(private_key.hex())
    event_dict = event.to_dict()

    results = []
    for relay_url in PUBLISH_RELAYS:
        host = relay_url.replace("wss://", "").rstrip("/")
        try:
            ok = _ws_publish(host, event_dict)
            results.append(f"{'✅' if ok else '⚠️'} {relay_url}")
        except Exception as e:
            results.append(f"❌ {relay_url} ({e})")

    print("\n".join(results))
    return event.id

def parse_args():
    parser = argparse.ArgumentParser(description="Publie les stats 24h du relay")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="affiche les stats sans publier ni écrire l'historique",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    keys = load_keys()

    if keys.get("nsec_relay") == "NSEC_A_RENSEIGNER":
        print("ERREUR : nsec_relay non renseignée dans keys.json")
        exit(1)

    state = load_state()
    had_launch_date = "relay_launch_date" in state

    events_24h, seen_pubkeys_24h, active_pubkeys_24h = collect_24h_stats()
    uptime       = get_uptime_pct()
    runtime      = get_relay_runtime(state)
    total_events = get_total_events()

    if not had_launch_date and "relay_launch_date" in state:
        save_state(state)

    content = build_post(
        events_24h,
        seen_pubkeys_24h,
        active_pubkeys_24h,
        uptime,
        runtime,
        total_events,
    )

    print("Post à publier :")
    print("─" * 40)
    print(content)
    print("─" * 40)

    # Garde-fou anti-post-vide : ne JAMAIS publier un post qui suggererait
    # que le relay est en panne alors qu'il tourne. Si les sources de donnees
    # ont echoue (commandes systemctl/strfry retournant 0), on log et on sort.
    sanity_problems = []
    if total_events <= 1000:
        sanity_problems.append(f"total_events={total_events} (suspect, < 1000)")
    if runtime in ("arrêté", "inconnu"):
        sanity_problems.append(f"runtime={runtime!r} (suspect)")
    if uptime <= 0.0 and is_strfry_active():
        sanity_problems.append(f"uptime={uptime}% mais strfry actif (incoherent)")

    if sanity_problems:
        print("\n⛔ POST NON PUBLIE : sanity-check echoue.")
        for p in sanity_problems:
            print(f"   - {p}")
        print("Le post n'est PAS envoye pour ne pas faire croire que le relay est en panne.")
        print("Investiguer les sources de donnees (systemctl, strfry binaire, journalctl).")
        return

    if args.dry_run:
        print("\nMode dry-run : aucune publication, historique inchangé.")
        return

    event_id = publish(content, keys)
    print(f"\n✅ Publié — event id : {event_id}")

    history = state.get("posts_history", [])
    history.append({
        "date":         datetime.now(timezone.utc).isoformat(),
        "event_id":     event_id,
        "events_24h":   events_24h,
        "seen_pubkeys_24h": seen_pubkeys_24h,
        "active_pubkeys_24h": active_pubkeys_24h,
        "pubkeys_24h":  seen_pubkeys_24h,
        "total_events": total_events,
        "uptime":       uptime,
        "runtime":      runtime,
    })
    state["posts_history"] = history[-30:]
    save_state(state)

if __name__ == "__main__":
    main()
