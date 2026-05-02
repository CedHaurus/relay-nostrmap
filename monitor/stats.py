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

def get_events_last_24h():
    """Events stockés dans les 24 dernières heures (lecture directe DB strfry)."""
    since_ts = int(time.time()) - 86400
    return sum(1 for _ in iter_events_since(since_ts))

def get_events_24h():
    """Events stockés dans les 24 dernières heures (lecture directe DB strfry)."""
    since_ts = int(time.time()) - 86400
    return list(iter_events_since(since_ts))

def count_seen_pubkeys(events):
    """Pubkeys distinctes vues dans les events reçus."""
    return len({event.get("pubkey") for event in events if event.get("pubkey")})

def count_human_active_pubkeys(events):
    """Pubkeys distinctes ayant publié au moins un event d'activité humaine."""
    return len({
        event.get("pubkey")
        for event in events
        if event.get("pubkey") and event.get("kind") in HUMAN_ACTIVITY_KINDS
    })

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

def get_uptime_pct():
    """Uptime strfry sur 24h estime via journalctl.

    Si strfry est down maintenant : 0%.
    Sinon, on compte les redemarrages des dernieres 24h (un Started par restart)
    et on estime un downtime de 5s par restart (RestartSec=5).
    """
    if not is_strfry_active():
        return 0.0

    out = run(
        "journalctl -u strfry --since '24h ago' --no-pager 2>/dev/null "
        "| grep -c 'Started strfry.service'"
    )
    try:
        nb_starts = int(out)
    except ValueError:
        nb_starts = 0

    # Le premier "Started" du jour est le start regulier ; les suivants sont des restarts.
    nb_restarts = max(0, nb_starts - 1)
    # RestartSec=5 dans le service ; 5s de downtime par restart est une bonne approximation.
    downtime = nb_restarts * 5

    uptime_pct = max(0.0, min(100.0, 100 - (downtime / 86400) * 100))
    return round(uptime_pct, 2)

def get_total_events():
    """Nombre total d'events dans la DB (binaire strfry natif)."""
    out = run(
        "/usr/local/bin/strfry --config /etc/strfry/strfry.conf scan '{}' 2>/dev/null | wc -l"
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

    events       = get_events_24h()
    events_24h   = len(events)
    seen_pubkeys_24h = count_seen_pubkeys(events)
    active_pubkeys_24h = count_human_active_pubkeys(events)
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
