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
from datetime import datetime, timezone

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
    """Events acceptés dans les 24 dernières heures (logs Docker)"""
    out = run("docker logs strfry --since 24h 2>&1 | grep -c 'accepted'")
    try:
        return int(out)
    except ValueError:
        return 0

def get_active_pubkeys_24h():
    """Pubkeys distinctes actives sur 24h (logs Docker)"""
    out = run(
        "docker logs strfry --since 24h 2>&1 "
        "| grep -oP '\"pubkey\":\"\\K[^\"]+' "
        "| sort -u | wc -l"
    )
    try:
        return int(out)
    except ValueError:
        return 0

def get_uptime_pct():
    """Uptime strfry sur 24h estimé via les redémarrages Docker"""
    restarts = run(
        "docker logs strfry --since 24h 2>&1 "
        "| grep -c 'Started websocket server'"
    )
    try:
        r = max(0, int(restarts) - 1)
        downtime_pct = (r * 5) / 86400 * 100
        return round(max(0, 100 - downtime_pct), 2)
    except ValueError:
        return 100.0

def get_total_events():
    """Nombre total d'events dans la DB"""
    out = run(
        "docker exec strfry strfry --config /etc/strfry/strfry.conf "
        "scan '{}' 2>/dev/null | wc -l"
    )
    try:
        return int(out)
    except ValueError:
        return 0

# ─── Construction et publication ──────────────────────────────────────────────

def build_post(events_24h, pubkeys_24h, uptime, total_events):
    return (
        f"📡 relay.nostrmap.net — stats 24h\n\n"
        f"⚡ {events_24h:,} events reçus\n"
        f"🔑 {pubkeys_24h:,} clés actives\n"
        f"🗄 {total_events:,} events en base\n"
        f"⏱ Uptime : {uptime}%\n\n"
        f"Relay Nostr public francophone — ouvert à tous\n"
        f"nostrmap.fr\n\n"
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

def main():
    keys = load_keys()

    if keys.get("nsec_relay") == "NSEC_A_RENSEIGNER":
        print("ERREUR : nsec_relay non renseignée dans keys.json")
        exit(1)

    state = load_state()

    events_24h   = get_events_last_24h()
    pubkeys_24h  = get_active_pubkeys_24h()
    uptime       = get_uptime_pct()
    total_events = get_total_events()

    content = build_post(events_24h, pubkeys_24h, uptime, total_events)

    print("Post à publier :")
    print("─" * 40)
    print(content)
    print("─" * 40)

    event_id = publish(content, keys)
    print(f"\n✅ Publié — event id : {event_id}")

    history = state.get("posts_history", [])
    history.append({
        "date":         datetime.now(timezone.utc).isoformat(),
        "event_id":     event_id,
        "events_24h":   events_24h,
        "pubkeys_24h":  pubkeys_24h,
        "total_events": total_events,
        "uptime":       uptime,
    })
    state["posts_history"] = history[-30:]
    save_state(state)

if __name__ == "__main__":
    main()
