#!/usr/bin/env python3
"""
strfry write policy plugin
- Rate limiting : 10 events/minute/pubkey
- Blocklist communautaire (nostr.watch)
"""
import sys, json, time
from collections import defaultdict

# Rate limiting en mémoire
rate_store = defaultdict(list)
RATE_LIMIT = 10       # events max
RATE_WINDOW = 60      # par seconde

# Blocklist — rechargée depuis /etc/strfry/blocklist.txt
def load_blocklist():
    try:
        with open('/etc/strfry/blocklist.txt', 'r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()

blocklist = load_blocklist()
last_reload = time.time()

def check(event):
    global blocklist, last_reload

    # Rechargement blocklist toutes les 5 minutes
    now = time.time()
    if now - last_reload > 300:
        blocklist = load_blocklist()
        last_reload = now

    pubkey = event.get('pubkey', '')

    # Vérification blocklist
    if pubkey in blocklist:
        return False, "blocked: pubkey on blocklist"

    # Rate limiting
    timestamps = rate_store[pubkey]
    timestamps = [t for t in timestamps if now - t < RATE_WINDOW]
    rate_store[pubkey] = timestamps

    if len(timestamps) >= RATE_LIMIT:
        return False, f"rate-limited: max {RATE_LIMIT} events/{RATE_WINDOW}s"

    rate_store[pubkey].append(now)
    return True, ""

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
        event = req.get('event', {})
        accepted, reason = check(event)
        result = {
            "id": event.get("id", ""),
            "action": "accept" if accepted else "reject",
            "msg": reason
        }
        print(json.dumps(result), flush=True)
    except Exception as e:
        print(json.dumps({"id": "", "action": "accept", "msg": ""}), flush=True)
