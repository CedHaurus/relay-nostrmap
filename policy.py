#!/usr/bin/env python3
"""
strfry write policy plugin
- Rate limiting : 30 events/minute/pubkey (relevé depuis 10 le 2026-05-02 — un user
  postant un thread + reactions tape facilement >10/min)
- Blocklist locale alimentée à la main (sources publiques mortes en 2026-05)
- Sanity-check basique sur taille content / nb tags / timestamp futur
"""
import sys, json, time
from collections import defaultdict

# Rate limiting en mémoire
rate_store = defaultdict(list)
RATE_LIMIT = 30        # events max
RATE_WINDOW = 60       # par fenêtre (secondes)

# Sanity limits applicatives
MAX_CONTENT_BYTES = 102400   # 100 KiB pour event content
MAX_TAGS = 2000              # garde-fou tag bombs
MAX_FUTURE_DRIFT = 900       # 15 min : timestamps futurs

# Blocklist — rechargée depuis /etc/strfry/blocklist.txt
def load_blocklist():
    try:
        with open('/etc/strfry/blocklist.txt', 'r') as f:
            return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()

blocklist = load_blocklist()
last_reload = time.time()

def reap_rate_store(now):
    """Purge les pubkeys silencieux pour eviter la fuite memoire long-terme.
    Garde uniquement ceux qui ont posté dans la fenetre courante."""
    global rate_store
    rate_store = defaultdict(list, {
        k: [t for t in v if now - t < RATE_WINDOW]
        for k, v in rate_store.items()
        if v and now - v[-1] < RATE_WINDOW
    })

def check(event):
    global blocklist, last_reload

    now = time.time()

    # Rechargement blocklist + purge rate_store toutes les 5 minutes
    if now - last_reload > 300:
        blocklist = load_blocklist()
        reap_rate_store(now)
        last_reload = now

    pubkey = event.get('pubkey', '')

    # Vérification blocklist
    if pubkey in blocklist:
        return False, "blocked: pubkey on blocklist"

    # Sanity checks applicatifs (tag bombs, content overflow, horloge future)
    content = event.get('content', '')
    if isinstance(content, str) and len(content.encode('utf-8', errors='ignore')) > MAX_CONTENT_BYTES:
        return False, f"blocked: content too large (>{MAX_CONTENT_BYTES} bytes)"
    tags = event.get('tags', [])
    if isinstance(tags, list) and len(tags) > MAX_TAGS:
        return False, f"blocked: too many tags (>{MAX_TAGS})"
    created_at = event.get('created_at', 0)
    if isinstance(created_at, (int, float)) and created_at > now + MAX_FUTURE_DRIFT:
        return False, "blocked: timestamp in future"

    # Rate limiting
    timestamps = [t for t in rate_store[pubkey] if now - t < RATE_WINDOW]
    if timestamps:
        rate_store[pubkey] = timestamps
    else:
        rate_store.pop(pubkey, None)

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
        # Fail-closed sur erreur policy : on rejette plutot que d accepter aveuglement.
        # Log sur stderr (visible dans journalctl strfry).
        print(f"policy error: {e}", file=sys.stderr, flush=True)
        print(json.dumps({"id": "", "action": "reject", "msg": "policy error"}), flush=True)
