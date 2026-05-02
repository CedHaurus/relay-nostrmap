#!/bin/bash
# Mise a jour de la blocklist strfry
#
# Etat des sources publiques (verifie 2026-05-02) :
#   - https://api.nostr.band/v0/spam/pubkeys      : injoignable
#   - https://spam.nostr.band/spam_api?...        : timeout
#   - https://nostr.watch/api/blocklist           : injoignable
#   - https://github.com/Spl0itable/nostr-relay-spam-blocklist : depot supprime
#
# La blocklist peut etre alimentee manuellement : une pubkey hex par ligne
# dans /etc/strfry/blocklist.txt (rechargee toutes les 5 min par policy.py).
#
# Le script ne logge que si la blocklist change, pour eviter le bruit syslog.

set -e
BLOCKLIST="/etc/strfry/blocklist.txt"
TMP=$(mktemp)
trap "rm -f $TMP" EXIT

SOURCES=(
    "https://spam.nostr.band/spam_api?method=get_current_spam&view=pubkeys"
    "https://api.nostr.band/v0/spam/pubkeys"
    "https://nostr.watch/api/blocklist"
)

for URL in "${SOURCES[@]}"; do
    curl -sf --max-time 15 "$URL" -o "$TMP" 2>/dev/null || continue

    COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$TMP'))
    pubkeys = data if isinstance(data, list) else data.get('pubkeys', data.get('items', []))
    valid = [p for p in pubkeys if isinstance(p, str) and len(p) == 64]
    print(len(valid))
    if valid:
        open('$BLOCKLIST', 'w').write('\n'.join(sorted(set(valid))) + '\n')
except Exception:
    print(0)
" 2>/dev/null)

    if [ "${COUNT:-0}" -gt 0 ]; then
        logger -t strfry-blocklist "blocklist mise a jour depuis $URL ($COUNT entrees)"
        exit 0
    fi
done

# Aucune source disponible : on reste silencieux sauf si la blocklist est vide
# ET que la derniere notification date de plus de 7 jours (evite le spam syslog).
MARKER="/var/run/strfry-blocklist-warned"
if [ ! -f "$MARKER" ] || [ $(($(date +%s) - $(stat -c %Y "$MARKER" 2>/dev/null || echo 0))) -gt 604800 ]; then
    CURRENT=$(wc -l < "$BLOCKLIST" 2>/dev/null || echo 0)
    logger -t strfry-blocklist "info: aucune source distante disponible, blocklist locale = $CURRENT entrees (rappel hebdo)"
    touch "$MARKER"
fi
