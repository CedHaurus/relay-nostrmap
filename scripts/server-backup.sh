#!/usr/bin/env bash
# Backup complet du serveur nostr-relay vers Cloudflare R2 via restic

set -euo pipefail

LOG_FILE="/var/log/server-backup.log"
DUMP_DIR="/var/backups/server-backup"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

die() {
    log "ERREUR: $*"
    exit 1
}

# ── 1. Chargement des credentials ──────────────────────────────────────────
source /etc/restic/r2.env

log "=== DÉBUT BACKUP $TIMESTAMP ==="

# ── 2. Répertoire de travail pour les dumps ─────────────────────────────────
mkdir -p "$DUMP_DIR"
chmod 700 "$DUMP_DIR"

# ── 3. Export strfry (LMDB → JSON) ─────────────────────────────────────────
# Utilise le binaire natif (stack systemd, plus de Docker depuis 2026-05-02).
# strfry export est non-bloquant et coherent meme pendant que strfry tourne.
STRFRY_DUMP="$DUMP_DIR/strfry-export-$TIMESTAMP.jsonl.gz"
STRFRY_DUMP_LATEST="$DUMP_DIR/strfry-export-latest.jsonl.gz"
MIN_EVENTS=1000   # seuil sanity-check : un dump avec moins d'events que ca est suspect

log "Export strfry LMDB → $STRFRY_DUMP"
/usr/local/bin/strfry --config /etc/strfry/strfry.conf export 2>>"$LOG_FILE" \
    | gzip -9 > "$STRFRY_DUMP" || true

if [ ! -s "$STRFRY_DUMP" ]; then
    rm -f "$STRFRY_DUMP"
    die "Export strfry a produit un fichier vide. Symlink 'latest' NON modifie. Verifier strfry et /etc/strfry/strfry.conf."
fi

EVENT_COUNT=$(zcat "$STRFRY_DUMP" | wc -l)
SIZE_BYTES=$(stat -c %s "$STRFRY_DUMP")
SIZE=$(numfmt --to=iec --suffix=B "$SIZE_BYTES")

if [ "$EVENT_COUNT" -lt "$MIN_EVENTS" ]; then
    rm -f "$STRFRY_DUMP"
    die "Export strfry suspect : $EVENT_COUNT events (< $MIN_EVENTS). Symlink 'latest' NON modifie. Investiguer avant le prochain run."
fi

log "Export strfry OK ($EVENT_COUNT events, $SIZE)"
ln -sf "$STRFRY_DUMP" "$STRFRY_DUMP_LATEST"
# Garder les 5 derniers dumps locaux (restic garde l'historique distant)
ls -1t "$DUMP_DIR"/strfry-export-*.jsonl.gz 2>/dev/null | tail -n +6 | xargs -r rm -f

# ── 4. Backup restic ────────────────────────────────────────────────────────
log "Lancement restic backup…"

restic backup \
    --verbose \
    --tag "server-backup" \
    --tag "nostr-relay" \
    \
    /etc \
    /root \
    "$DUMP_DIR" \
    \
    --exclude "/root/.vscode-server" \
    --exclude "/root/.cache" \
    --exclude "/root/.codex" \
    --exclude "**/.cache" \
    --exclude "**/node_modules" \
    --exclude "**/__pycache__" \
    --exclude "**/*.pyc" \
    --exclude "**/.git" \
    --exclude "/etc/alternatives" \
    --exclude "/etc/ssl/certs" \
    --exclude "/etc/terminfo" \
    --exclude "/etc/perl" \
    \
    2>&1 | tee -a "$LOG_FILE"

log "Restic backup terminé."

# ── 5. Politique de rétention ───────────────────────────────────────────────
log "Application de la politique de rétention…"
restic forget \
    --keep-daily   7 \
    --keep-weekly  4 \
    --keep-monthly 3 \
    --prune \
    2>&1 | tee -a "$LOG_FILE"

# ── 6. Vérification d'intégrité légère ─────────────────────────────────────
log "Vérification du dernier snapshot…"
restic check --read-data-subset=5% 2>&1 | tee -a "$LOG_FILE"

# ── 7. Résumé ───────────────────────────────────────────────────────────────
log "=== SNAPSHOTS DISPONIBLES ==="
restic snapshots --latest 5 2>&1 | tee -a "$LOG_FILE"

log "=== FIN BACKUP OK ==="
