#!/bin/bash
# Retention 5 ans (purge events plus vieux que 5 ans).
# Avant : 1 an. Etendu le 2026-05-02 apres upgrade VPS (7.6 Gi RAM, 150 Go disque).
# Les events ephemeres et expirations NIP-40 sont nettoyes par strfry lui-meme,
# independamment de ce script.
set -e
CUTOFF=$(date -d "5 years ago" +%s)
/usr/local/bin/strfry --config /etc/strfry/strfry.conf delete --filter "{\"until\": $CUTOFF}" 2>&1 | logger -t strfry-retention
