#!/bin/bash
# Politique de retention strfry.
#
# 1. Retention generale : 5 ans (purge events plus vieux que 5 ans).
#    Avant : 1 an. Etendu le 2026-05-02 apres upgrade VPS (7.6 Gi RAM, 150 Go disque).
#    Garde-fou : ne mord quasiment jamais, Nostr ayant moins de 5 ans d'usage reel.
#
# 2. Gift wraps NIP-59 (kind 1059) : 30 jours.
#    Ajoute le 2026-07-18. Diagnostic : les 1059 representaient 98,5 % du volume
#    de la base (30,5 Go sur 31,0 Go, 1,9 M events, moyenne 17,2 ko) alors que le
#    relais francophone lui-meme pese moins de 500 Mo. Un destinataire recupere
#    ses DM chiffres bien avant 30 jours ; au-dela c'est du stockage mort qui part
#    en sauvegarde R2 deux fois par jour. Cf JOURNAL-IA 2026-07-18.
#
# Les events ephemeres et expirations NIP-40 sont nettoyes par strfry lui-meme,
# independamment de ce script.

set -e

STRFRY="/usr/local/bin/strfry --config /etc/strfry/strfry.conf"

CUTOFF_GENERAL=$(date -d "5 years ago" +%s)
$STRFRY delete --filter "{\"until\": $CUTOFF_GENERAL}" 2>&1 | logger -t strfry-retention

CUTOFF_GIFTWRAP=$(date -d "30 days ago" +%s)
$STRFRY delete --filter "{\"kinds\":[1059],\"until\": $CUTOFF_GIFTWRAP}" 2>&1 | logger -t strfry-retention
