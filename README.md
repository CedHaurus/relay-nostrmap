# relay.nostrmap.net

Relay Nostr public francophone — ouvert à tous.

**wss://relay.nostrmap.net**

---

## À propos

Ce relay fait partie du projet [nostrmap.fr](https://nostrmap.fr), une initiative francophone pour renforcer la décentralisation du réseau Nostr.

- Public, sans inscription
- Aucune limite de kind (tous les événements acceptés)
- Filtrage anti-spam par politique (write policy Python : rate-limit 30/min/pubkey, sanity checks taille/tags/horloge, blocklist locale)
- Compression WebSocket activée (permessage-deflate)
- TLS via Caddy (certificat Let's Encrypt automatique)
- Rétention 5 ans (purge automatique au-delà)
- **Pas de logs d'IP** — adresses IP anonymisées /24 (IPv4) ou /48 (IPv6) dans les logs Caddy, et strfry voit toutes les connexions comme 127.0.0.1

## Contact

- npub : `npub1n2878xq8jmacnjsyun6a0nrys7tcglzq8znzv05s33ddrxupd36q6uhtpg`

## Stack technique

- **[strfry](https://github.com/hoytech/strfry)** — relay Nostr haute performance (C++, LMDB)
- **[Caddy v2](https://caddyserver.com/)** — reverse proxy TLS automatique
- **systemd** — orchestration native (Docker volontairement non utilisé depuis mai 2026)
- **fail2ban** — protection brute-force SSH + scans web (3 jails : sshd, caddy-bad-requests, recidive)
- **restic + Cloudflare R2** — backup automatique 2×/jour avec rétention 7d/4w/3m
- **Python** — write policy, monitoring (alertes DM Nostr NIP-04, post stats quotidien)

## Ce dépôt

Ce dépôt contient les fichiers de configuration publics du relay, publiés pour la transparence et pour aider d'autres opérateurs francophones à monter leur propre relay.

Les fichiers sensibles (`keys.json`, `r2.env`, mots de passe restic, clés SSH) ne sont pas inclus.

## Structure

```
relay-nostrmap/
├── README.md, SETUP.md, RESTORE.md     # documentation
├── Caddyfile                           # → /etc/caddy/Caddyfile
├── strfry.conf                         # → /etc/strfry/strfry.conf
├── policy.py                           # → /etc/strfry/policy.py
├── retention.sh                        # → /etc/strfry/retention.sh
├── update-blocklist.sh                 # → /etc/strfry/update-blocklist.sh
├── crontab-root.example                # → crontab -e (root)
├── monitor/
│   ├── monitor.py, stats.py            # → /etc/strfry/monitor/
│   └── keys.example.json               # template — créer keys.json à la main (chmod 600)
├── systemd/
│   ├── strfry.service                  # → /etc/systemd/system/
│   └── strfry.service.d-override.conf  # → /etc/systemd/system/strfry.service.d/override.conf
├── scripts/
│   └── server-backup.sh                # → /usr/local/sbin/
└── system/                             # configurations OS
    ├── sysctl.d/, fail2ban-jail.d/, fail2ban-filter.d/
    ├── sshd_config.d/, logrotate.d/
    └── apt.conf.d/, journald.conf.d/, cron.d/
```

Voir [SETUP.md](SETUP.md) pour l'installation complète, [RESTORE.md](RESTORE.md) pour la procédure de disaster recovery.

## Sécurité & RGPD

- **Anonymisation IP /24** par design (volontaire, RGPD)
- **Garde-fou systemd `ExecStartPre`** qui refuse de démarrer si la DB strfry est absente ou < 1 Mo (protège contre les recréations accidentelles)
- **Hardening systemd** : `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `RestrictAddressFamilies AF_INET AF_INET6 AF_UNIX`
- **Headers HTTPS** : HSTS 1 an, X-Frame-Options DENY, Referrer-Policy no-referrer, Permissions-Policy
- **Auto-reboot** après upgrades sécurité kernel à 04:50 UTC
- **Limites cgroup** : `MemoryHigh=6000M`, `MemoryMax=7000M` (sur VPS 8 Go)
- **Backup chiffré** vers Cloudflare R2 avec sanity-check anti-export-vide

## Lancer votre propre relay

Voir [SETUP.md](SETUP.md) pour un guide d'installation complet.

---

`#nostr #relay #nostrfr`
