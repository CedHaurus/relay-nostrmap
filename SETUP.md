# SETUP.md — Installation complète du relay strfry

Ce guide décrit comment déployer un relay Nostr strfry sur un VPS Ubuntu 24.04 avec Caddy comme reverse proxy, en stack **native systemd** (sans Docker).

## Prérequis

- VPS Ubuntu 24.04 LTS (4 vCPU / 8 Go RAM / 80+ Go disque recommandés)
- Un nom de domaine pointant sur le VPS (A et AAAA records)
- Accès root SSH

## 1. Compiler strfry depuis les sources

```bash
apt update && apt install -y \
    git build-essential libssl-dev zlib1g-dev liblmdb-dev \
    libflatbuffers-dev libsecp256k1-dev libzstd-dev \
    pkg-config libtool ca-certificates curl

git clone https://github.com/hoytech/strfry.git /opt/strfry
cd /opt/strfry
git submodule update --init
make setup-golpe
make -j$(nproc)
install -m 755 strfry /usr/local/bin/strfry
/usr/local/bin/strfry --version
```

## 2. Installer Caddy v2 + autres paquets

```bash
apt install -y caddy fail2ban ufw restic \
    python3-pip python3-pynostr python3-psutil
# Si python3-pynostr indispo :
# pip3 install pynostr psutil --break-system-packages
```

## 3. Déployer les fichiers de config

Cloner ce dépôt et copier les fichiers à leur place :

```bash
git clone https://github.com/CedHaurus/relay-nostrmap.git /tmp/relay-cfg
cd /tmp/relay-cfg

# strfry
mkdir -p /etc/strfry/monitor
install -m 644 strfry.conf            /etc/strfry/strfry.conf
install -m 755 policy.py              /etc/strfry/policy.py
install -m 755 retention.sh           /etc/strfry/retention.sh
install -m 755 update-blocklist.sh    /etc/strfry/update-blocklist.sh
touch /etc/strfry/blocklist.txt        # alimentation manuelle, voir update-blocklist.sh
install -m 755 monitor/monitor.py     /etc/strfry/monitor/monitor.py
install -m 755 monitor/stats.py       /etc/strfry/monitor/stats.py
install -m 600 monitor/keys.example.json /etc/strfry/monitor/keys.json
# ⚠️ remplacer le contenu de /etc/strfry/monitor/keys.json par les vraies clés (voir section 7)

# Caddy
install -m 644 Caddyfile              /etc/caddy/Caddyfile

# systemd
install -m 644 systemd/strfry.service /etc/systemd/system/strfry.service
mkdir -p /etc/systemd/system/strfry.service.d
install -m 644 systemd/strfry.service.d-override.conf \
                /etc/systemd/system/strfry.service.d/override.conf

# Scripts
install -m 750 scripts/server-backup.sh /usr/local/sbin/server-backup.sh

# Système
install -m 644 system/sysctl.d/99-relay.conf       /etc/sysctl.d/99-relay.conf
install -m 644 system/fail2ban-jail.d/custom.conf   /etc/fail2ban/jail.d/custom.conf
install -m 644 system/fail2ban-filter.d/caddy-bad-requests.conf \
                                                    /etc/fail2ban/filter.d/caddy-bad-requests.conf
install -m 644 system/sshd_config.d/99-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf
install -m 644 system/logrotate.d/strfry-monitor    /etc/logrotate.d/strfry-monitor
install -m 644 system/apt.conf.d/52unattended-upgrades-local \
                                                    /etc/apt/apt.conf.d/52unattended-upgrades-local
mkdir -p /etc/systemd/journald.conf.d
install -m 644 system/journald.conf.d/limits.conf   /etc/systemd/journald.conf.d/limits.conf
install -m 644 system/cron.d/server-backup          /etc/cron.d/server-backup

# Crontab root (à éditer pour adapter chemins/horaires)
crontab crontab-root.example
```

## 4. Adapter le Caddyfile et strfry.conf

Dans `/etc/caddy/Caddyfile`, remplacer `relay.nostrmap.net` par votre domaine.

Dans `/etc/strfry/strfry.conf`, remplacer dans le bloc `info { ... }` :
- `name`, `description`, `contact`, `pubkey` par les valeurs de votre relay

## 5. Configurer le firewall (UFW)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp   # HTTP/3 QUIC
ufw enable
```

## 6. Activer les services

```bash
systemctl daemon-reload
systemctl enable --now strfry caddy fail2ban
systemctl reload ssh    # applique le drop-in 99-hardening.conf

# ⚠️ Au PREMIER démarrage strfry, le garde-fou ExecStartPre bloquera car data.mdb n existe pas.
# Importer un dump initial AVANT, ou désactiver temporairement l ExecStartPre. Voir RESTORE.md.
```

## 7. Configurer les clés Nostr du relay (monitor/stats)

`monitor.py` envoie des DM Nostr d'alerte ; `stats.py` publie un post quotidien.

```bash
nano /etc/strfry/monitor/keys.json
# Format :
# {
#   "npub_relay": "npub1...",
#   "nsec_relay": "nsec1...",     # clé privée du COMPTE qui poste les stats
#   "npub_operator": "npub1..."   # ton npub perso, qui reçoit les DM d alerte
# }
chmod 600 /etc/strfry/monitor/keys.json
```

## 8. Configurer le backup restic (Cloudflare R2)

```bash
mkdir -p /etc/restic
chmod 700 /etc/restic

# Mot de passe restic (à conserver HORS du serveur !)
echo "<MOT_DE_PASSE_FORT>" > /etc/restic/password
chmod 600 /etc/restic/password

# Credentials R2
cat > /etc/restic/r2.env <<'EOF'
export RESTIC_REPOSITORY="s3:<endpoint>/<bucket>"
export RESTIC_PASSWORD_FILE="/etc/restic/password"
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
EOF
chmod 600 /etc/restic/r2.env

# Initialiser le dépôt restic
set -a; source /etc/restic/r2.env; set +a
restic init

# Lancer un backup manuel pour tester
/usr/local/sbin/server-backup.sh
```

## 9. Validation

```bash
# Service NIP-11 OK ?
curl -sH "Accept: application/nostr+json" https://votre-domaine.net/ | python3 -m json.tool

# Compter les events en DB
/usr/local/bin/strfry --config /etc/strfry/strfry.conf scan '{}' 2>/dev/null | wc -l

# Tester le monitor
python3 /etc/strfry/monitor/monitor.py alert
```

## Pièges connus

- **Garde-fou `ExecStartPre`** : strfry refuse de démarrer si `data.mdb` est absent ou < 1 Mo. Pour bootstrap, importer un dump (cf. RESTORE.md) AVANT le premier `systemctl start`.
- **Caddy `header_up X-Real-Ip`** : volontairement absent (anonymisation RGPD). strfry log toutes les connexions comme `127.0.0.1`. Ne pas l'ajouter sauf si tu veux désactiver l'anonymisation.
- **Docker** : volontairement non utilisé. `systemctl mask docker` si nécessaire.
- **`maxWebsocketPayloadSize`** ≠ **`events.maxEventSize`** : 2 paramètres distincts dans strfry.conf, à aligner pour permettre les events > 64 KiB.
- **Rétention `retention.sh`** (5 ans) doit être cohérente avec `events.rejectEventsOlderThanSeconds` dans strfry.conf, sinon strfry rejette à l'écriture des events que retention aurait gardés en DB.

## Références

- strfry : https://github.com/hoytech/strfry
- Caddy : https://caddyserver.com/
- Nostr NIPs : https://github.com/nostr-protocol/nips
