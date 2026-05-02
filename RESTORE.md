# RESTORE.md — Procédure de restauration relay.nostrmap.net

Stack native systemd (strfry binaire + Caddy v2). Mise à jour : 2026-05-02 (post migration Docker → natif).

## Informations du dépôt restic

- **Bucket R2** : `backup-relay-nostr`
- **Endpoint** : `https://ae7eea23a151c74ad1d2b52ef5590ac0.r2.cloudflarestorage.com`
- **Repository ID** : `8286fa9794`
- **Credentials** : `/etc/restic/r2.env` (root:root 600)
- **Mot de passe** : `/etc/restic/password` (root:root 600) — ⚠️ **DOIT être conservé HORS du serveur** (gestionnaire de mots de passe, papier en coffre, autre serveur). Sans lui, R2 est irrécupérable.

## Pré-requis hors-serveur (CRITIQUE)

À conserver IMPÉRATIVEMENT en lieu sûr :

1. **Mot de passe restic** (équivalent du contenu actuel de `/etc/restic/password`)
2. **Credentials R2** (équivalent de `/etc/restic/r2.env` : `RESTIC_REPOSITORY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. **nsec du compte relay** (`keys.json`)
4. **Clé SSH GitHub deploy** (`/root/.ssh/github_relay`) si utilisée

**Sans (1) et (2), les snapshots R2 sont définitivement irrécupérables.**

## RPO / RTO

- **RPO** (perte max) : ≤ 12h (2 backups/jour à 04:00 et 16:00 UTC)
- **RTO** (temps de remise en service) : 45-90 min sur Hetzner pour un opérateur familier ; ~3h pour quelqu'un qui découvre

## Étapes de restauration sur un VPS neuf

### 1. Provisionner le VPS et installer les paquets

```bash
# Sur Hetzner : Ubuntu 24.04 LTS, 4 vCPU / 8 Go RAM / 150 Go (CPX31)
apt update && apt install -y \
    restic caddy fail2ban ufw \
    python3-pip python3-pynostr python3-psutil \
    git build-essential libssl-dev zlib1g-dev liblmdb-dev \
    libflatbuffers-dev libsecp256k1-dev libzstd-dev \
    pkg-config libtool ca-certificates curl

# Si python3-pynostr indispo via apt :
# pip3 install pynostr psutil --break-system-packages
```

### 2. Compiler et installer strfry

```bash
git clone https://github.com/hoytech/strfry.git /opt/strfry
cd /opt/strfry
git submodule update --init
make setup-golpe
make -j4
install -m 755 strfry /usr/local/bin/strfry
/usr/local/bin/strfry --version  # vérifier
```

### 3. Restaurer les credentials restic (manuellement, depuis le hors-serveur)

```bash
mkdir -p /etc/restic
chmod 700 /etc/restic
# Recréer /etc/restic/password (depuis sauvegarde hors-serveur)
echo "<MOT_DE_PASSE_RESTIC>" > /etc/restic/password
chmod 600 /etc/restic/password
# Recréer /etc/restic/r2.env (depuis sauvegarde hors-serveur)
cat > /etc/restic/r2.env <<'EOF'
export RESTIC_REPOSITORY="s3:https://ae7eea23a151c74ad1d2b52ef5590ac0.r2.cloudflarestorage.com/backup-relay-nostr"
export RESTIC_PASSWORD_FILE="/etc/restic/password"
export AWS_ACCESS_KEY_ID="<R2_ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<R2_SECRET_KEY>"
EOF
chmod 600 /etc/restic/r2.env
```

### 4. Restaurer les configurations système depuis R2

```bash
set -a; source /etc/restic/r2.env; set +a

# Vérifier que le repo R2 est joignable
restic snapshots --latest 5

# Restaurer dans / (en place)
restic restore latest --target / \
    --include /etc/strfry \
    --include /etc/caddy \
    --include /etc/systemd/system/strfry.service \
    --include /etc/systemd/system/strfry.service.d \
    --include /etc/cron.d \
    --include /etc/fail2ban \
    --include /etc/sysctl.d \
    --include /etc/logrotate.d \
    --include /var/backups/server-backup \
    --include /root/.ssh
```

### 5. Restaurer (ou installer) le service strfry

Le snapshot inclut `/etc/systemd/system/strfry.service` et son override. Sinon, recréer :

```bash
cat > /etc/systemd/system/strfry.service <<'EOF'
[Unit]
Description=strfry Nostr relay
After=network.target

[Service]
ExecStart=/usr/local/bin/strfry --config /etc/strfry/strfry.conf relay
Restart=always
RestartSec=5
User=root
WorkingDirectory=/var/lib/strfry
LimitNOFILE=1000000
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

L'override (`/etc/systemd/system/strfry.service.d/override.conf`) est restauré du snapshot — il contient `MemoryHigh=6000M`, `MemoryMax=7000M`, et le **garde-fou ExecStartPre** qui refuse de démarrer si `/var/lib/strfry/data.mdb` est absent ou < 1 Mo.

```bash
systemctl daemon-reload
systemctl enable strfry caddy fail2ban
```

### 6. Importer la DB strfry depuis le dump JSON

⚠️ **PIÈGE** : tant que `/var/lib/strfry/data.mdb` n'existe pas, le garde-fou ExecStartPre **empêche** le démarrage. C'est INTENTIONNEL. Il faut donc créer la DB **hors-systemd** via un import direct.

```bash
mkdir -p /var/lib/strfry
chmod 700 /var/lib/strfry

# Import (cree data.mdb)
zcat /var/backups/server-backup/strfry-export-latest.jsonl.gz \
  | /usr/local/bin/strfry --config /etc/strfry/strfry.conf import

# Verifier que data.mdb est bien cree avec une taille > 1 Mo
ls -la /var/lib/strfry/

chmod 600 /var/lib/strfry/data.mdb /var/lib/strfry/lock.mdb
```

### 7. Démarrer les services

```bash
systemctl start strfry
systemctl status strfry
journalctl -u strfry -n 20  # doit montrer "Started websocket server on 127.0.0.1:7777"

systemctl start caddy
systemctl status caddy

systemctl start fail2ban
fail2ban-client status
```

### 8. Configurer le firewall

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp   # HTTP/3 QUIC
ufw enable
```

### 9. Configurer le DNS

Dans le panneau DNS (Cloudflare ou autre) : pointer `relay.nostrmap.net` (A et AAAA) vers la nouvelle IP du VPS. Caddy obtiendra automatiquement un nouveau certificat Let's Encrypt au premier appel HTTPS (peut prendre 30-60s).

### 10. Restaurer le crontab root

Le crontab root est dans `/var/spool/cron/crontabs/root`, qui n'est PAS dans le snapshot (zone non incluse). Le recréer :

```bash
crontab -e
```

Coller :
```
0 3 * * * /etc/strfry/retention.sh
0 */6 * * * /etc/strfry/update-blocklist.sh
0 6,18 * * * flock -n /var/run/strfry-monitor.lock timeout 240 python3 /etc/strfry/monitor/monitor.py report >> /var/log/strfry-monitor.log 2>&1
*/5 * * * * flock -n /var/run/strfry-monitor.lock timeout 240 python3 /etc/strfry/monitor/monitor.py alert >> /var/log/strfry-monitor.log 2>&1
0 12 * * * flock -n /var/run/strfry-monitor.lock timeout 240 python3 /etc/strfry/monitor/stats.py >> /var/log/strfry-monitor.log 2>&1
```

Le cron `/etc/cron.d/server-backup` est restauré du snapshot.

### 11. Validation finale

```bash
# 1. WebSocket / NIP-11 OK ?
curl -sH "Accept: application/nostr+json" https://relay.nostrmap.net/ | python3 -m json.tool

# 2. Events présents en DB ?
/usr/local/bin/strfry --config /etc/strfry/strfry.conf scan '{}' 2>/dev/null | wc -l
# doit retourner ~232k events ou plus

# 3. Backup tourne (test manuel) ?
/usr/local/sbin/server-backup.sh
tail -20 /var/log/server-backup.log

# 4. Monitor OK ?
python3 /etc/strfry/monitor/monitor.py alert
```

## Restauration partielle

### Récupérer juste un fichier de config

```bash
set -a; source /etc/restic/r2.env; set +a
restic restore latest --target /tmp/restore-partial --include /etc/strfry/strfry.conf
cp /tmp/restore-partial/etc/strfry/strfry.conf /etc/strfry/strfry.conf
```

### Récupérer la DB strfry à une date donnée (rollback)

```bash
restic snapshots                              # lister les snapshots dispos
restic restore <SNAPSHOT_ID> --target /tmp/r --include /var/backups/server-backup
zcat /tmp/r/var/backups/server-backup/strfry-export-latest.jsonl.gz | wc -l

# Pour replacer la DB en place (DESTRUCTIF, perte des events depuis le snapshot) :
systemctl stop strfry
rm -f /var/lib/strfry/data.mdb /var/lib/strfry/lock.mdb
zcat /tmp/r/var/backups/server-backup/strfry-export-latest.jsonl.gz \
  | /usr/local/bin/strfry --config /etc/strfry/strfry.conf import
chmod 600 /var/lib/strfry/data.mdb
systemctl start strfry
```

## Checklist de continuité (à vérifier 1× par trimestre)

- [ ] Mot de passe restic accessible hors-serveur ?
- [ ] `r2.env` accessible hors-serveur ?
- [ ] Dernière sauvegarde restic récente ? `restic snapshots --latest 1`
- [ ] Test de restauration partielle sur un VPS jetable ?
- [ ] DNS encore valide / Cloudflare R2 quota OK ?

## Pièges connus

- **Garde-fou ExecStartPre** : strfry refuse de démarrer si `data.mdb` manque ou < 1 Mo. NORMAL. Faire l'import via CLI direct (étape 6) AVANT `systemctl start`.
- **Symlink `latest`** : pointe sur le dernier dump strfry **valide** local. Le script de backup refuse de mettre à jour le symlink si l'export courant a < 1000 events (sanity check). Tu peux donc t'y fier.
- **First TLS cert** : Caddy peut prendre 30-60s pour obtenir le cert Let's Encrypt au premier démarrage post-DNS. Patience.
- **Anonymisation IPs** : Caddy log avec `ip_mask /24`, strfry voit `127.0.0.1` (pas de `realIpHeader`). C'est volontaire (RGPD), ne pas remettre `header_up X-Real-Ip`.
- **Docker** : volontairement masked. Ne pas le réactiver.
