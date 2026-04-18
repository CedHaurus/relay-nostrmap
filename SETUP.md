# Guide d'installation — relay strfry sur VPS

Ce guide décrit comment déployer un relay Nostr strfry sur un VPS Ubuntu 24.04 avec Caddy comme reverse proxy.

## Prérequis

- VPS Ubuntu 22.04 ou 24.04 (2 vCPU, 4 GB RAM minimum)
- Un nom de domaine pointant sur le VPS
- Docker et Docker Compose installés
- Python 3.10+

## 1. Compiler strfry depuis les sources

```bash
# Dépendances
apt update && apt install -y git build-essential cmake libssl-dev \
  zlib1g-dev liblmdb-dev libflatbuffers-dev libsecp256k1-dev \
  libzstd-dev pkg-config

# Cloner et compiler
git clone https://github.com/hoytech/strfry.git /opt/strfry
cd /opt/strfry
git submodule update --init
make setup-golpe
make -j$(nproc)
```

## 2. Structure Docker

```
/opt/docker/
├── docker-compose.yml
├── caddy/
│   ├── Caddyfile
│   ├── data/          # certificats TLS (persisté)
│   └── config/
└── strfry/
    ├── Dockerfile
    ├── strfry.conf
    ├── policy.py
    ├── blocklist.txt
    └── data/          # base LMDB (persistée)
```

### Dockerfile strfry

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y \
    libssl3 zlib1g liblmdb0 libsecp256k1-2 libzstd1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/strfry/strfry /usr/local/bin/strfry
COPY policy.py /etc/strfry/policy.py
COPY blocklist.txt /etc/strfry/blocklist.txt
CMD ["strfry", "--config", "/etc/strfry/strfry.conf", "relay"]
```

> **Note** : buildez l'image depuis les sources compilées ou copiez le binaire strfry dans `./strfry/`.

## 3. Configuration

Copiez et adaptez les fichiers de ce dépôt :

```bash
# Adapter le domaine dans Caddyfile
sed -i 's/relay.votre-domaine.net/relay.mon-domaine.fr/g' Caddyfile

# Adapter le nom et la description dans strfry.conf
# Générer vos clés Nostr (npub/nsec) avec un outil comme nak ou nostr-keygen
```

## 4. Lancer la stack

```bash
cd /opt/docker
docker compose up -d

# Vérifier
docker compose ps
docker logs strfry --tail 20
docker logs caddy --tail 20
```

## 5. Sécurité

### UFW

```bash
apt install -y ufw
ufw default deny incoming
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### fail2ban

```bash
apt install -y fail2ban
```

Jail SSH dans `/etc/fail2ban/jail.d/sshd.conf` :
```ini
[sshd]
enabled  = true
maxretry = 5
bantime  = 1h
findtime = 10m
```

Jail Caddy dans `/etc/fail2ban/jail.d/caddy.conf` :
```ini
[caddy-bad-requests]
enabled  = true
port     = http,https
filter   = caddy-bad-requests
logpath  = /var/log/caddy/relay-access.log
maxretry = 20
bantime  = 1h
findtime = 5m
```

Filter `/etc/fail2ban/filter.d/caddy-bad-requests.conf` :
```ini
[Definition]
failregex = .*"remote_ip":"<HOST>".*"status":4[0-9]{2}.*
```

### iptables — protection DDoS légère

```bash
# Limite de connexions par IP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j REJECT

# Rate limiting des nouvelles connexions
iptables -A INPUT -p tcp --dport 443 -m state --state NEW \
  -m hashlimit --hashlimit-above 20/min --hashlimit-burst 50 \
  --hashlimit-mode srcip --hashlimit-name ws_limit -j DROP

# Sauvegarder
apt install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4
```

## 6. Anonymisation des IPs

Par défaut Caddy logue les IPs complètes des clients. Pour un relay public respectueux de la vie privée, on peut les tronquer directement dans la config :

```caddy
log {
    format filter {
        wrap json
        fields {
            request>remote_ip ip_mask {
                ipv4 24    # garde seulement x.x.x.0
                ipv6 48    # garde seulement les 48 premiers bits
            }
            request>client_ip ip_mask {
                ipv4 24
                ipv6 48
            }
        }
    }
}
```

Le `Caddyfile` de ce dépôt inclut déjà cette configuration. Les logs ne contiennent jamais d'IP complète — impossible de retracer un utilisateur individuel.

Pour désactiver complètement les logs :

```caddy
relay.votre-domaine.net {
    reverse_proxy 127.0.0.1:7777
    # pas de bloc log = aucun log d'accès
}
```

## 7. Monitoring (optionnel)

Le dossier `monitor/` contient un script Python :

- `monitor.py` — envoie des rapports et alertes à l'opérateur

### Installation

```bash
pip3 install pynostr --break-system-packages
mkdir -p /etc/strfry/monitor
cp monitor/monitor.py /etc/strfry/monitor/

# Créer keys.json avec les clés Nostr du relay
cat > /etc/strfry/monitor/keys.json << 'EOF'
{
  "npub_relay": "npub1...",
  "nsec_relay": "nsec1...",
  "npub_operator": "npub1..."
}
EOF
chmod 600 /etc/strfry/monitor/keys.json
```

### Crontab

```bash
# Rapport toutes les 12h
0 */12 * * * /usr/bin/python3 /etc/strfry/monitor/monitor.py report >> /var/log/strfry-monitor.log 2>&1

# Alertes toutes les 5 minutes
*/5 * * * * /usr/bin/python3 /etc/strfry/monitor/monitor.py alert >> /var/log/strfry-monitor.log 2>&1
```

## 8. Annoncer son relay

- [nostr.watch](https://nostr.watch) — annuaire de relays
- [relay.tools](https://relay.tools) — listing communautaire
- Publier un event NIP-65 (kind:10002) pour indiquer son relay dans son profil

---

*Ce guide est basé sur l'infrastructure de relay.nostrmap.net.*
