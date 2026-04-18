# relay.nostrmap.net

Relay Nostr public francophone — ouvert à tous.

**wss://relay.nostrmap.net**

---

## À propos

Ce relay fait partie du projet [nostrmap.fr](https://nostrmap.fr), une initiative francophone pour renforcer la décentralisation du réseau Nostr.

- Public, sans inscription
- Aucune limite de kind (tous les événements acceptés)
- Filtrage anti-spam par politique (write policy Python)
- Compression WebSocket activée (permessage-deflate)
- TLS via Caddy (certificat Let's Encrypt automatique)
- **Pas de logs d'IP** — les adresses IP sont anonymisées dans les logs Caddy (masque /24 IPv4, /48 IPv6)

## Contact

- npub : `npub1n2878xq8jmacnjsyun6a0nrys7tcglzq8znzv05s33ddrxupd36q6uhtpg`

## Stack technique

- **[strfry](https://github.com/hoytech/strfry)** — relay Nostr haute performance (C++, LMDB)
- **[Caddy v2](https://caddyserver.com/)** — reverse proxy TLS automatique
- **Docker Compose** — orchestration des services
- **Python** — write policy, monitoring

## Ce dépôt

Ce dépôt contient les fichiers de configuration publics du relay, publiés pour la transparence et pour aider d'autres opérateurs francophones à monter leur propre relay.

Les fichiers sensibles (clés, IP du serveur) ne sont pas inclus.

## Fichiers

| Fichier | Description |
|---|---|
| `strfry.conf` | Configuration du relay strfry |
| `Caddyfile` | Configuration Caddy (reverse proxy + anonymisation IP) |
| `docker-compose.yml` | Stack Docker |
| `policy.py` | Write policy (filtrage des événements) |
| `monitor/monitor.py` | Monitoring et alertes opérateur |

## Lancer votre propre relay

Voir [SETUP.md](SETUP.md) pour un guide d'installation complet.

---

`#nostr #relay #nostrfr`
