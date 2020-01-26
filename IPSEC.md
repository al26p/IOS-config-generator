# IPSEC Pro Tips :)

### Etapes principales :

A chaque changement : reload IKE

`<no> crypto isakmp enable`

1. Politique de sécurité ISAKMP
- `(config)crypto isakmp policy <id>`
- `(conig-isakmp)encryption <des>`
- `(config-isakmp)hash <md5>`
- `(config-isakmp)authentication <pre-share>`
- `(config-isakmp)lifetime <14400>`
2. Configuration de l'auth par clé partagée
- `(config)crypto isakmp key <6> <key> address <hote distant>`
3. Configuration des paramètres IPSec (tr-set)
- `(config)crypto ipsec transform-set <tr-set name> <esp-des> <esp-md5-hmac>`
4. Crypto map
- `(config)crypto map <map name> <seqnum> ipsec-isakmp`
- `(config-crypto-map)match adddress <ACL id>`
- `(config-crypto-map)set peer <hote distant>`
- `(config-crypto-map)set transform-set <tr-set name>`
- `(config-crypto-map)set security-association lifetime seconds 1440`
5. Appliquer la crypto map
- Sur l'interface WAN
- `(config-if)crypto map <map name>`

### Config Access List Etendue

`(config)access-list <101> permit ip <ip src> <imask> <ip dest> <imask>`


### Ping on VPCs

`ping <ip> [OPTIONS]`

Guide des options:
 + -T : TTL
 + -P : Protocol 
  - 6 : TCP
  - 17 : UDP
  - 1 : ICMP
 + -l : size
 + -c : count
 + -p : port
