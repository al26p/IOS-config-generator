# Config commands for MPLS

### Enable MPLS on routers

`(conf) ip cef`

Enabled by default

Check if CEF is enabled : `sh ip cef`

+ LIB : `sh mpls ip bindings`
+ LFIB : `sh mpls forw`

Enable mpls on each interface :

`(conf-if) mpls ip`


646 : Port LDP

LDP  : Hello packet = UDP => Broadcast

LDP : Keep-alive = TCP => Unicast

Resemble à BGP (neughbor toussa toussa)

### Filtrage labels

1. Désactiver les annonces le temps de la config
  - `(conf)no mpls ldp advertise-labels`
2. Annoncer uniquement selon les ACL
  - `(conf)mpls ldp advertise-labels for <ACL>`
3. Refresh les sessions LDP
  - `clear mpls ldp neighbor *`
  
`access-list <id> <permit/deny> <net> <imask>`

Sur les 4 routeurs : 
- `access-list 10 deny <loopback> 0.0.0.0 Pour toutes les loopbacks
- `access-list 10 permit any`

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

