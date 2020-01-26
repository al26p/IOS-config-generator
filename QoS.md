# Qos Cheat Sheet

1. Identifier/classer traffic

#### Définition des Class-map
- `(config)class-map <Class Name>`
- `(config-cmap)match access-group <ACL id>`

Pour la classse par défaut
- `(config)class-map <Cname>`
- `(config-cmap)match ip dscp default`


2. Definir règles QoS/Appliquer les règles
- `(config)policy-map <TOMARK>`
- `(config-pmap)class <Cname>`
- `(config-pmap-c)set ip dscp <dscp class>`

- `(config)policy-map <MARKED>`
- `(config-pmap)class <Cname>`
- `(config-pmap-c)bandwidth percent <%>`

**Total des bande passantes <= 80 % !**

3. Indiquer les interfaces concernées
- `(config)interface F0/0`
- `(config-int)service-policy <output/input> <MARKED/TOMARK>`

MARKED : Interface out | TOMARK : Interface in

### Config Access List Etendue

- `(config)access-list <101> permit <protocol> <ip src> <imask> <ip dest> <imask> eq <port/service>`
- `(config)access-list <101> permit <protocol> any any eq <port/service>`

### DSCP Classes
|Classes\Drop|Classe 1|Classe 2|Classe 3|Classe 4|
| :---: | :---: | :---: | :---: | :---: |
|Bas|AF11|AF21|AF31|AF41|
|Medium|AF12|AF22|AF32|AF42|
|Elevé|AF13|AF23|AF33|AF43|

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
