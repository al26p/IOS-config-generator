package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type mask struct {
	masque string
	imask  string
	network string
}

type address struct {
	ip  string
	netw mask
}

type inter struct {
	tech       string
	id         string
	lan        bool
	clock_rate string
	mpls 	   bool
	ip address
	ipsec bool
}

type router struct {
	hostname   string
	interfaces []inter
	dhcp string
	route string
	mpls string
	ipsec string
}

func (r router) String() string {
	s := "\n\n\n\n\n\n   _____________________________________\n  |" +
		"                                     |\n  |       CONFIGURATION FOR " +
		r.hostname + "          |"+
		"\n  |_____________________________________|\n" +
		"!\n!\nversion 12.4\n" +
		"service timestamps debug datetime msec\n" +
		"service timestamps log datetime msec\n" +
		"no service password-encryption\n" +
		"!\n" +
		"!\n" +
		"hostname " + r.hostname + "\n!\n" +
		"boot-start-marker\n" +
		"boot-end-marker\n" +
		"!\n" +
		"!\n" +
		"no aaa new-model\n" +
		"memory-size iomem 5\n" +
		"no ip icmp rate-limit unreachable\n" +
		"ip cef\n" +
		"!\n" +
		r.dhcp +
		"no ip domain lookup\n" +
		"ip auth-proxy max-nodata-conns 3\n" +
		"ip admission max-nodata-conns 3\n" +
		"!\n" +
		r.mpls +
		"!\n" +
		"ip tcp synwait-time 5\n" +
		"!\n" +
		r.ipsec +
		"!\n"

	for _, i := range r.interfaces {
		if i.tech == "Loopback" {
			if i.ip.ip != "" {
				s += "!\n" +
					"interface " + i.tech + i.id + "\n" +
					" ip address " + i.ip.ip + " " + i.ip.netw.masque + "\n"
				if i.mpls {
					s += " mpls ip\n"
				}
			}
		} else {
			s += "!\n" +
				"interface " + i.tech + i.id + "\n"
			if i.ip.ip != "" {
				s += " ip address " + i.ip.ip + " " + i.ip.netw.masque + "\n"
			} else {
				s += " no ip address \n"
				s += " shutdown \n"
			}
			if i.tech == "Serial" {
				s += " clock rate " + i.clock_rate + "\n"
			} else {
				s += " duplex auto\n speed auto\n"
			}
			if i.mpls {
				s += " mpls ip\n"
			}
		}
	}
	s += "!\n"
	s += r.route
	return s
}

const end string = "ip forward-protocol nd\n" +
	"!\n" +
	"!\n" +
	"no ip http server\n" +
	"no ip http secure-server\n" +
	"!\n" +
	"no cdp log mismatch duplex\n" +
	"!\n" +
	"!\n" +
	"control-plane\n" +
	"!\n" +
	"!\n" +
	"!\n" +
	"!\n" +
	"!\n" +
	"line con 0\n" +
	"exec-timeout 0 0\n" +
	"privilege level 15\n" +
	"logging synchronous\n" +
	"line aux 0\n" +
	"exec-timeout 0 0\n" +
	"privilege level 15\n" +
	"logging synchronous\n" +
	"line vty 0 4\n" +
	"login\n" +
	"!\n" +
	"!\n" +
	"end\n"

var maskDict = map[int]mask{
	1:  {masque: "128.0.0.0", imask: "127.255.255.255"},
	2:  {masque: "192.0.0.0", imask: "63.255.255.255"},
	3:  {masque: "224.0.0.0", imask: "31.255.255.255"},
	4:  {masque: "240.0.0.0", imask: "15.255.255.255"},
	5:  {masque: "248.0.0.0", imask: "7.255.255.255"},
	6:  {masque: "252.0.0.0", imask: "3.255.255.255"},
	7:  {masque: "254.0.0.0", imask: "1.255.255.255"},
	8:  {masque: "255.0.0.0", imask: "0.255.255.255"},
	9:  {masque: "255.128.0.0", imask: "0.127.255.255"},
	10: {masque: "255.192.0.0", imask: "0.63.255.255"},
	11: {masque: "255.224.0.0", imask: "0.31.255.255"},
	12: {masque: "255.240.0.0", imask: "0.15.255.255"},
	13: {masque: "255.248.0.0", imask: "0.7.255.255"},
	14: {masque: "255.252.0.0", imask: "0.3.255.255"},
	15: {masque: "255.254.0.0", imask: "0.1.255.255"},
	16: {masque: "255.255.0.0", imask: "0.0.255.255"},
	17: {masque: "255.255.128.0", imask: "0.0.127.255"},
	18: {masque: "255.255.192.0", imask: "0.0.63.255"},
	19: {masque: "255.255.224.0", imask: "0.0.31.255"},
	20: {masque: "255.255.240.0", imask: "0.0.15.255"},
	21: {masque: "255.255.248.0", imask: "0.0.7.255"},
	22: {masque: "255.255.252.0", imask: "0.0.3.255"},
	23: {masque: "255.255.254.0", imask: "0.0.1.255"},
	24: {masque: "255.255.255.0", imask: "0.0.0.255"},
	25: {masque: "255.255.255.128", imask: "0.0.0.127"},
	26: {masque: "255.255.255.192", imask: "0.0.0.63"},
	27: {masque: "255.255.255.224", imask: "0.0.0.31"},
	28: {masque: "255.255.255.240", imask: "0.0.0.15"},
	29: {masque: "255.255.255.248", imask: "0.0.0.7"},
	30: {masque: "255.255.255.252", imask: "0.0.0.3"},
	31: {masque: "255.255.255.254", imask: "0.0.0.1"},
	32: {masque: "255.255.255.255", imask: "0.0.0.0"},
}

var lastRout string = "rip"

func ask(q string, p string) string {
	var text string
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(q + "[" + p + "]" + "\n--> ")
		text, _ = reader.ReadString('\n')
		re := regexp.MustCompile("[^\x20-\x7F]")
		text = re.ReplaceAllLiteralString(text, "")
		if text == "" {
			text = p
		}
		fmt.Printf("Appuyez sur entrée pour valider : %s\n", text)
		confirm, _ := reader.ReadString('\n')
		if re.ReplaceAllLiteralString(confirm, "") == "" {
			break
		}
	}
	return text
}

func newRouter3175(h string) router {
	r := router{
		hostname: h,
		interfaces: []inter{{
			tech: "Loopback",
			id:   "0",
		}, {
			tech: "FastEthernet",
			id:   "0/0",
		}, {
			tech: "Serial",
			id:   "0/0",
		}, {
			tech: "FastEthernet",
			id:   "0/1",
		}, {
			tech: "Serial",
			id:   "0/1",
		}}}

	return r
}

func cidr(s string) address {
	add,nn, _ := net.ParseCIDR(s)
	r := strings.SplitN(s, "/", -1)
	m, _ := strconv.Atoi(r[1])

	var netww = mask{
		masque:  maskDict[m].masque,
		imask:   maskDict[m].imask,
		network: add.Mask(nn.Mask).String(),
	}
	return address{
		ip:  add.String(),
		netw: netww,
	}
}

func getAddressChopped(s string) []string {
	return strings.SplitN(s, ".", -1)
}

//noinspection GoSnakeCaseUsage
func conf_t(f int) router {
	r := newRouter3175(ask("Entrez le hostname", "R" + strconv.Itoa(f)))
	for i, _ := range r.interfaces {
		if r.interfaces[i].tech == "Serial" {
			r.interfaces[i].clock_rate = "2000000"
		}
		if !("y" == ask("Voulez vous configurer "+r.interfaces[i].tech+r.interfaces[i].id+" ?", "n")) {
			continue
		}
		ip := cidr(ask("Entrez l'ip", fmt.Sprintf("%d.%d.%d.%d/32", f, f, f, f)))
		r.interfaces[i].ip.ip = ip.ip + " " + ip.netw.masque
		r.interfaces[i].ip = ip


		r.interfaces[i].lan = "y" == ask("Interface LAN ? (utile pour routage)", "n")

		if r.interfaces[i].lan {
			if "y" == ask("Configurer le DHCP ?", "n") {
				r.dhcp = "!\nno ip dhcp use vrf connected\n"
				dea := getAddressChopped(r.interfaces[i].ip.netw.network)
				a :=  ask("Adresses exclues de la zone dhcp (' ' for none)", fmt.Sprintf("%s.%s.%s.1 %s.%s.%s.99",
					dea[0], dea[1], dea[2], dea[0], dea[1], dea[2]))
				if " " != a  {
					r.dhcp += "ip dhcp excluded-address " + a + "\n"
				}
				r.dhcp += "!\nip dhcp pool LAN\n   network " + r.interfaces[i].ip.netw.network + " " + ip.netw.masque +
					"\n   default-router " + r.interfaces[i].ip.ip + "\n!\n"
			}
		}
	}
	return r
}


func rip(r router) string{
	s := "!\nrouter rip\n version 2\n"
	for _, iface := range r.interfaces {
		if iface.ip.ip != "" {
			if iface.lan {
				s += " passive-interface " + iface.tech + iface.id + "\n"
			}
			s += " network " + iface.ip.netw.network + "\n"
		}
	}
	s += " no auto-summary\n!\n"
	return s
}

func ospf(r router) string{
	pid := ask("Saisir ID de l'OSPF", "100")
	s := fmt.Sprintf("!\nrouter ospf %s\n", pid)
	if r.interfaces[0].ip.ip == "" {
		s += fmt.Sprintf(" router-id %s\n", ask("Loopback non renseignée, saisir id du router", "1.1.1.1"))
	}else {
		s += fmt.Sprintf(" router-id %s\n", r.interfaces[0].ip.ip)
	}
	s += " log-adjacency-changes\n"
	for _, iface := range r.interfaces {
		if iface.ip.ip != "" {
			if iface.lan {
				s += fmt.Sprintf(" passive-interface %s%s\n", iface.tech, iface.id)
			}
			s += fmt.Sprintf(" network %s %s area %s\n", iface.ip.netw.network, iface.ip.netw.imask,
				ask("Area for network " + iface.ip.netw.network, "0"))
		}
	}
	return s
}

func bgp(r router) string{
	as := ask(fmt.Sprintf("Entrez le numéro d'as pour %s", r.hostname), "72000")
	s := fmt.Sprintf("!\nrouter bgp %s\n no synchronization\n gbp log-neighbor-changes\n", as)
	for _, v := range r.interfaces {
		if v.lan || (v.tech == "Loopback" && v.ip.ip != ""){
			s += fmt.Sprintf(" network %s mask %s\n", v.ip.netw.network, v.ip.netw.masque)
		} else if v.ip.ip != "" && "y" == ask(fmt.Sprintf("Neighbor sur le lien %s ?", v.tech + v.id), "n"){
			ip := getAddressChopped(v.ip.netw.network)
			ip[3] = ask(fmt.Sprintf("Entrez la fin de l'ip du voisin %s.%s.%s.xxx", ip[0], ip[1], ip[2]), "1")
			asp := ask("Entrez le numéro d'as du voisin", "7200")
			s += fmt.Sprintf(" neighbor %s remote-as %s\n", strings.Join(ip, "."), asp)
			if as == asp {
				s += fmt.Sprintf(" neighbor %s next-hop-self\n", strings.Join(ip, "."))
			}
		}
	}
	s += " no auto-summary\n!\n"
	return s
}

func routage(r router) string{
	switch ask("Quel type de routae voulez vous effectuer ? (rip, ospf, bgp)", lastRout) {
	case "rip":
		lastRout = "rip"
		return rip(r)
	case "ospf":
		lastRout = "ospf"
		return ospf(r)
	case "bgp":
		lastRout = "bgp"
		return bgp(r)
	}
	return ""
}



func main() {
	fmt.Println("Bienvenue sur le générateur de configuration iOS\n\n Configuration de la topologie : \n")
	var routers = map[string]router{}

	n, _ := strconv.Atoi(ask("Combien de routeurs voulez-vous configurer ? ", "4"))

	for i := 0; i < n; i ++ {
		r := conf_t(i+1)
		routers[r.hostname] = r
		ask("\n\n\n\n" + r.hostname + " Has been configured, press any key to continue.", "")
	}

	for k, v := range routers{
		if "y" == ask(fmt.Sprintf("Souhaitez vous configurer le routage de %s ?", k), "y"){
			routers[k] = router{
				hostname:   v.hostname,
				interfaces: v.interfaces,
				dhcp:       v.dhcp,
				route:      routage(v),
			}
		}
	}


	for k, v := range routers{
		ask("Press any key to reveal configuration of ", k)
		fmt.Println(v)
		fmt.Println(end)
	}
}
