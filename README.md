# barpo - Bash ARP POisoner 
Author: Davide `Anathema` Barbato

Table of contents:
[1] What is barpo?
[2] Features
[3] Usage


###[1] What is barpo?
barpo is a Bash shell script that make ARP Cache poisoning easy.
The concept behind the ARP Cache Poisoning and barpo can be found here: 
http://www.areanetworking.it/arp-cache-poisoning.html (italian only)

N.B.: It requrires [nemesis](http://nemesis.sourceforge.net/)

###[2] Features
barpo not only do ARP Cache Poisoning roughly but take some actions to prevent victims to discover that they are under attack.
That is:
- TTL field: the TTL IP field is decremented every time a packet hit an host; with a traceroute a victim can detect the sniffing host. To avoid that, an iptables rule has been implemented
- Inspecting the victim ARP Cache two host (the attacker and the gateway) had the same MAC Address; barpo fakes the attacker MAC Address into victim ARP Cache

Altrought, barpo check for modules and binaries necessary to its execution. The high detailed output can be activated by the -v flag.
The poisoned packets will be sent every 10 seconds (by default) but this value can be overwritten by the -t flag.

Note that fake your IP-MAC assosiation of your targets will cause, if any, the lost of all your connection with them. As is, if you are in touch with your victims (with SSH or NFS, for example), you will loose the connection. To avoid that, use the -n flag.

###[3] Usage
Very simple usage:

~# bash barpo.sh -h 192.168.1.3 -g 192.168.1.1

will poison 192.168.1.3; the gateway is 192.168.1.1.

To poison a whole network (N.B. This will NOT fake hosts ARP cache with Your_IP-Fake_MAC):
~# bash barpo.sh -h 192.168.1.0
or
~# bash barpo.sh -h 192.168.1.0 -g 192.168.1.1 (This will fake hosts ARP cache with Your_IP-Fake_MAC)


To poison only a limited range of hosts (This will NOT fake hosts ARP cache with Your_IP-Fake_MAC):
~# bash barpo.sh -h 192.168.1.1-20
or
~# bash barpo.sh -h 192.168.1.1-20 -g 192.168.1.1 (This will fake hosts ARP cache with Your_IP-Fake_MAC)


~# bash barpo.sh -h 192.168.1.3 -g 192.168.1.1 -n (This will NOT fake hosts ARP cache with Your_IP-Fake_MAC)