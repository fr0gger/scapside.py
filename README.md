# Scapside
```
Usage: scapside.py | by R1tch1e & Bastichou 

A scapside.py is a pretty little tool to perform basic network attacks using Scapy

scapside.py [options] [arguments] 

Ex : python scapside.py --arpoison <victimIP> <routerIP> 

Ex : python scapside.py --sniffing ["filter"] 

Ex : python scapside.py --vlanhop <typeTAG> <vlanID> <vlanID> <IPsrc> <IPdst> 

Ex : python scapside.py --dhcpstar 

Ex : python scapside.py --scanner <targetIP> 

Options:

  --version             show program's version number and exit

  -h, --help            show this help message and exit

  -a, --arpoison        Start an ARP Poisonning attack

  -v, --vlanhop         Start VLAN Hopping attack

  -d, --dhcp            Start DHCP Starvation attack

  -n, --scanner         Start Port scanning
  
  -s SFILTER, --sniffing=SFILTER
  
                        Start sniffing traffic while script is running: add a
  
                        filter between double quote.
  
  -i INT, --interface=INT
  
                        Select a specific interface to perform attacks
  
  -q, --quiet           Don't show the verbose action
```
