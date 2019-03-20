#! /usr/bin/env python 

from scapy.all import *
import sys

# action personnalise effectuee par la methode sniff
def custom_action(packet):
    
    # only prob request
    if packet.type !=0 or packet.subtype != 0x04:
        return
    elif packet.addr2 == mac:
        print "The target is here"
        sys.exit(0) 

try:
    mac = sys.argv[1]
except:
    print("Please give the address of the target in argument ")
    sys.exit(0)
    
# demarre la detection des paquets provenant de l'adresse MAC donne par l'utilisateur
sniff(iface="wlan0mon", filter="ether src "+mac , prn=custom_action, count=0)
