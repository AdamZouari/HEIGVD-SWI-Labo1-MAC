#! /usr/bin/env python 3.5

from scapy.all import *
import sys

def custom_action(packet):
    
    # only prob request
    if packet.type !=0 or packet.subtype != 0x04:
        return
    else:
        return "The target is here" 

# demarre la detection des paquets provenant de l'adresse MAC donne par l'utilisateur
sniff(iface="wlan0mon", filter="ether src "+sys.argv[1] , prn=custom_action, count=0)
