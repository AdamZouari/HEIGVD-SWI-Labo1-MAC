#! /usr/bin/env python

from scapy.all import *
import sys
import urllib.request as urllib2
import json
import codecs

dict = {}

# permet de récuperer le constructeur de la MAC address
def get_vendor(mac):
    
    url = "http://macvendors.co/api/"
    request = urllib2.Request(url+mac, headers={'User-Agent' : "API Browser"}) 
    response = urllib2.urlopen( request )
    reader = codecs.getreader("utf-8")
    obj = json.load(reader(response))
    return obj['result']['company']

    
# action personnalise effectuee par la methode sniff
def custom_action(packet):    

    # filtre pour recuperer seulement les probe request
    if packet.type == 0 and packet.subtype == 0x04:
        
        try:
            mac = str(packet.addr2)
            ssid = str(packet.info,"utf-8")
            org = get_vendor(mac)        
        except:
            org= "UNKNOWN"
            
        macOrg = mac + " (" + org + ") " 
        
        # si le ssid n'est pas vide
        if ssid :
            
            # si l'appareil n'as jamais ete detecte
            if macOrg not in dict:
                
                # on cree une entree pour l'appareil et on ajoute le ssid
                dict[macOrg] = [ssid]
                printApp(macOrg)
                
            # si le ssid n'as jamais ete detecte sur cet appareil    
            if ssid not in dict[macOrg]:
                
                # on ajoute le ssid a la liste et on l'affiche
                dict[macOrg] += [ssid]
                printApp(macOrg)


# affiche la liste des ssid d'un appareil
def printApp(macOrg):
    for k,v in dict.items():  
        if k == macOrg :
            print(k,v)
            
            
# demarre la detection des paquets sur l'interface wlan0mon pendant un temps defini par l'utilisateur
sniff(iface="wlan0mon" , prn=custom_action,count=0)
