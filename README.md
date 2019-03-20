# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC
###### Auteurs : Nair Alic, Adam Zouari

### 1. Détecter si un ou plusieurs clients 802.11 spécifiques sont à portée

Script : 

```python
#! /usr/bin/env python 

from scapy.all import *
import sys

# action personnalisee effectuee par la methode sniff
def custom_action(packet):
    
    # uniquement les probe requests
    if packet.type !=0 or packet.subtype != 0x04:
        return
    elif packet.addr2 == mac:
        print ("The target is here")
        sys.exit(0)

try:
    mac = sys.argv[1]
except:
    print("Please give the address of the target in argument ")
    sys.exit(0)
    
# demarre la detection des paquets provenant de l'adresse MAC donne par l'utilisateur
sniff(iface="wlan0mon", filter="ether src "+mac , prn=custom_action, count=0)
```

- Quel type de trames sont nécessaires pour détecter les clients de manière passive ?
 
	Il s'agit des probe requests car les appareils des clients s'annonçent au monde entier en devoilant leurs adresses MAC ainsi que les SSID des réseaux utilisés.

- Pourquoi le suivi n'est-il plus possible sur iPhone depuis iOS 8 ?</br>
	
	Depuis iOS 8, Apple a introduit une randomization de l'adresse MAC quand l'iPhone scanne passivement les reseaux WiFi. C'est ce mécanisme qui rend impossible le suivi de ceux-ci.


### 2. Clients WiFi bavards

```python
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
```
