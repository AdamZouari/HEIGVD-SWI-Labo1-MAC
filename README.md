# Sécurité des réseaux sans fil

## Laboratoire 802.11 MAC
###### Auteurs : Nair Alic, Adam Zouari

### 1. Détecter si un ou plusieurs clients 802.11 spécifiques sont à portée

Script : 

```python
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

```

- Quel type de trames sont nécessaires pour détecter les clients de manière passive ?

	Probe requests

- Pourquoi le suivi n'est-il plus possible sur iPhone depuis iOS 8 ?</br>
	
	Car depuis iOS 8 Apple a introduit une randomization de l'adresse MAC quand il scanne passivement des reseaux WiFi


### 2. Clients WiFi bavards

```python
#! /usr/bin/env python3.5

from scapy.all import *
import sys

dict = {}

# action personnalise effectuee par la methode sniff
def custom_action(packet):    
    
    # filtre pour recuperer seulement les probe request
    if packet.type == 0 and packet.subtype == 0x04:
        try:
            mac = str(packet.addr2)
            ssid = str(packet.info,"utf-8")
            org = mac.oui.registration().org                
        except:
            org= "UKNOWN"
            
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
        
try:
    time = int(sys.argv[1])
except:
    print("Please give the sniffing time (in seconds) in argument ")
    sys.exit(1)
   
# demarre la detection des paquets sur l'interface wlan0mon pendant un temps defini par l'utilisateur
sniff(iface="wlan0mon" , prn=custom_action, timeout=time ,count=0)

# affiche les ssid detectes sur l'ensemble des appareils
print("\n------------------------------- Summary of findings ----------------------------------\n")
for k,v in dict.items():  
    print(k,v)
```
