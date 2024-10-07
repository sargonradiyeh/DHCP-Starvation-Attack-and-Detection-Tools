from scapy.all import sniff, DHCP, ARP, Ether, BOOTP, srp #general reference for anything scapy: https://scapy.readthedocs.io/en/latest/usage.html
from datetime import datetime, timedelta
import requests
import threading 
import time
import logging #general reference for anything logging related: https://docs.python.org/3/howto/logging.html

mac_requests= {} #dictionary to track MAC addresses and their request time
window= 60 #time window in seconds
max_unique_macaddr= 5 #threshold for unique MAC addresses within the window, modify this as you see fit, my private home shouldn't have more than 5 unique MAC addresses offered every minute
ema= max_unique_macaddr #initializing the ema to the maximum unique mac addresses that the user sets.... you can set it to 0 or anything else and it should adapt just fine.
arp_retries= 5 #number of ARP requests to verify MAC to IP mapping
slack_webhook= "https://hooks.slack.com/services/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" #Slack webhook in order to alert user of a potential DHCP starvation attack. Follow this guide to create your own: https://api.slack.com/messaging/webhooks
alpha= 0.125 #default alpha from EECE 350 slides

logging.basicConfig( #creating config for logging
    level=logging.INFO, #display all log levels from info and above ie: INFO, ERROR, WARNING, CRITICAL
    format='%(asctime)s - %(levelname)s - %(message)s', #basic formatting of the log
    handlers=[
        logging.FileHandler("dhcp_starve_monitoring.log"), #save logs to this file
        logging.StreamHandler() #display logs on console 
        ]
)

def update_ema(current_mac_count, old_ema, alpha): #Idea taken from EECE 350 slides... EstimatedRTT = (1- α)*EstimatedRTT + α*SampleRTT
    return alpha * current_mac_count + (1 - alpha) * old_ema 

def periodic_ema_update(): #the goal with this is to have changing threshold for unique mac addresses based on how the network behaves within the window
    global mac_requests  #be able to access mac_requests
    global ema #be able to access and modify ema
    while True:
        clean_old_requests()
        current_unique_macaddr_count= len(mac_requests)
        ema= update_ema(current_unique_macaddr_count, ema, alpha)  # Update EMA based on current count
        logging.info(f"Periodic EMA update: EMA={ema}, MAC Count={current_unique_macaddr_count}")
        time.sleep(window) # Sleep for window duration

def send_alert(message): #function created to send alert to slack, documentation used: https://api.slack.com/messaging/webhooks
    response=requests.post(slack_webhook, json=message)
    if response.status_code != 200: #if the status code is not OK, then the alert wasn't sent successfuly 
        logging.error(f"Failed to send alert to Slack: {response.status_code}, {response.text}")

def verify_ip_is_used(ipaddr, macaddr): #Idea inspired by https://ieeexplore.ieee.org/abstract/document/10084265
    count= 0
    arp_req_packet= Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ipaddr) #general reference for arp process: https://www.practicalnetworking.net/series/arp/traditional-arp/
    while count!=arp_retries:
        (answered, unanswered) = srp(arp_req_packet, timeout=1, verbose=False) #arp request asking Who's Ip is this? 
        if answered:
            for (sent, response) in answered:
                if response[ARP].hwsrc == macaddr: #if the source MAC address of the targetted IP is the same as the MAC address from the DHCP offer then it should return True as this implies the device actually exists
                    return True
        count+=1
    return False

def clean_old_requests():#clean up the old requests outside the time window
    global mac_requests #be able to access and modify mac_requests
    #logging.debug("Cleaning old MAC requests.") #may be used for debugging purposes
    time_now = datetime.now()
    for macaddr in list(mac_requests.keys()):
        mac_requests[macaddr] = [time for time in mac_requests[macaddr] if time > time_now - timedelta(seconds=window)] #if the time is greater the time now - window then dont include that specific time entry for that MAC entry(remove it)
        if not mac_requests[macaddr]:#remove the MAC address if no time entries are left
            del mac_requests[macaddr]

def detect_dhcp_starvation(packet):
    global mac_requests #be able to access and modify mac_requests
    global ema #be able to access ema
    if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 2:  #DHCP Offer
        offered_ip= packet[BOOTP].yiaddr  # extract the offered IP
        macaddr= packet[BOOTP].chaddr[:6] # get the MAC address from the offer
        macaddr= ":".join(f"{octet:02x}" for octet in macaddr) #make it human-readable format
        logging.info(f"Offered IP: {offered_ip} to MAC: {macaddr}")
        time_now= datetime.now()

        if macaddr not in mac_requests:
            mac_requests[macaddr]= [] #initialize the entry if the MAC address is new, we are using the DHCP offer from the server however for an offer to exists, a request must have been made...
            
        mac_requests[macaddr].append(time_now) #add the time entry to that specific MAC entry

        current_unique_macaddr_count= len(mac_requests) #count the current unique MAC addresses in the given window
        
        if not verify_ip_is_used(offered_ip, macaddr):
            logging.warning(f"Suspicious allocation for {macaddr} at {offered_ip}. No ARP reply received.")
            message= {
            "text": f":warning: DHCP Starvation Potential Attack Detected! Suspicious allocation for {macaddr} at {offered_ip}. No ARP reply received." 
            }
            send_alert(message) #warn user on slack channel of a potential attack... including the supicious MAC and its leased IP

        if current_unique_macaddr_count > ema: #if the current amount of unique mac addresses over the past minute is higher than the average of the usual amount (ema), send an alert (disregarded the use of a deviation margin in the if statement)
            logging.critical(f"High amount of unique MAC addresses detected: {current_unique_macaddr_count} unique MAC addresses in the last {window} seconds.")
            message= {
            "text": f":bangbang::warning::bangbang: DHCP Starvation Attack Detected! {current_unique_macaddr_count} unique MAC addresses in the last {window} seconds."
            }
            send_alert(message) #warn user on slack channel of a potential attack... including the count of unique MACs within the set window


def main():
    ema_update_thread = threading.Thread(target=periodic_ema_update, daemon=True) #learnt from: https://www.geeksforgeeks.org/multithreading-python-set-1/
    ema_update_thread.start() #start a separate thread for periodic ema updates

    sniff(iface='eth0', filter='udp and (port 67 or port 68)', prn=detect_dhcp_starvation) #sniff for DHCP traffic continuously

if __name__ == "__main__":
    main()
    