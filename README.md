# DHCP Starvation Attack and Detection Tools

## Objective
Our objective for this assignment is to create a network attack along with a corresponding detection method. We chose to focus our efforts on the topic of DHCP starvation.

# Definition:
DHCP starvation attack is a malicious digital attack that target DHCP servers. During attack, a hostile actor floods a DHCP server with Discover packets until the DHCP server exhausts its supply of IP addresses. Once that happens, the attacker can deny legitimate network users service, or even supply an alternate DHCP connection that leads to a MITM attack.

## Description of Tools

### DHCP Starvation Attack
- **Purpose:** To simulate a DHCP starvation attack.
- **How It Works:**
  - Sends forged DHCP Discover requests with randomized MAC addresses.
  - Each request mimics a unique device by using a different random MAC address.
  - Uses a randomized sleep timer (between 1 to 5 seconds) between requests to reduce the chance of early detection.
  - Prints the offered IP address upon receiving a DHCP offer, allowing the user to monitor available IPs.
  - If no more IPs are available, a message is printed indicating the exhaustion of the DHCP pool.

### DHCP Starvation Detection
- **Purpose:** To monitor network traffic for potential DHCP starvation attacks and notify users in real-time.
- **How It Works:**
  - Utilizes the `scapy` library to capture DHCP and ARP packets.
  - Maintains a record of MAC addresses and their request times within a sliding time window.
  - Sets an initial threshold for the maximum number of unique MAC addresses expected in a given time window.
  - Uses an Exponential Moving Average (EMA) to dynamically adjust the threshold based on network conditions.
  - Runs a separate thread to update the EMA and clean up old MAC address entries.
  - If the count of unique MAC addresses exceeds the EMA, an alert is sent to a Slack channel.
  - Sends ARP requests for each DHCP offer to verify if the IP is actively used by the device. If the ARP reply's source MAC does not match the DHCP offer or no reply is received, the allocation is flagged as suspicious, and a Slack alert is sent.
  - Logs all activities and detections to both a log file and the console for further review.

## How to Run the Tools

### Windows
1. Open a terminal (e.g., PowerShell) with administrative privileges (right-click and select "Run as Administrator").
2. Navigate to the project folder.
3. Run the following commands in separate terminals:
   - `python attack.py`
   - `python detection.py`

### Linux
1. Open a terminal.
2. Navigate to the project folder.
3. Run the following commands in separate terminals (with sudo privileges):
   - `sudo python attack.py`
   - `sudo python detection.py`

*Note: Ensure that you are in the correct directory. These tools can be tested on any device with access to a DHCP server. We tested the tools using VMware’s built-in DHCP server in NAT mode for a safe and controlled environment.*

## DHCP Procedure

![image](https://github.com/user-attachments/assets/1bc05d95-bff5-48f4-ae7b-b4c3cc7debbf)

As we see in the picture above, we will explain in the following the several DHCP messages:

1) DHCP Discover message: It broadcasts a message searching for the DHCP server in the network saying it needs an IP address we can see it in the following picture using Wireshark we see that the the destination MAC address is all "ff:ff:ff:ff:ff".<!--⚠️Imgur upload failed, check dev console-->
![image](https://github.com/user-attachments/assets/14fdea8d-85a4-444f-b8e3-1a5261cfb88f)


2) DHCP offer message: it basically give an IP address, as well as other information like the default gateway, DNS server and other information.<!--⚠️Imgur upload failed, check dev console-->
![image](https://github.com/user-attachments/assets/38066400-7b8e-4806-8c6b-3e9dcdcac04f)


3) DHCP request message: The client tells the DHCP server it wants to use the IP address the server has offered. The main purpose of this message: assume that we have many DHCP servers in the network, this message will indicate which DHCP server the client is actually pointing out. Usually the client will accept the first offer it receives.![image](https://github.com/user-attachments/assets/b3c9c7c6-b44c-4b02-a006-be8e9d3445f8)


4) DHCP ACK message: It is telling that is has agreed, and has assigned the IP address with the other corresponding filed to the host <!--⚠️Imgur upload failed, check dev console-->
![image](https://github.com/user-attachments/assets/eb63a76a-e826-41e6-a97c-5365f3532c1e)



After understand the whole protocol, the attack is the following: the attacker initiate a large sequence of DHCP discover packets making the server think that there are suddenly several host that are trying to connect to the network, thus it needs to accommodate  for all the available host by assigning to them corresponding IPs from the range (2-254) assuming that the IPs ending with the following: ["0", "1", "255"] are all reserved in the network. Thus denying access to all the new "legitimate" clients or even getting this attack much more further by assigning the attacker machine as an DHCP server.


## Testing

### Legitimate Devices Requesting DHCP Leases
- **Test:** A legitimate device requests a DHCP lease.
- **Observation:** The detection tool correctly records the DHCP offer and corresponding ARP reply. No suspicious IP allocation warning is generated, and the MAC address count is used to establish a baseline threshold.

### Illegitimate Devices Requesting DHCP Leases
- **Test:** Launch an attack by sending crafted DHCP Discover messages.
- **Observation:**
  - The attack tool successfully sends requests with randomized MAC addresses, exhausting the DHCP pool as seen on Wireshark.
  - The detection tool identifies the illegitimate offers by sending ARP requests. Since there is no valid ARP reply for these forged requests, the IP-MAC pair is flagged as suspicious.
  - Once the number of unique MAC addresses exceeds the EMA threshold, a critical warning is sent to a Slack channel and logged.

## Team Contribution
- **Detection Tool (100%):** Sarjoun Radiyeh
- **Attack Tool (100%):** Samer Saade



