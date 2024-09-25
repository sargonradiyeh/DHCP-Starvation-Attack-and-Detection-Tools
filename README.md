# DHCP starvation
_____

# I) Definition:
____
DHCP starvation attack is a malicious digital attack that target DHCP servers. During attack, a hostile actor floods a DHCP server with Discover packets until the DHCP server exhausts its supply of IP addresses. Once that happens, the attacker can deny legitimate network users service, or even supply an alternate DHCP connection that leads to a MITM attack.


# II) Procedure
____

To understand this attack, we must first refresh our networking concepts, especially the DHCP protocol.  DHCP which is short for Dynamic Host Configuration protocol is used to allow hosts to automatically and dynamically lean various aspect of their network configuration such as IP addresses, subnet mask, default gateway, DNS server without manual/static configuration.

DHCP servers usually use UDP on port 67, while the clients uses DHCP UDP n port 68. In small networks the router typically acts as the DHCP server for hosts in the LAN, while on larger network the DHCP server is a windows/Linux server.

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


