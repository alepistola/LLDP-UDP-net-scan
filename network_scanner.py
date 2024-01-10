import struct
import sys
import socket
import os
import threading
import time
from netaddr import IPNetwork, IPAddress

# host to listen on
host = "192.168.1.153"
# subnet to target
subnet = "192.168.1.0/24"

# signature to search for in the ICMP responses message
signature = "retidicalcolatori"

# used to send udp messages across all the subnet (random port 65212)
def udp_sender(subnet, singature):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(signature.encode(),("%s" % ip, 65212))
        except:
            pass

# function used to unpack the ethernet header (unpack format: https://docs.python.org/2/library/struct.html)
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

# function used to unpack the lldp header
def lldp_head(raw_data):
    valid_payload = 1
    tlvs = {}
    cap = {}
    while(valid_payload):
        tlv_header = struct.unpack("!H", raw_data[:2])[0]
        tlv_type = tlv_header >> 9
        tlv_len = (tlv_header & 0x01ff)
        lldpDU = raw_data[2:tlv_len + 2]

        # type = 0 -> last tlv
        if tlv_type == 0:
            valid_payload = 0
        # type 1 and 2 contain a subtype field of 1 byte size
        elif tlv_type == 1 or tlv_type == 2:
            tlv_subtype = struct.unpack("!B", lldpDU[0:1])[0]
            tlv_datafield = lldpDU[1:tlv_len]
            if(tlv_subtype == 1): tlv_subtype = "interface alias"
            if(tlv_subtype == 3): tlv_subtype = "mac address"
            if(tlv_subtype == 4): tlv_subtype = "network address"
            if(tlv_subtype == 5): tlv_subtype = "interface name"
        
        elif tlv_type == 8:
            ip_length = struct.unpack("!B", lldpDU[0:1])[0]
            ip_version = struct.unpack("!B", lldpDU[1:2])[0]
            if(ip_version == 1): # ipv4 = 1 and ipv6 = 2
                ip = struct.unpack("!4B", lldpDU[2:ip_length+1])
                tlv_datafield = get_ip(ip)
        else:
            tlv_datafield = lldpDU[:tlv_len]

        if tlv_type == 1:
            tlvs["ChassisID"] = str(tlv_subtype) + " " + get_mac_addr(tlv_datafield)
        elif tlv_type == 2:
            tlvs["PortID"] = str(tlv_subtype) + " " + get_mac_addr(tlv_datafield)
        elif tlv_type == 3:
            tlvs["TTL"] = struct.unpack("!H", tlv_datafield)[0] 
        elif tlv_type == 4:
            tlvs["Port Description"] = tlv_datafield.decode()
        elif tlv_type == 5:
            tlvs["Sys name"] = tlv_datafield.decode()
        elif tlv_type == 6:
            tlvs["Sys Description"] = tlv_datafield.decode()
        elif tlv_type == 7:
            bitmap = struct.unpack("!4B", tlv_datafield)
            capacities = bitmap[1]
            activated = bitmap[3]
            if(capacities & 0x1): cap["Other"] = "off"
            if(capacities & 0x2): cap["Repeater"] = "off"
            if(capacities & 0x4): cap["Bridge"] = "off"
            if(capacities & 0x8): cap["Wlan AP"] = "off"
            if(capacities & 0x10): cap["Router"] = "off"
            if(capacities & 0x20): cap["Telephone"] = "off"
            if(capacities & 0x40): cap["Docsis cable"] = "off"
            if(capacities & 0x80): cap["Station"] = "off"
            if(activated & 0x1 & capacities): cap["Other"] = "on"
            if(activated & 0x2 & capacities): cap["Repeater"] = "on"
            if(activated & 0x4 & capacities): cap["Bridge"] = "on"
            if(activated & 0x8 & capacities): cap["Wlan AP"] = "on"
            if(activated & 0x10 & capacities): cap["Router"] = "on"
            if(activated & 0x20 & capacities): cap["Telephone"] = "on"
            if(activated & 0x40 & capacities): cap["Docsis cable"] = "on"
            if(activated & 0x80 & capacities): cap["Station"] = "on"
            tlvs["Sys Capability"] = cap
        elif tlv_type == 8:
            tlvs["Mgmt Addr"] = tlv_datafield
        else:
            pass

        # point to the next tlv
        raw_data = raw_data[2 + tlv_len:]
    return tlvs
        
#function for unpacking IPv4 header
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data

#function for unpacking icmp header
def icmp_head(raw_data, signature):
    icmp_header = raw_data[:2]
    icmp_type, code = struct.unpack('! B B', icmp_header)
    signature = raw_data[len(raw_data) - len(signature):]
    return icmp_type, code, signature.decode()

# converts mac addresses from bytes to human readable format
def get_mac_addr(addr):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0] , addr[1] , addr[2], addr[3], addr[4] , addr[5])
    return b

#converts ip addresses the standar way
def get_ip(addr):
    return '.'.join(map(str, addr))

def main():

    # host and device found
    hosts = []
    devices = []

    print("[!] Starting the sender thread")
    # start sending packets using a new thread to avoid interferences
    t = threading.Thread(target=udp_sender, args=(subnet, signature))
    t.start()

    print("[!] Now sniffing on interface..  [CTRL-C to stop]")
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #ntohs -> endian swap (0x0003) -> captures all packets
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            eth = ethernet_head(raw_data)
            # checking if eth frame is containing a IPv4 packet as payload (0x0800)
            if eth[2] == 8:
                ipv4 = ipv4_head(eth[3])
                #checking if the ipv4 packet is trasporting an ICMP message
                if ipv4[3] == 1:
                    icmp = icmp_head(ipv4[6], signature)
                    #checking for type and code = 3
                    if(icmp[0] == 3 and icmp[1] == 3):
                        # make sure it has the signature
                        if icmp[2] == signature:
                            # check if it is a duplicate
                            if(((ipv4[4], eth[1]) not in hosts) and ipv4[4] != host):
                                hosts.append((ipv4[4], eth[1]))
                                print("[+] Host Up: {} - {} (ICMP reply)".format(ipv4[4], eth[1]))
            # checking if eth frame is a LLDP packet (socket.htons(0x88CC) == 52360)
            elif eth[2] == 52360:
                lldp = lldp_head(eth[3])
                if(len(lldp) > 0 and ((lldp["ChassisID"], lldp["PortID"]) not in devices)):
                    devices.append((lldp["ChassisID"], lldp["PortID"]))
                    print("[+] Device found (LLDP):")
                    for key in lldp:
                        if(key == "Sys capability"):
                            for subkey in lldp[key]:
                                print("\t\t%s: %s" % (subkey, lldp[key][subkey]))
                        print("\t%s: %s" % (key, lldp[key]))
    # handle CTRL-C
    except KeyboardInterrupt:
        print("\nQuitting..")

if __name__ == "__main__":
    main()