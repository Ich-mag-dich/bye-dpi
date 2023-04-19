from scapy.all import *


protocols = {1:'ICMP', 6:"TCP", 17:"UDP"}

my_ip = get_if_addr(conf.iface)

def show_packet(packet):
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    proto= packet[0][1].proto
    if proto in protocols:
        if src_ip == my_ip:
            print(f"protocol: {protocols[proto]}: {src_ip} -> {dst_ip}")
        if proto == 1:
            print(f"type: {packet[0][2].type}, code: {packet[0][2].code}")

    


if __name__ == "__main__":
    filter = "ip"
    sniff(filter=filter, prn=show_packet, count=0)



