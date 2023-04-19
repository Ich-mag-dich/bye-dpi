import socket
from scapy.all import *

protocols = {1:'ICMP', 6:"TCP", 17:"UDP"}

my_ip = get_if_addr(conf.iface)

i = 0
host = "google.com"
get_host_ip = socket.gethostbyname(host)
print(get_host_ip)

def show_packet(packet):
    
    packet.show()



if __name__ == "__main__":
    filter = "ip"
    sniff(filter=filter, prn=show_packet, count=0)
    # send( fragment(IP(dst="google.com")/ICMP()/"X"*20), verbose=0)



