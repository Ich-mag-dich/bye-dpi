from scapy.all import *
from scapy.layers.tls.all import *
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

print(f"my_ip: {my_ip}")

def test(packet):
    if packet[0][1].src != my_ip:
        return
    if packet.haslayer(TLSClientHello) == False:
        pass
        return
    # if packet.getlayer(TLSClientHello)[ServerName].servername != b'hitomi.la':
    #     return
    if packet[0][1].src != my_ip: 
        return
    del packet[TCP][ServerName].servername
    # packet.getlayer(TLSClientHello)[ServerName].servername = b'google.com'
    # if packet[0][1].dst != "88.80.31.197":
    #     return
    print(f"server name: {packet.getlayer(TLSClientHello)[ServerName].servername}")
    print(f"DST: {packet[0][1].dst}")
    print(f"SRC: {packet[0][1].src}")
    
    # packet.getlayer(TLSClientHello)[ServerName].servername = b'HItOMl.lA'
    
    frags = fragment(packet, fragsize=1000)
    # for i in frags:
    #     sr(i, iface="en0")
    
    # packet.show2()
    # print(packet.getlayer(TLSClientHello)[ServerName].servername)
    # send(packet, iface="en0")
    if packet.getlayer(Raw) != None:
        # print(bytes_hex(packet.getlayer(Raw).load).decode())
        print(bytes_hex(packet))
    # print(packet.fields)
        

sniff(filter="tcp port 443", prn=test)