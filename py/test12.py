from scapy.all import *
from scapy.layers.tls.all import *
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

print(my_ip)

def test(packet):
    try:
        if packet.haslayer(TLSClientHello) and packet.getlayer(TLSClientHello)[ServerName].servername == b'hitomi.la':
            if packet[0][1].src == my_ip:
                print("my packet")
                packet.getlayer(TLSClientHello)[ServerName].servername = b'google.com'
                return packet
    except:
        pass
        

sniff(filter="tcp port 443", prn=test)