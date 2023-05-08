import socket, ssl
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.http import *

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

res = ""

def packet_callback(packet):
    global res
    if packet.haslayer(TLSClientHello) and packet.getlayer(TLSClientHello)[ServerName].servername == b'hitomi.la' and packet[0][1].src == my_ip:
        print("-----------------------------------\n")
        print(packet[0][1].src)
        try:
            sni = packet.getlayer(TLSClientHello)[ServerName].servername.decode()
        except:
            sni = packet.getlayer(TLSClientHello)[ServerName].servername
            print(packet.getlayer(TLSClientHello)[ServerName].servername)
            print("something wrong")
        # print(packet.getlayer(TLSClientHello)[ServerName])
        packet.getlayer(TLSClientHello)[ServerName].servernamelen = 14
        packet.getlayer(TLSClientHello)[ServerName].servername = b'google.com'
        # print(packet.getlayer(TLSClientHello)[ServerName].servername)
        # packet.show()

        dst = socket.gethostbyname(sni)
        packet[0][1].dst = dst
        new_packet = packet[IP] / packet[TCP] / packet[TLS] 
        del new_packet[IP].chksum
        new_packet.getlayer(TLSClientHello)[ServerName].servername = b'google.com'
        # print(f"{sni}, {dst}")
        del new_packet[TCP].chksum
        del new_packet[IP].payload.chksum
        # new_packet.show()

        # frags = fragment(new_packet)
        # for i in frags:
        #     # print(i)
        #     send(i, iface="en0")
            
        # sendp(new_packet, iface="en0")
        
        
        # sendp(packet, iface="en0")
        # if sni != "hitomi.la":
        #     return

        
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_default_certs()
        print(f"Captured SNI: {sni}")
        SNI = "www.google.com"
        HOST = sni
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname="www.google.la")
        ssl_sock.connect((HOST, 443))

        ssl_sock.send(b"GET / HTTP/1.1\r\nhoSt:%b\r\n\r\n" % sni.encode())

        print(b"GET / HTTP/1.1\r\nhoSt:%b\r\n\r\n" % sni.encode())
       
        res = ssl_sock.recv(100000000)
        print(f"\n\n{res}\n\n")
        print("-----------------------------------\n")
        with open("test.html", "w") as f:
            f.write(res.decode())
        
        # replace received packet's data to this res data
        packet = res
        
        ssl_sock.close()
    elif packet[0][1].dst == my_ip and packet[0][1].src == "88.80.31.197":
        print("-----------------------------ww------\n")
        if res != "":
            packet = res
            # print(packet.getlayer(HTTPResponse))



SNI = 'www.google.com'


sniff(filter="tcp port 443", prn=packet_callback, )