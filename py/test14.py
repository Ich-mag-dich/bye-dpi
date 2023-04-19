import socket, ssl
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.http import *

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_default_certs()

sni = "hitomi.la"
SNI = "www.google.com"
SNI2 = "hItOmI.lA"
HOST = "hitomi.la"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = context.wrap_socket(s, server_hostname=SNI)
ssl_sock.connect((HOST, 443))

ssl_sock.send(b"GET / HTTP/1.1\r\nhoSt:%b\r\n\r\n" % sni.encode())

print(b"GET / HTTP/1.1\r\nhoSt:%b\r\n\r\n" % sni.encode())

res = ssl_sock.recv(100000000)


with open("test2.html", "w") as f:
    f.write(res.decode())
print(f"\n\nres:\n\n{res}\n\n")