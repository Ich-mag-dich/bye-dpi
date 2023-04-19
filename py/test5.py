from scapy.all import *
import socket



def _dpi_send(host, port, data, fragment_size=0, fragment_count=0):
    sock = socket.create_connection((host, port), 10)
    if fragment_count:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    try:
        for fragment in range(fragment_count):
            sock.sendall(data[:fragment_size].encode())
            data = data[fragment_size:]
        sock.sendall(data.encode())
        recvdata = sock.recv(8192)
        recv = recvdata
        while recvdata:
            recvdata = sock.recv(8192)
            recv += recvdata
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
    return recv

def show_packet(packet):
    # packet.tcp.rst = False
    # packet[TCP].flags = "PA"
    # print(packet[0][1].dst)
    print(packet)
    packet[0][1].payload = str(packet[0][1].payload).replace("Host", "hoSt")
    # print(packet[0][1].payload)  
    # send(packet)
    try:
        print("sending")
        # send(_dpi_send(packet[0][1].dst, 443, str(packet[0][1].payload), fragment_size=20, fragment_count=0), verbose=0)
        print(_dpi_send(packet[0][1].dst, 443, str(packet[0][1].payload), fragment_size=20, fragment_count=10))
    except:
        print("error")

def test(packet):
    print(packet)

if __name__ == "__main__":
    filter = "tcp port 443"    
    # sniff(filter=filter, prn=test, count=0)
    _dpi_send("google.com", 443, "GET / HTTP/1.1\r", fragment_size=20, fragment_count=10)