import socket
from scapy.all import *

my_ip = get_if_addr(conf.iface)

def encrypt(payload):
    # 패딩
    length = 16 - (len(payload) % 16)
    payload += bytes([length])*length
    return payload

def decrypt(payload):
    # 언패딩
    padding_length = payload[-1]
    decrypted = decrypted[:-padding_length]
    return decrypted

def send_frag_packets(target_ip, target_port, payload):
    # 패킷 세분화
    frag_packets = fragment(IP(dst=target_ip)/TCP(dport=target_port)/payload, fragsize=200)
    # 세분화된 패킷 전송
    for packet in frag_packets:
        send(packet)

def recieve_frag_packets(port):
    # 소켓 생성
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.bind(('127.0.0.1', port))

    # 패킷 조합을 위한 버퍼
    packet_buffer = {}

    while True:
        # 패킷 수신
        packet = sock.recvfrom(65535)[0]

        # IP 패킷 추출
        ip_packet = IP(packet)

        # IP 패킷이 세분화되었는지 확인
        if ip_packet.flags == 1:
            # 세분화된 패킷을 조합하여 패킷 버퍼에 추가
            if ip_packet.id not in packet_buffer:
                packet_buffer[ip_packet.id] = []

            packet_buffer[ip_packet.id].append(ip_packet)

            # 모든 세분화된 패킷을 수신한 경우, 패킷 조합
            if ip_packet.fragoff & 0x1FFF == 0:
                fragments = sorted(packet_buffer[ip_packet.id], key=lambda x: x.fragoff)

                # 세분화된 패킷의 암호화된 페이로드 조합
                decrypted_payload = b"".join([x.payload for x in fragments])


                print("Received fragmented packet:", decrypted_payload)

                # 패킷 버퍼 초기화
                del packet_buffer[ip_packet.id]
                break
        else:
            # 암호화된 페이로드 복호화
            decrypted_payload = ip_packet.payload

            print("Received packet:", decrypted_payload)
            break

def prl(packet):
    # check packet's destination is my ip
    if packet[0][1].dst == my_ip:
        try:
            # recieve_frag_packets(packet[0][1].dport)
            pass
        except:
            pass
        
    else:
        try:
            print(packet[0][1].dport)
            send_frag_packets(packet[0][1].dst, packet[0][1].dport, packet[0][1].payload)
        except:
            pass

if __name__ == "__main__":
    sniff(filter="tcp", prn=prl, count=0)