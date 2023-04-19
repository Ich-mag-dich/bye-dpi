from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

iface = 'en0' # 캡처할 인터페이스 이름
# 캡처된 패킷을 처리하는 함수

def send_frag_packets(target_ip, target_port, payload):
    # 패킷 세분화
    frag_packets = fragment(IP(dst=target_ip)/TCP(dport=target_port)/payload, fragsize=200)
    # 세분화된 패킷 전송
    for packet in frag_packets:
        send(packet)

def handle_packet(packet, key):
    # IP 패킷이 아닌 경우 무시
    global iface
    if not packet.haslayer(IP):
        return
    # TCP 패킷이 아닌 경우 무시
    if not packet.haslayer(TCP):
        return
    if packet.haslayer(Raw):
        # 수정된 패킷 송신
        send_frag_packets(packet[IP].dst, packet[TCP].dport, packet[Raw].load)

# 캡처 설정
filter = 'tcp' # 캡처할 패킷 필터

# 암호화를 위한 키와 초기 벡터 설정
key = get_random_bytes(16)

# 캡처 시작
sniff(iface=iface, filter=filter, prn=lambda packet: handle_packet(packet, key))

