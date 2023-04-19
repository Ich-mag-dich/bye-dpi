from scapy.all import *
from Crypto.Cipher import AES
from scapy.layers.tls.all import *
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
# from scapy_ssl_tls.ssl_tls import TLS_Ext_SNI
import hashlib

# 사이트 별로 다른 키를 사용하여 암호화할 수 있도록 사전을 만듦
keys = {'www.example.com': 'your-key-here', 'www.google.com': 'another-key'}

def encrypt_sni(sni):
    sni_bytes = sni.encode()
    # Pad SNI bytes to 16-byte boundary
    key = get_random_bytes(16)
    iv = b'0000000000000000'  # 초기화 벡터
    cipher = AES.new(key, AES.MODE_CBC, iv)
    sni_padded = pad(sni_bytes, AES.block_size)
    # Encrypt padded SNI bytes with AES cipher
    encrypted_sni = cipher.encrypt(sni_padded)
    return encrypted_sni

def packet_callback(packet):
    if packet.haslayer(TLSClientHello):
        # SNI 필드를 가져옴
        sni = packet.getlayer(TLSClientHello)[ServerName].servername.decode()
        print(f"Captured SNI: {sni}")
        # 키를 사용하여 암호화
        key = get_random_bytes(16)
        iv = b'0000000000000000'  # 초기화 벡터
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_sni = encrypt_sni(sni)
        print(f"Encrypted SNI: {encrypted_sni.hex()}")
        # 암호화된 SNI 필드로 대체
        packet.getlayer(TLSClientHello)[ServerName].servername = encrypted_sni
        print(f"enc: {encrypted_sni}")
        # something wrong here
        # packet.getlayer(TLSClientHello)[ServerName].servername = b'www.google.com'
        print(packet.getlayer(TLSClientHello)[ServerName].servername)
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        # 수정된 패킷 전송
        send(packet, iface="en0")

# 패킷 캡처 시작
sniff(filter="tcp port 443", prn=packet_callback)
