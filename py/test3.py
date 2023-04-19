#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from scapy.layers.inet import _IPOption_HDR

def handle_pkt(pkt):
    pkt.show()
    # hexdump(pkt)


def main():
    iface = "en0"
    print(f"sniffing on {iface}")
    sys.stdout.flush()
    sniff(iface = iface,
        prn = handle_pkt)

if __name__ == '__main__':
    main()