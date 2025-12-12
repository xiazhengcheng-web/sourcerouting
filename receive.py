#!/usr/bin/env python3
import sys
from scapy.all import sniff, get_if_list
from scapy.all import Ether, IP, TCP
from scapy.all import bind_layers
from scapy.fields import *
from scapy.packet import Packet

# 同样的头部定义，确保接收端能解析
class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)

def handle_pkt(pkt):
    if IP in pkt or SourceRoute in pkt:
        print("got a packet")

        # 判断包类型
        if SourceRoute in pkt:
            print("Type: Source Routing Packet")
            # 打印剩余的源路由跳数
            sr_layer = pkt[SourceRoute]
            hop_count = 0
            while isinstance(sr_layer, SourceRoute):
                print(f"  - Hop port: {sr_layer.port}, BOS: {sr_layer.bos}")
                if sr_layer.bos == 1:
                    break
                sr_layer = sr_layer.payload
        elif IP in pkt:
             print(f"Type: Standard IPv4 Packet (Src: {pkt[IP].src} -> Dst: {pkt[IP].dst})")

        pkt.show2()
        sys.stdout.flush()

def main():
    iface = 'eth0'
    print(f"sniffing on {iface}")
    sniff(iface = iface,
          prn = handle_pkt)

if __name__ == '__main__':
    main()
