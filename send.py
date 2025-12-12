#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import bind_layers
from scapy.fields import *

# 1. 定义 Source Routing 头部，对应 P4 中的 header srcRoute_t [cite: 6]
class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

# 绑定协议号 0x1234 [cite: 3] 到 SourceRoute
bind_layers(Ether, SourceRoute, type=0x1234)
# 如果 bos=0，下一层还是 SourceRoute；如果 bos=1，下一层是 IPv4
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)

def get_if():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address")
    parser.add_argument('message', type=str, help="The message to send")
    # 新增模式选择参数
    parser.add_argument('--mode', choices=['ipv4', 'src_route'], default='ipv4',
                        help="Send 'ipv4' packet or 'src_route' packet")
    parser.add_argument('--ports', type=int, nargs='+', help="List of egress ports for source routing (e.g. 2 3 1)")

    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    iface = get_if()

    print(f"Sending on interface {iface} to {args.ip_addr}")

    # 构造基础数据
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')

    if args.mode == 'ipv4':
        # --- 普通 IPv4 模式 ---
        print("Mode: Standard IPv4 Forwarding")
        pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
        # P4 解析器会识别 EtherType 0x0800 进入 parse_ipv4

    elif args.mode == 'src_route':
        # --- 源路由模式 ---
        if not args.ports:
            print("Error: Source routing mode requires --ports list")
            exit(1)

        print(f"Mode: Source Routing through ports: {args.ports}")

        # 递归构造源路由头
        # 端口列表反转，因为我们在栈顶压入
        port_list = list(args.ports)

        # 最后一个端口的 BOS 设为 1
        # 比如路径是 s1(p2)->s2(p3)->host，列表是 [2, 3]
        # 我们需要构造层级：Ether / SR(port=2, bos=0) / SR(port=3, bos=1) / IP

        sr_header = None
        for i, p in enumerate(port_list):
            is_last = (i == len(port_list) - 1)
            if sr_header is None:
                sr_header = SourceRoute(bos=1 if is_last else 0, port=p)
            else:
                # 注意：Scapy层级叠加通常是 Layer1 / Layer2
                # 但这里我们需要根据你的P4解析逻辑。
                # P4通常解析第一个SR头部，弹出，转发。
                # 所以发送时，最外层应该是第一跳的端口。
                # 这里简化处理，假设用户按顺序输入 [p_first, p_next, ..., p_last]
                # 我们需要把它们串起来。
                pass

        # 简单实现：
        pkt_sr = Packet()
        for i, p in enumerate(port_list):
            bos_val = 1 if i == len(port_list)-1 else 0
            pkt_sr = pkt_sr / SourceRoute(bos=bos_val, port=p)

        pkt = pkt / pkt_sr / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message
        # 设置 EtherType 为 0x1234 [cite: 3]
        pkt[Ether].type = 0x1234

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
