#!/usr/bin/env python3
import argparse
import os
import sys
import grpc

# 导入 P4Runtime 库
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def writeSourceRoutingRules(p4info_helper, sw, dst_ip_addr, dst_mac, port_list):
    """
    下发源路由封装规则到 ipv4_src_route_tbl 表
    dst_ip_addr: 目标 IP
    dst_mac: 最终主机的 MAC 地址 (解决透明 Ping 的关键)
    port_list: 路径上每一跳交换机的出口端口列表 [switch1_out, switch2_out, ...]
    """
    num_hops = len(port_list)
    action_name = ""
    action_params = {}

    if num_hops == 2:
        action_name = "MyIngress.insert_srcRoute_2hops"
        action_params = {
            "p1": port_list[0],
            "p2": port_list[1],
            "dstMac": dst_mac
        }
    elif num_hops == 3:
        action_name = "MyIngress.insert_srcRoute_3hops"
        action_params = {
            "p1": port_list[0],
            "p2": port_list[1],
            "p3": port_list[2],
            "dstMac": dst_mac
        }
    else:
        print(f"Error: No action defined for {num_hops} hops in P4 program.")
        return

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_src_route_tbl",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name=action_name,
        action_params=action_params
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed Source Route on {sw.name}: IP {dst_ip_addr} -> Path {port_list} -> MAC {dst_mac}")

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print(f"({status_code.name})", end=' ')
    traceback = sys.exc_info()[2]
    print(f"[{traceback.tb_frame.f_code.co_filename}:{traceback.tb_lineno}]")

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # 1. 建立与交换机的连接
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', address='127.0.0.1:50051', device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2', address='127.0.0.1:50052', device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3', address='127.0.0.1:50053', device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # 2. 发送 MasterArbitrationUpdate
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # 3. 安装 P4 程序
        for sw in [s1, s2, s3]:
            sw.SetForwardingPipelineConfig(
                p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
            print(f"Installed P4 Program on {sw.name}")

        # ----------------------------------------------------------------
        # 4. 下发源路由规则
        # 目标 MAC 地址 (来自 topology.txt)
        h1_mac = "08:00:00:00:01:11"
        h2_mac = "08:00:00:00:02:22"
        h3_mac = "08:00:00:00:03:33"

        # 拓扑连接参考:
        # s1: p1-h1, p2-s2, p3-s3
        # s2: p1-h2, p2-s1, p3-s3
        # s3: p1-h3, p2-s1, p3-s2

        print("\n--- Installing Source Routing Rules on S1 ---")
        # H1 -> H2 (Path: S1 -> S2 -> H2)
        # S1 出口: 2, S2 出口: 1
        writeSourceRoutingRules(p4info_helper, s1, "10.0.2.2", h2_mac, [2, 1])
        # H1 -> H3 (Path: S1 -> S3 -> H3)
        # S1 出口: 3, S3 出口: 1
        writeSourceRoutingRules(p4info_helper, s1, "10.0.3.3", h3_mac, [3, 1])

        # H1 ping 自己的网关或同一子网不需要源路由，通常由 arp_reply 处理或本地转发，
        # 但为了完整性，如果 ping 10.0.1.1 (自己)，S1 可以直接转发回 p1
        # writeSourceRoutingRules(p4info_helper, s1, "10.0.1.1", h1_mac, [1]) # 特殊情况，暂不处理

        print("\n--- Installing Source Routing Rules on S2 ---")
        # H2 -> H1 (Path: S2 -> S1 -> H1)
        # S2 出口: 2, S1 出口: 1
        writeSourceRoutingRules(p4info_helper, s2, "10.0.1.1", h1_mac, [2, 1])
        # H2 -> H3 (Path: S2 -> S3 -> H3)
        # S2 出口: 3, S3 出口: 1
        writeSourceRoutingRules(p4info_helper, s2, "10.0.3.3", h3_mac, [3, 1])

        print("\n--- Installing Source Routing Rules on S3 ---")
        # H3 -> H1 (Path: S3 -> S1 -> H1)
        # S3 出口: 2, S1 出口: 1
        writeSourceRoutingRules(p4info_helper, s3, "10.0.1.1", h1_mac, [2, 1])
        # H3 -> H2 (Path: S3 -> S2 -> H2)
        # S3 出口: 3, S2 出口: 1
        writeSourceRoutingRules(p4info_helper, s3, "10.0.2.2", h2_mac, [3, 1])

        print("\nRules installation complete.")

    except KeyboardInterrupt:
        print("\nShutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for Transparent Source Routing')
    parser.add_argument('--p4info', type=str, default='./build/source_routing.p4.p4info.txt',
                        help='P4info text file')
    parser.add_argument('--bmv2-json', type=str, default='./build/source_routing.json',
                        help='BMv2 JSON file')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print(f"\nError: P4Info file not found: {args.p4info}")
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print(f"\nError: BMv2 JSON file not found: {args.bmv2_json}")
        parser.exit(1)

    main(args.p4info, args.bmv2_json)
