#!/usr/bin/env python3
import argparse
import os
import sys
import grpc

# 导入 P4Runtime 库 (假设路径结构与之前一致)
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def writeIpv4Rules(p4info_helper, sw, dst_ip_addr, dst_mac, out_port):
    """
    下发 IPv4 转发规则到 ipv4_lpm 表
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_mac,
            "port": out_port
        })
    sw.WriteTableEntry(table_entry)
    print(f"Installed IPv4 rule on {sw.name}: {dst_ip_addr}/32 -> Port {out_port}, NextHop {dst_mac}")

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print(f"({status_code.name})", end=' ')
    traceback = sys.exc_info()[2]
    print(f"[{traceback.tb_frame.f_code.co_filename}:{traceback.tb_lineno}]")

def main(p4info_file_path, bmv2_file_path):
    # 初始化 P4Info helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # 1. 建立与交换机的连接
        # S1: gRPC port 50051, device_id 0
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', address='127.0.0.1:50051', device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        
        # S2: gRPC port 50052, device_id 1
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2', address='127.0.0.1:50052', device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        
        # S3: gRPC port 50053, device_id 2
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
        # 4. 下发 IPv4 转发规则
        # 根据 topologe.txt:
        #   h1: 10.0.1.1, mac 08:00:00:00:01:11 (接 s1-p1)
        #   h2: 10.0.2.2, mac 08:00:00:00:02:22 (接 s2-p1)
        #   h3: 10.0.3.3, mac 08:00:00:00:03:33 (接 s3-p1)
        #
        #   s1 端口: p1->h1, p2->s2, p3->s3
        #   s2 端口: p1->h2, p2->s1, p3->s3
        #   s3 端口: p1->h3, p2->s1, p3->s2
        # ----------------------------------------------------------------

        print("\n--- Installing IPv4 Forwarding Rules on S1 ---")
        # S1 -> H1 (直连)
        writeIpv4Rules(p4info_helper, s1, "10.0.1.1", "08:00:00:00:01:11", 1)
        # S1 -> H2 (经 S2-port2)
        writeIpv4Rules(p4info_helper, s1, "10.0.2.2", "08:00:00:00:02:22", 2)
        # S1 -> H3 (经 S3-port3)
        writeIpv4Rules(p4info_helper, s1, "10.0.3.3", "08:00:00:00:03:33", 3)

        print("\n--- Installing IPv4 Forwarding Rules on S2 ---")
        # S2 -> H1 (经 S1-port2)
        writeIpv4Rules(p4info_helper, s2, "10.0.1.1", "08:00:00:00:01:11", 2)
        # S2 -> H2 (直连)
        writeIpv4Rules(p4info_helper, s2, "10.0.2.2", "08:00:00:00:02:22", 1)
        # S2 -> H3 (经 S3-port3)
        writeIpv4Rules(p4info_helper, s2, "10.0.3.3", "08:00:00:00:03:33", 3)

        print("\n--- Installing IPv4 Forwarding Rules on S3 ---")
        # S3 -> H1 (经 S1-port2)
        writeIpv4Rules(p4info_helper, s3, "10.0.1.1", "08:00:00:00:01:11", 2)
        # S3 -> H2 (经 S2-port3)
        writeIpv4Rules(p4info_helper, s3, "10.0.2.2", "08:00:00:00:02:22", 3)
        # S3 -> H3 (直连)
        writeIpv4Rules(p4info_helper, s3, "10.0.3.3", "08:00:00:00:03:33", 1)

        print("\nRules installation complete.")

        # 注意：源路由 (Source Routing) 不需要下发流表规则。
        # P4 程序中的解析器和 Apply 逻辑会自动根据包头中的端口进行转发。

    except KeyboardInterrupt:
        print("\nShutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for Source Routing & IPv4')
    # 默认路径指向 build 目录下的文件
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