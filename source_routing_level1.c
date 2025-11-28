/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_SRCROUTING = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t; // 必须确保是 32 位

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    macAddr_t srcHwAddr;
    ip4Addr_t srcProtoAddr;
    macAddr_t dstHwAddr;
    ip4Addr_t dstProtoAddr;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

// [重点修正] 确保这里加起来等于 160 bits
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv; // 标准应该是 8 位 (包含 DSCP 和 ECN)
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    // empty
}

struct headers {
    ethernet_t         ethernet;
    arp_t              arp;
    srcRoute_t[10]     srcRoutes; 
    ipv4_t             ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_SRCROUTING: parse_srcRoute;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_srcRoute {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_ipv4;
            0: parse_srcRoute;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action arp_reply(egressSpec_t port) {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.arp.dstHwAddr;
        hdr.arp.opcode = 2;
        hdr.arp.dstHwAddr = hdr.arp.srcHwAddr;
        hdr.arp.dstProtoAddr = hdr.arp.srcProtoAddr;
        hdr.arp.srcHwAddr = hdr.arp.dstHwAddr;
        hdr.arp.srcProtoAddr = hdr.arp.dstProtoAddr;
        standard_metadata.egress_spec = port;
    }

    action ipv4_forward(egressSpec_t port, macAddr_t dstAddr) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.srcAddr = hdr.ethernet.srcAddr; 
    }

    action srcRoute_forward() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        if (hdr.srcRoutes[0].bos == 1) {
            hdr.ethernet.etherType = TYPE_IPV4;
        }
        hdr.srcRoutes.pop_front(1);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_ARP && hdr.arp.isValid()) {
            if (hdr.arp.opcode == 1) {
                if (hdr.arp.dstProtoAddr == 0x0a00010a || 
                    hdr.arp.dstProtoAddr == 0x0a000214 || 
                    hdr.arp.dstProtoAddr == 0x0a00031e) {
                    arp_reply(standard_metadata.ingress_port);
                } else {
                    standard_metadata.egress_spec = (bit<9>)0x1FF; 
                }
            }
        } 
        else if (hdr.ethernet.etherType == TYPE_SRCROUTING && hdr.srcRoutes[0].isValid()) {
            srcRoute_forward();
            if (hdr.ipv4.isValid()) {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            }
        } 
        else if (hdr.ethernet.etherType == TYPE_IPV4 && hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } 
        else {
            drop();
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
         update_checksum(
             hdr.ipv4.isValid(),
             { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
               hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
               hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
             hdr.ipv4.hdrChecksum,
             HashAlgorithm.csum16);
    }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;