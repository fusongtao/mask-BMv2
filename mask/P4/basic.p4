/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 16

const bit<16> TYPE_IPv6 = 0x86dd;
const bit<8> FROM_CONTROLLER = 0;
const bit<8> TO_CONTROLLER = 3;  /*  send to the controller */

const bit<16> Req_PROCESS = 5;
//const bit<16> RResp_PROCESS = 6;
const bit<16> PACKET_OUT_ON_PORT = 11;
const bit<16> FULL_PROCESS = 12;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;

header cpu_t {
    bit<64> zeros_prefix;
    bit<16> info;
    bit<16> port;
    bit<48> timestamp;
    bit<128> rkey;
    bit<32>  last_label;
    bit<32>  next_label;
}

header ethernet_t {
    macAddr_t dstAddr;//0:6
    macAddr_t srcAddr;//6:12
    bit<16>   etherType;//12:14
}

header ipv6_t {
    bit<4>   version;//14:
    bit<8>   tc;
    bit<20>  flowLabel;//18
    bit<16>  payLoadLen;//18:20
    bit<8>   nHdr;//20:21
    bit<8>   hopL;//21:22
    bit<128> srcIP;//22:38
    bit<128> dstIP;//38:54
}

header maskh_t {
    bit<8>   nH;//54:55
    bit<8>   hLen;//55:56
    bit<8>   flag;//56:57
    bit<32>  label;//57:61
    bit<32>  session;//61:65
    bit<32>  datahash;//65:69
    bit<32>  mac;//69:73
}

struct user_metadata_t {
    bool      from_controller;
}



struct metadata {
    @metadata @name("intrinsic_metadata")
    //intrinsic_metadata_t intrinsic_metadata;
    user_metadata_t      user_metadata;
}

struct headers {
    cpu_t        cpu;
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    maskh_t      maskh;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<cpu_t>().zeros_prefix) {
            (bit<64>)0 : parse_cpu_header;
            default: parse_ethernet;
        }
    }

    state parse_cpu_header {
        packet.extract(hdr.cpu);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPv6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition parse_maskh;
    }
    
    state parse_maskh{
        packet.extract(hdr.maskh);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action send_to_controller(bit<16> info, egressSpec_t port) {
        standard_metadata.egress_spec = CPU_PORT;
        //hdr.cpu.setValid();
        hdr.cpu.info = info;
        hdr.cpu.port = (bit<16>) port;
        hdr.cpu.timestamp = standard_metadata.ingress_global_timestamp;
    }

    action reply(bit<8> flag) {
        hdr.ipv6.tc = flag;//.maskh.flag
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopL = hdr.ipv6.hopL - 1;
    }

    
    
    table ipv6_lpm {
        key = {
            hdr.ipv6.dstIP: lpm;
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action writetc(bit<128> rkey,bit<32> last_label,bit<32> next_label) {
        hdr.ipv6.tc = TO_CONTROLLER;
        hdr.cpu.setValid();
        hdr.cpu.rkey=rkey;
        hdr.cpu.last_label=last_label;
        hdr.cpu.next_label=next_label;
    }
    
    table comparelabel {
        key = {
            hdr.maskh.label: exact;
        }
        actions = {
            writetc;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        comparelabel.apply();//judge whether deal with hmac
        //packet from controller, go through full pipeline
        if (hdr.cpu.isValid() && hdr.cpu.info == FULL_PROCESS) {
            hdr.cpu.setInvalid();
            meta.user_metadata.from_controller = true;
            reply(FROM_CONTROLLER);
    	} else {
            meta.user_metadata.from_controller = false;
        }

        // packet from controller, send out on specified port
    	if (hdr.cpu.isValid() && hdr.cpu.info == PACKET_OUT_ON_PORT) {
            standard_metadata.egress_spec = (bit<9>) hdr.cpu.port;
            hdr.cpu.setInvalid();
    	}

        // ethernet packets src mac
        else if (hdr.ethernet.isValid()) {
            // ipv6 forwarding
            if (hdr.ipv6.isValid()) {
                // mask process
                if(hdr.ipv6.tc == TO_CONTROLLER && !meta.user_metadata.from_controller) {
                    send_to_controller(Req_PROCESS, standard_metadata.ingress_port);
                }

               
                if(!hdr.cpu.isValid()) {
                    if(!ipv6_lpm.apply().hit) {
                        drop();
                    }
                }
            }
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.cpu);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.maskh);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
