/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 16

#define COUNTER_ENTRIES 4096
#define COUNTER_BIT_WIDTH 32
#define COUNT_TH          800

const bit<16> DROP_TOTAL = 0x1024;
const bit<8> DROP_MIS = 0; //drop rate
const bit<8> DROP_NATURAL = 1;
const bit<16> TYPE_IPv6 = 0x86dd;
const bit<8> FROM_CONTROLLER = 0;
const bit<8> TO_CONTROLLER = 3;  /*  send to the controller */


const bit<64> const_1 = 0x736f6d6570736575;
const bit<64> const_2 = 0x646f72616e646f6d;
const bit<64> const_3 = 0x6c7967656e657261;
const bit<64> const_4 = 0x7465646279746573;

const bit<16> Req_PROCESS = 5;
//const bit<16> RResp_PROCESS = 6;
const bit<16> PACKET_OUT_ON_PORT = 11;
const bit<16> FULL_PROCESS = 12;


const bit<8> PROBE=2;  
const bit<8>  DATA=1; 
const bit<8>  UNSAV_DATA=0;
const bit<8>   ACK=4;



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
    bit<32>  current_label;
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
    bit<8>   mflag;
    bit<8>   epoch;
    bit<16>  seq;
    bit<32>  id;
    bit<32>  session;
    bit<32>  dataauth;
    bit<32>  mark;
}

struct user_metadata_t {
    bool      from_controller;
}



struct metadata {
    @metadata @name("intrinsic_metadata")
    //intrinsic_metadata_t intrinsic_metadata;
    user_metadata_t      user_metadata;
    bit<64> v0;
    bit<64> v1;
    bit<64> v2; 
    bit<64> v3;
    bit<32> result_add;
    bit<32> result_src;
    bit<64> session_key;
    bit<64> rkey;
    bit<8>  flag;
    bit<32>  current_label;
    bit<32>  last_label;
    bit<32>  next_label;
}

struct headers {
    cpu_t        cpu;
    ethernet_t   ethernet;
    ipv6_t       ipv6;
    maskh_t     maskh;
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
    //register<bit<COUNTER_BIT_WIDTH>>(COUNTER_ENTRIES) counter_10;
    //bit<32> reg_pos; 
    //bit<32> reg_val; 
    //bit<32> drop_val;
    
    //bit<8> drop_real;

    action drop() {
        mark_to_drop();
    }
    /*
    action compute_hashes(){
       //Get register position
 
       hash(reg_pos, HashAlgorithm.crc32, (bit<32>)0, {hdr.maskh.session,
                                                            hdr.ipv6.dstIP,
                                                            hdr.ipv6.srcIP},
                                                           (bit<32>)COUNTER_ENTRIES);
    }

    action compute_drop_rate(){
       //compute_drop_rate
 
       hash(drop_val, HashAlgorithm.crc16, (bit<32>)0, {hdr.maskh.session,
                                                            hdr.ipv6.dstIP,
                                                            hdr.ipv6.srcIP,
                                                            hdr.maskh.epoch,
                                                            hdr.maskh.seq},
                                                           (bit<32>)DROP_TOTAL);
    }*/

       // one round  for SipHash 
    action sip_round() {
	meta.v0 = meta.v0 + meta.v1;
	meta.v2 = meta.v2 + meta.v3;
	meta.v1 = (bit<64>) (meta.v1 << 13);
	meta.v3 = (bit<64>) (meta.v3 << 16);
	meta.v1 = meta.v1 ^ meta.v0;
	meta.v3 = meta.v3 ^ meta.v2;
	meta.v0 = (bit<64>) (meta.v0 << 32);
	meta.v2 = meta.v2 + meta.v1;
	meta.v0 = meta.v0 + meta.v3;
	meta.v1 = (bit<64>) (meta.v1 << 17);
	meta.v3 = (bit<64>) (meta.v3 << 21);
	meta.v1 = meta.v1 ^ meta.v2;
	meta.v3 = meta.v3 ^ meta.v0;
	meta.v2 = (bit<64>) (meta.v2 << 32);
    }

    // Performs SipHash to get the key
    action sip_hash_sk(bit<64> message, bit<64> key_real, bit<64> key_content) {
        meta.v0 = key_real ^ const_1;
        meta.v1 = key_content ^ const_2;
        meta.v2 = key_real ^ const_3;
        meta.v3 = key_content ^ const_4;
	meta.v3 = meta.v3 ^ message;
	sip_round();
	meta.v0 = meta.v0 ^ message;
	meta.v2 = meta.v2 ^ 0x00000000000000ff;	
	sip_round();
	sip_round();
	meta.session_key = meta.v0 ^ meta.v1 ^ meta.v2 ^ meta.v3;
    }
    //to get marking
    action sip_hash_mark(bit<64> message, bit<64> key_real, bit<64> key_content) {
        meta.v0 = key_real ^ const_1;
        meta.v1 = key_content ^ const_2;
        meta.v2 = key_real ^ const_3;
        meta.v3 = key_content ^ const_4;
	meta.v3 = meta.v3 ^ message;
	sip_round();
	meta.v0 = meta.v0 ^ message;
	meta.v2 = meta.v2 ^ 0x00000000000000ff;	
	sip_round();
	sip_round();
	bit<64> result = meta.v0 ^ meta.v1 ^ meta.v2 ^ meta.v3;
        meta.result_src=(bit<32>)(result>>32);
	meta.result_add = (bit<32>) result;
    }

   
    
  

  

  
    
    
    action send_to_controller(bit<16> info, egressSpec_t port) {
        standard_metadata.egress_spec = CPU_PORT;
        //hdr.cpu.setValid();
        hdr.cpu.info = info;
        hdr.cpu.port = (bit<16>) port;
        hdr.cpu.timestamp = standard_metadata.ingress_global_timestamp;
    }

    action reply(bit<8> tc) {
        hdr.ipv6.tc = tc;
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopL = hdr.ipv6.hopL - 1;
    }


     action load_parameter(bit<32> current_label,bit<32> next_label,bit<32> last_label,bit<64> rkey) {
        meta.rkey=rkey;
        meta.current_label=current_label;
        meta.next_label=next_label;
        meta.last_label=last_label;  
    }

    table load_info {
        key = {
            hdr.ipv6.nHdr: exact;
        }
        actions = {
            load_parameter;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
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

    action write_info() {
        hdr.ipv6.tc  = TO_CONTROLLER;
        hdr.cpu.setValid();
        hdr.cpu.rkey=(bit<128>)meta.session_key;
        hdr.cpu.current_label=meta.current_label;       
    }

   

    
    apply {
        
        load_info.apply();
        //packet from controller, go through full pipeline
        if (hdr.cpu.isValid() && hdr.cpu.info == FULL_PROCESS) {
            hdr.cpu.setInvalid();
            meta.user_metadata.from_controller = true;
            reply(FROM_CONTROLLER);
    	} 
       else {
            meta.user_metadata.from_controller = false;
            if(meta.current_label==hdr.maskh.id)
              {
               bit<64> addr = (bit<64>)hdr.ipv6.srcIP ^ (bit<64>)hdr.ipv6.dstIP; 
               sip_hash_sk((bit<64>)hdr.maskh.session,meta.rkey,addr); 
            
               bit<32> temp_hdr = (bit<32>)(hdr.maskh.mflag ++ hdr.maskh.epoch ++ hdr.maskh.seq);
               bit<64> const_hdr = temp_hdr ++ meta.last_label;
               sip_hash_mark(const_hdr, meta.session_key, (bit<64>)meta.next_label);

              if(hdr.maskh.mark == meta.result_src ) 
                     hdr.maskh.mark=meta.result_add;
              else 
                   hdr.maskh.mark=0; //filter the packet
               
               }
            
            
            
           // hdr.maskh.mark = meta.session_key; //test
            
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
                if(hdr.ipv6.tc  == TO_CONTROLLER && !meta.user_metadata.from_controller) {
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
