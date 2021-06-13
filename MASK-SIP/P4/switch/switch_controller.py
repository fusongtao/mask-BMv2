#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import Queue
import binascii
import json
import random
import struct
import threading
import time
import os, sys
import p4runtime_lib
import hashlib
import hmac
from Crypto.Cipher import AES
from aes import *

sys.path.append(os.path.abspath("../"))

#from utils.d_val_util import DVal

# from scapy.all import Packet, hexdump
# from scapy.layers.l2 import ARP, Ether

list_label=[267772161,267772162,267772163,267772164,267772165,267772166,267772167,267772168,267772169,267772170]
sk_sw_origin=[123456789,223456789,323456789,423456789,523456789,623456789,
              723456789,823456789,923456789,23456789]

Req_PROCESS = 5
PACKET_OUT_ON_PORT = 11
FULL_PROCESS = 12

LEN_HDR_CPU = 42
LEN_HDR_ETH = 14
LEN_HDR_IP = 40

BEG_LABEL= 57
END_LABEL= 61
END_SID  = 65
END_AUTH = 69
END_MAC  = 73
END_MAC_LINE  = 77

DATA_UNSAV = 0
DATA_SAV = 1
PROBE=2
REPLY=3
ACK =4

HOPS = 10


counter_0=[[] for i in range(10)]
counter=[[] for i in range(10)]

SEQ_THRESHOLD=350
DROP_RATE = 30
FAULT_NODE=2

class SwitchController:
    def __init__(self, p4info_file_path, bmv2_file_path, port_mapping_path, topo_path, routing_path, d_val_path):
        self.switches = []
        self.switches_name = []
        self.name2switch = {}
        self.port_queues = {}
        self.port_threads = {}
        self.connection_info = []

        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.p4info_file_path = p4info_file_path
        self.bmv2_file_path = bmv2_file_path
        self.packet_in_threads = []

        self.num_ports = {}
        self.d_val = {}

        with open(port_mapping_path, 'r') as f:
            json_str = f.read()
            port_mapping = json.loads(json_str)
            self.port_map = port_mapping

        with open(topo_path, 'r') as f:
            json_str = f.read()
            topo = json.loads(json_str)
            self.hosts = topo['hosts']
            self.sw = topo['switches']
            self.links = topo['links']

        with open(routing_path, 'r') as f:
            json_str = f.read()
            self.routing = json.loads(json_str)


    def add_switch_connection(self, name, address, device_id, type='bmv2',
                              debug=False, num_ports=15):
        if type == 'bmv2':
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=name, address=address,
                                                                                    device_id=device_id)
            self.port_queues[sw.name] = Queue.Queue()

        elif type == 'tofino':
            print 'No tofino defined.'

        self.switches.append(sw)
        self.controller_addr = address
        self.name2switch[sw.name] = sw
        self.switches_name.append(sw.name)
        self.num_ports[sw.name] = num_ports

    def startup(self):
        for sw in self.switches:
            sw.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)

            t = threading.Thread(target=sw.send_init_and_wait, args=(self.response_callback,))
            t.start()
            self.packet_in_threads.append(t)

        time.sleep(0.5)
        self.routing_config()

    def routing_config(self):
        sw_name = self.switches_name[0]
        if sw_name not in self.routing.keys():
            print sw_name + ' : no routing configure'
            exit(-1)

        if sw_name not in self.sw.keys():
            print sw_name + ' : no topo configure'
            exit(-1)

        for h_name in self.hosts.keys():
            if h_name not in self.routing[sw_name].keys():
                print sw_name + ': has no route to ' + h_name
                exit(-1)

            # TODO: for multicast, it should be an array
            next_hop_name = self.routing[sw_name][h_name]

            dst_ip = self.hosts[h_name]
            dst_mac = ''
            dst_port = -1
            for k in self.port_map[sw_name].keys():
                v = self.port_map[sw_name][k]
                if v[0] == next_hop_name:
                    dst_port = int(k)
                    dst_mac = v[-1]
                    break

            if dst_port == -1:
                print 'Next hop path unexist: ' + self.switches_name[0] + ' to ' + h_name
                exit(-1)

            self.writeL3Mapping(self.switches[0], dst_ip, 32, dst_mac, dst_port)
            print "Routing Info:", self.switches[0], dst_ip, 32, dst_mac, dst_port 
        print "sw name:",self.switches[0].name      
        self.load_info(self.switches[0])

    def teardown(self):
        for sw in self.switches:
            sw.stop_waiting()
        for t in self.packet_in_threads:
            t.join()

        self.grpc_server.stop(0)

    def send_packet_out(self, switch, payload):
        switch.send_packet_out(payload)

    def send_packet_out_multiple(self, switch, payloads):
        switch.send_packet_out_multiple(payloads)

    def response_callback(self, switch, response):
        print("got a response from switch %s" % switch.name)
        # print "response: ", response
        if response.packet.payload:
            self.packet_in_callback(switch, response.packet.payload)
        else:
            print("Non packet_in response: \n" + str(response))
            pass

    def assemble_packet(self, reason, port, pkt):
        reason_h = struct.pack(">H", reason)
        out_port_h = struct.pack(">H", port)
        zeros_h = struct.pack(">q", 0)
        timestamp1_h = struct.pack('<H', 0)
        timestamp2_h = struct.pack('<H', 0)
        timestamp3_h = struct.pack('<H', 0)
        key1_h = struct.pack(">q", 0)
        key2_h = struct.pack(">q", 0)
        last_next_label = struct.pack(">q", 0)
        cpu_header = zeros_h + reason_h + out_port_h + timestamp1_h + timestamp2_h + timestamp3_h + key1_h + key2_h+last_next_label

        return cpu_header + str(pkt)

    def de_assemble_packet(self, packet_in):
        # remove CPU header
        reason = struct.unpack(">H", packet_in[8:10])[0] 
        ingress_port = struct.unpack(">H", packet_in[10:12])[0]
        timestamp = int(str(binascii.hexlify(packet_in[12:18])), 16)
        rkey = packet_in[18:34] #struct.unpack(">QQ", packet_in[18:34])
        current_label = struct.unpack(">I", packet_in[34:38])[0]
        next_label = struct.unpack(">I", packet_in[38:42])[0]
        '''
        print("Packet in, reason: " + str(reason) + ", in port: " + str(ingress_port) + ", timestamp: " + str(
            timestamp) +",rkey1:" + str(rkey[0]) +",rkey2:" + str(rkey[1])+",current_label:" + str(current_label)+
            ",next_label:" + str(next_label) )
        '''
        return reason, ingress_port, timestamp, rkey, current_label, next_label 

    def packet_in_callback(self, switch, packet_in):
        reason, ingress_port, timestamp, rkey, current_label, next_label = self.de_assemble_packet(packet_in)
        if reason == Req_PROCESS:
            # acquire the deviation value, process_result would be
            #   1) False: not have a deviation value
            #   2) True: have a deviation value
            pkt_to_process = packet_in[LEN_HDR_CPU:]
            pkt_after_porcess, process_result = self.process_all(switch, pkt_to_process, rkey, current_label, next_label)

            #print "Packet pkt_after_porcess:\t", pkt_after_porcess
            if process_result:  # 
                packet_processed = pkt_after_porcess              
                self.packet_out(switch, FULL_PROCESS, 0, packet_processed)

            #self.flooding(switch, pkt_to_process, ingress_port)
            return

        print('reason unknown or wrong ethertype')

    def packet_out(self, switch, reason, port, pkt):
        self.send_packet_out(switch, self.assemble_packet(reason, port, pkt))

    def flooding(self, switch, pkt, exclude_port):
        pkts = []
        for i in range(1, int(self.num_ports[switch.name])):
            if i != exclude_port:
                pkts.append(self.assemble_packet(PACKET_OUT_ON_PORT, i, pkt))
                print "flooding: %s -> eth%d" % (switch.name, i)

        self.send_packet_out_multiple(switch, pkts)
        return

    def writeL3Mapping(self, sw, dst_addr, dst_addr_len, dst_mac_addr, port):
        #dstlpm = struct.pack(">I", dst_addr)
        print "dstip:",str(dst_addr),type(dst_addr)
        print "port:",port,type(port)
        dstip=str(dst_addr)
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv6_lpm",
            match_fields={
                "hdr.ipv6.dstIP": (dstip, 32)  
            },
            action_name="MyIngress.ipv6_forward",
            action_params={
                "dstAddr": str(dst_mac_addr),
                "port": port + 1
            })
        sw.WriteTableEntry(table_entry)

    def load_info(self,sw):
        print "switch.name:", sw.name                
        label=0  #current
        rkey = 0
        last_label=0
        next_label=0
        id_router=0
        in_port=0
        passport=0
        if sw.name == 's1':
            label = list_label[0]
            rkey = sk_sw_origin[0]
            last_label = 0
            next_label = list_label[1]
            id_router=1
            in_port=1
            passport=0xffff
        elif sw.name == 's2':
            label = list_label[1]
            rkey = sk_sw_origin[1]
            last_label = list_label[0]
            next_label = list_label[2]
            id_router=2
            in_port=1
            passport=0x19
        elif sw.name == 's3':
            label = list_label[2]
            rkey = sk_sw_origin[2]
            last_label = list_label[1]
            next_label = list_label[3]
            id_router=3
            in_port=1
            passport=0x19
        elif sw.name == 's4':
            label = list_label[3]
            rkey = sk_sw_origin[3]
            last_label = list_label[2]
            next_label = list_label[4]
            id_router=4
            in_port=1
            passport=0x19
        elif sw.name == 's5':
            label = list_label[4]
            rkey = sk_sw_origin[4]
            last_label = list_label[3]
            next_label = list_label[5]
            id_router=5
            in_port=1
            passport=0x19
        elif sw.name == 's6':
            label = list_label[5]
            rkey = sk_sw_origin[5]
            last_label = list_label[4]
            next_label = list_label[6]
            id_router=6
            in_port=1
            passport=0x19
        elif sw.name == 's7':
            label = list_label[6]
            rkey = sk_sw_origin[6]
            last_label = list_label[5]
            next_label = list_label[7]
            id_router=7
            in_port=1
            passport=0x19
        elif sw.name == 's8':
            label = list_label[7]
            rkey = sk_sw_origin[7]
            last_label = list_label[6]
            next_label = list_label[8]
            id_router=8
            in_port=1
            passport=0x19
        elif sw.name == 's9':
            label = list_label[8]
            rkey = sk_sw_origin[8]
            last_label = list_label[7]
            next_label = list_label[9]
            id_router=9
            in_port=1
            passport=0x19
        elif sw.name == 's10':
            label = list_label[9]
            rkey = sk_sw_origin[9] #0
            last_label = list_label[8]
            id_router=10
            in_port=1
            next_label = 0
            passport=0x19
        print "switch.label:", label,"--rkey:",rkey
       
        #mis=0
        #if sw.name == 's3':
        #    mis=1
        nheader=150  #next header
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.load_info",
            match_fields={
                "hdr.ipv6.nHdr": nheader
            },
            action_name="MyIngress.load_parameter",
            action_params={
                "rkey":rkey,
                "current_label":label,
                "next_label":next_label,
                "last_label":last_label,
                #"mis":mis
            })
        sw.WriteTableEntry(table_entry)
        
    def cal_macs(self,skey,pkt_label,macline,next_label,epoch,seq):
        message = pkt_label + macline + struct.pack("!I",next_label) +struct.pack("!B",0)+epoch+seq
        #print "message:",struct.unpack("!4I",message)
        cal_macline = (hmac.new(skey,message)).digest()                      
        cal_macline_first=struct.unpack("!I",cal_macline[12:16])[0]
        macline = struct.pack("!I",cal_macline_first)
        cal_macline_second=struct.unpack("!I",cal_macline[8:12])[0]
        cal_macline_third=struct.unpack("!I",cal_macline[4:8])[0]
        #print "macline:",cal_macline_first, "cal_macline_second:",cal_macline_second,"cal_macline_third:",cal_macline_third
        return macline,cal_macline_second,cal_macline_third       

    def process_all(self, switch, packet_in, skey,current_label,next_label):
        flag = False
        if packet_in != 0:
            packet_lsflow = packet_in
            
                
            src_ip = packet_lsflow[22:38]
            dst_ip = packet_lsflow[38:54]
            int_epoch =struct.unpack("!B",packet_lsflow[54:55])
            int_seq =struct.unpack("!H",packet_lsflow[55:57])
            next_header=packet_lsflow[20:21]            
            #print "src_ip:", struct.unpack("!QQ",src_ip),"dst_ip:", struct.unpack("!QQ",dst_ip) #[0],struct.unpack("!QQ",src_ip)[1]
            int_nextheader=struct.unpack("!B",next_header)[0]
            print "int_nextheader:",int_nextheader,"epoch:",int_epoch,"seq:",int_seq
            counter = next_label

            if int_nextheader==150:                
                reply_pack = str(counter)  #struct.unpack("!H",counter) #seq
                reply_pack_enc = encrypt(reply_pack,skey)
                print "########reply_pack_enc:", reply_pack_enc,"reply_pack---2:",reply_pack,"len:" ,len(reply_pack_enc)
                packet_in =  packet_lsflow[0:22] +dst_ip+ src_ip + packet_lsflow[54:77]+ reply_pack_enc #struct.pack("!H",reply_pack) 
                flag = True
        
                         
        return packet_in, flag




