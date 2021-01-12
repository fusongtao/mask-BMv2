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

sys.path.append(os.path.abspath("../"))

#from utils.d_val_util import DVal

# from scapy.all import Packet, hexdump
# from scapy.layers.l2 import ARP, Ether

list_label=[167772161,0x0a000002,0x0a000003,0x0a000004,0x0a000005]

Req_PROCESS = 5
PACKET_OUT_ON_PORT = 11
FULL_PROCESS = 12

LEN_HDR_CPU = 42
LEN_HDR_ETH = 14
LEN_HDR_IP = 40
LEN_HDR_MASK=19

BEG_LABEL= 57
END_LABEL= 61
END_SID  = 65
END_HASH = 69
END_MAC  = 73


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
        self.compareLabel(self.switches[0])

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
        rkey = struct.unpack(">QQ", packet_in[18:34])
        last_label = struct.unpack(">I", packet_in[34:38])[0]
        next_label = struct.unpack(">I", packet_in[38:42])[0]
        print("Packet in, reason: " + str(reason) + ", in port: " + str(ingress_port) + ", timestamp: " + str(
            timestamp) +",rkey1:" + str(rkey[0]) +",rkey2:" + str(rkey[1])+",last_label:" + str(last_label)+
            ",next_label:" + str(next_label) )
        return reason, ingress_port, timestamp, rkey, last_label, next_label 

    def packet_in_callback(self, switch, packet_in):
        reason, ingress_port, timestamp, rkey, last_label, next_label = self.de_assemble_packet(packet_in)
        if reason == Req_PROCESS:
            # acquire the deviation value, process_result would be
            #   1) False: not have a deviation value
            #   2) True: have a deviation value
            pkt_to_process = packet_in[LEN_HDR_CPU:]
            pkt_after_porcess, process_result = self.process_mask(switch, pkt_to_process, rkey, last_label, next_label)

            print "Packet pkt_after_porcess:\t", pkt_after_porcess
            if process_result:  # 
                packet_mask = pkt_after_porcess              
                self.packet_out(switch, FULL_PROCESS, 0, packet_mask)

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

    def compareLabel(self,sw):
        print "switch.name:", sw.name                
        label=0
        rkey = 0
        last_label=0
        next_label=0
        if sw.name == 's1':
            label = 167772161
            rkey = 123456789012
            last_label = 0
            next_label = list_label[1]
        elif sw.name == 's2':
            label = 167772162
            rkey = 223456789012
            last_label = list_label[0]
            next_label = list_label[2]
        elif sw.name == 's3':
            label = 167772163
            rkey = 323456789012
            last_label = list_label[1]
            next_label = list_label[3]
        elif sw.name == 's4':
            label = 167772164
            rkey = 423456789012
            last_label = list_label[2]
            next_label = list_label[4]
        elif sw.name == 's5':
            label = 167772165
            rkey = 523456789012
            last_label = list_label[3]
            next_label = 0
        print "switch.label:", label,"--rkey:",rkey
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.comparelabel",
            match_fields={
                "hdr.maskh.label": label
            },
            action_name="MyIngress.writetc",
            action_params={
                "rkey":rkey,
                "last_label":last_label,
                "next_label":next_label
            })
        sw.WriteTableEntry(table_entry)

    def process_mask(self, switch, packet_in, rkey,last_label,next_label):
        flag = False
        if packet_in != 0:
            packet_mask = packet_in
            print "switch.name:", switch.name                
            key=struct.pack(">QQ",rkey[0],rkey[1])
            print "switch.key:", key
                
            dst_mac = packet_mask[0:6]
            src_mac = packet_mask[6:12]
            src_ip = packet_mask[22:38]
            print "src_ip:", struct.unpack("!QQ",src_ip) #[0],struct.unpack("!QQ",src_ip)[1]
            dst_ip = packet_mask[38:54]
            print "dst_ip:", struct.unpack("!QQ",dst_ip) #[0],struct.unpack("!QQ",dst_ip)[1]
            label = packet_mask[BEG_LABEL:END_LABEL]
            session = packet_mask[END_LABEL:END_SID]
            int_label = struct.unpack("!I",label)
            print "label:", int_label
            print "session:", struct.unpack("!I",session)
            datahash = packet_mask[END_SID:END_HASH]  
            print "datahash:", struct.unpack("!I",datahash)
            mac = packet_mask[END_HASH:END_MAC]
            origin_mac = struct.unpack("!I",mac)
            print "mac:", origin_mac
            message = src_ip+dst_ip+session
            print "message:", struct.unpack("!4QI",message)

            # session key
            skey = (hmac.new(key,message)).digest()
            print skey,"skey_int:",struct.unpack("!2Q", skey)

            #last_label,next_label            
            print "last_label:",last_label,"next_label:",next_label            
            
            #compare the origin mac
            message = label+struct.pack("!I",last_label)+datahash
            print "message:",struct.unpack(">3I",message)
            cal_mac = (hmac.new(skey,message)).digest()  
            cal_mac_part=struct.unpack("!2Q",cal_mac)[1] & 0xffffffff          
            print "cal_mac:",struct.unpack("!2Q",cal_mac),cal_mac_part
            flag = packet_mask[56:57]
            flag_int = struct.unpack("!B",flag)[0]
            if cal_mac_part == origin_mac[0]:                
                # new maccontroller
                print "The origin verification is successed, calculate the new mac"
                message =label+struct.pack("!I",next_label)+datahash+mac
                machmac = (hmac.new(skey,message)).digest() 
                mac = machmac[0:4]                
                mac_int= struct.unpack("!I",mac)
                print  "mac:",mac,"int:",mac_int
                flag = True
            else:
                #filter the packet
                mac = struct.pack("!I",0)
                print "The origin verification is failed, dropped this packet"
                flag = True
            packet_mask =  packet_mask[0:END_HASH] + mac+ packet_mask[END_HASH+4:]
            print "pkt_after_porcess**:",packet_mask, type(packet_mask), type(packet_in)
        return packet_mask, flag
