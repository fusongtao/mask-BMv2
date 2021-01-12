#!/usr/bin/env python
import sys
import struct
import os
import logging

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from headerNew import *
from send import *

RReq_PROTO_OPT = 254
sCounter=[0,0,0,0,0]
fCounter=[0,0,0,0,0]
total = [0]

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        logging.error("Cannot find eth0 interface")
        exit(1)
    return iface


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [_IPOption_HDR,
                   FieldLenField("length", None, fmt="B",
                                 length_of="swids",
                                 adjust=lambda pkt, l: l + 4),
                   ShortField("count", 0),
                   FieldListField("swids",
                                  [],
                                  IntField("", 0),
                                  length_from=lambda pkt: pkt.count * 4)]


def handle_pkt(pkt):
    if pkt.haslayer("maskh") and pkt[maskh].flag == 0 :        
        pkt.show2()
        receive_hash = int(pkt[maskh].datahash)
        pl= str(pkt[TCP].payload)
        cal_hash=hash_toint(pl,sk_d,8)
        #print "receive-hash:",receive_hash,"calculated hash:",cal_hash
        if receive_hash == cal_hash:
            print "the hash is the same"
            verification(pkt,receive_hash)
        print "the successed verification:",sCounter
        print "the failed verification:",fCounter
        total[0] += 1
        print "total:",total[0]
    elif pkt.haslayer("maskh") and pkt[maskh].flag == 1 :        
        pkt.show2()
        policy=decrypt(str(pkt[TCP].payload),sk_d)
        print "policy:",policy
        policy_list=policy.split('p')
        if int(policy_list[1]) == src_dst[0] :
            message_ack = encrypt(policy_list[0] + "p" + str(src_dst[1]),sk_d)
            send_req_ack_check(2,message_ack)
    elif pkt.haslayer("maskh") and pkt[maskh].flag == 3 :        
        #pkt.show2()
        check_point=decrypt(str(pkt[TCP].payload),sk_d)
        print "check_point:",check_point
        counter_receive = sCounter[0]+sCounter[1]+sCounter[2]+sCounter[3]+sCounter[4]
        fcounter_receive = fCounter[0]+fCounter[1]+fCounter[2]+fCounter[3]+fCounter[4]
        print "total success:",counter_receive,"--total failed:",fcounter_receive
        i=0
        while i <= 4:   #clear the counter
            sCounter[i]=0
            fCounter[i]=0
            i=i+1
    sys.stdout.flush()

def verification(pkt,receive_hash):
    f_flag= False    
    next_label = 0
    k=4
    i=-1
    label = int(pkt[maskh].label)
    while k>=0:
        if (list_label[k] == label):
            i=k
            if i<4:
                next_label = list_label[i+1]
            else:
                next_label = 0
            break
        k=k-1
    #print("the i is  ",i,"--next label is :",next_label)
    mac_rec=int(pkt[maskh].mac)
    #calculate the origin mac
    session_hash=int(pkt[maskh].session)
    print "session:",session_hash
    sk1 = (sk_sw[i]>>64 & 0xFFFFFFFFFFFFFFFF)
    sk2 = (sk_sw[i]& 0xFFFFFFFFFFFFFFFF)
    skey = struct.pack("!QQ", sk1,sk2)
    last_label=0
    if i>0:
        last_label=list_label[i-1]
    message = struct.pack("!3I",list_label[i],last_label,receive_hash)
    #print "message:",struct.unpack(">3I",message)
    origin_mac = send_marking(skey,message)
    #print "origin_mac:", origin_mac    
    #calculate the mac 
    message = struct.pack("!4I",label,next_label,receive_hash,origin_mac)
    machmac = (hmac.new(skey,message)).digest() 
    mac = machmac[0:4]                
    mac_int= struct.unpack("!I",mac)[0]
    #print  "int:",mac_int
    if mac_int!=mac_rec:
        fCounter[i]=fCounter[i]+1
        print("verification failed at the switch, ",i+1,"false counter--",fCounter[i]) 
    else:
        sCounter[i]=sCounter[i]+1
        print("verification successed at the switch",i+1,"successed counter--",sCounter[i])    
        f_flag=True              
    return f_flag

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    logging.info("sniffing on %s" % iface)
    sniff(filter="", iface=iface, prn=handle_pkt, count=1000, timeout=3000)


if __name__ == '__main__':
    main()
