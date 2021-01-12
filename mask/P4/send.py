#!/usr/bin/env python

import sys
import logging
import struct
import random
from scapy.layers.inet import _IPOption_HDR
from scapy.all import *
from headerNew import *

from utils.srAPI import *

RResp_PROTO_OPT = 253
RReq_PROTO_OPT = 254
MAX_THRESHOLD = 0.5
MIN_THRESHOLD = 0.32

# setup logging
logging.basicConfig(format="[%(levelname)s] %(asctime)s: %(message)s", level=logging.DEBUG)

path = list_label[0]+list_label[1]+list_label[2]+list_label[3]+list_label[4]
payload = "path :"+ str(list_label[0])+str(list_label[1])+str(list_label[2])+str(list_label[3])+str(list_label[4])
timestamp = 0x1234
data_hash=hash_toint(payload,sk_d,8)

def main():
    if len(sys.argv) < 2:
        logging.info('pass 2 arguments: <type>  ')
        exit(1)
    #get session key
    i=int(sys.argv[1])
    #print i,"***"
    if i == DATA:
        j=0
        while j<5:
            j += 1
            k=random.randint(0, 4)
            send_data(k,j)
            print "j:",j
    elif i == NEG:
        message_req=encrypt(str(policy)+"p"+str(src_dst[0]),sk_d)
        send_req_ack_check(i,message_req)

def send_data(i,j):    
    iface = get_if()
    if i<5:
        session_hash=hash_toint(str(timestamp+path),sk_d,8)
        sk1 = (sk_sw[i]>>64 & 0xFFFFFFFFFFFFFFFF)
        sk2 = (sk_sw[i]& 0xFFFFFFFFFFFFFFFF)
        sk = struct.pack("!QQ", sk1,sk2)
        #print "sk:",sk  
        #calculate the mac 
        last_label=0
        if i>0:
            last_label=list_label[i-1]
        message = struct.pack("!3I",list_label[i],last_label,data_hash)
        print "message:",struct.unpack(">3I",message)
        mac = send_marking(sk,message)
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff',type=0x86dd)
        pkt = pkt /IPv6(src = src_dst_str[0],dst = src_dst_str[1],nh=143,tc=0,fl=j)/maskh(nHeader=1,flag=0,
              session=session_hash,label=list_label[i],datahash=data_hash,mac=mac)
        pkt = pkt/TCP(dport=1234, sport=49152) / payload
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        #i +=1

def send_req_ack_check(flag,policy):
    session_hash=hash_toint(str(timestamp+path),sk_d,8)
    sk1 = (sk_sw[0]>>64 & 0xFFFFFFFFFFFFFFFF)
    sk2 = (sk_sw[0]& 0xFFFFFFFFFFFFFFFF)
    sk = struct.pack("!QQ", sk1,sk2)
    iface = get_if()
    sa=src_dst_str[0]
    ds=src_dst_str[1]
    if (flag==2):
        sa=src_dst_str[1]
        ds=src_dst_str[0]
    message = struct.pack("!3I",list_label[0],0,data_hash)
    print "message:",struct.unpack(">3I",message)
    mac = send_marking(sk,message)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff',type=0x86DD)
    int_hash=hash_toint(policy,sk_d,8)
    pkt = pkt /IPv6(src=sa,dst=ds,nh=143,tc=0)/maskh(nHeader=1,flag=flag,
          session=session_hash,label=list_label[0],datahash=int_hash,mac=mac) #assume the first router verify control packet       
    pkt = pkt / TCP(dport=1234, sport=49152) / policy 
    #pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
