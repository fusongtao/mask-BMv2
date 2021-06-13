#!/usr/bin/env python

import sys
import logging
import struct
import random
from scapy.layers.inet import _IPOption_HDR
from scapy.all import *
from headerNew import *
import time,datetime
import headerNew

from utils.srAPI import *






path = list_label[0]+list_label[1]+list_label[2]+list_label[3]+list_label[4]
payload = "path :"+ str(list_label[0])+str(list_label[1])+str(list_label[2])+str(list_label[3])+str(list_label[4])
timestamp = 0x1234

def main():
    if len(sys.argv) < 2:
        logging.info('pass 2 arguments: <type>  ')
        exit(1)
    #i=int(sys.argv[1])
    #policy_element=policy.split('c')
    #n = int(policy_element[0])
    epoch = 0
    global src
    src=""
    for turns in range(2):
        #calculate the adjust factor
        n = new_policy(epoch)
        for seq in range(n):        
            k=random.randint(0, HOPS-1) 
            send_data(epoch,seq,0,k,payload)  
        epoch +=1     
        #time.sleep(SLEEP_TIME) 
    
def send_data(epoch,seq,packet_type,i,pay_load):    
    iface = get_if()
    session_hash=hash_toint(str(timestamp+path),sk_d,8)
    if packet_type == ACK:
        pay_load_enc = pay_load
    if seq >=0:
        pay_load=str( int(round((time.time()) * 1000000)))+"*"+pay_load
        for count_i in range(1300):
            pay_load +="0"
        dataauth=hash_toint(pay_load,sk_d,8)
        print "dataauth:",dataauth,"pay_load:",pay_load,"sk_d:",sk_d
        enc_label = list_label[i] #cal_id(sk,i,dataauth)
        mac,mac_r = send_marking(epoch,seq,session_hash,i,dataauth)
        print "mac:",mac          
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff',type=0x86dd)
        if packet_type == ACK:
            pkt = pkt /IPv6(src = src_dst_str[1],dst = src_dst_str[0],nh=150,tc=0)
            pay_load = pay_load_enc
        else:
            pkt = pkt /IPv6(src = src_dst_str[0],dst = src_dst_str[1],nh=150,tc=0)
        
        pkt = pkt/trustke(flag=packet_type,epoch=epoch,seq=seq,session=session_hash,label=enc_label,dataauth=dataauth,mac=mac)/pay_load
        #/TCP(dport=1234, sport=49152)
        pkt.show2()
        print "src_counter:",src_counter
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
