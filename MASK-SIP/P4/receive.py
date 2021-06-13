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
sCounter=[0,0,0,0,0,0,0,0,0,0]
fCounter=[0,0,0,0,0,0,0,0,0,0]
total = [0]
time_record = [0,0,0,0]
time_validation=[0,0]
new_n=[-1]

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
    time_record[2] = int(round((time.time()) * 1000000))     
    #pkt.show2()
    if pkt.haslayer("trustke"):
        if int(pkt[trustke].flag) == 0:
            starttime = int(str(pkt[trustke].payload).split("*")[0])
            time_record[2] = time_record[2] -starttime 
            time_record[3] += time_record[2]    
            print "time us:",time_record[2],"ms",time_record[2]/1000,"total ms:",time_record[3]/1000 
        receive_auth = int(pkt[trustke].dataauth)
        payload= str(pkt[trustke].payload)
        cal_hash=hash_toint(payload,sk_d,8)
        #print "receive-hash:",receive_auth,"calculated hash:",cal_hash,"pl:",payload,"sk_d:",sk_d
        if receive_auth == cal_hash:
            #print "the hash authenticator is the same"
            verification(pkt,receive_auth)
            print "the successed verification:",sCounter
            #print "the failed verification:",fCounter
            total[0] += 1
            print "total:",total[0] 
            counter_receive = sCounter[0]
            fcounter_receive = fCounter[0]
            for i in range(1,10):
                counter_receive += sCounter[i]
                fcounter_receive += fCounter[i]
            print "total success:",counter_receive,"--total failed:",fcounter_receive
            int_seq = int(pkt[trustke].seq)
            int_epoch = int(pkt[trustke].epoch)
            payload = str(int_epoch) + "c"+str(counter_receive) + "c"+str(fcounter_receive) + "c"+str(total[0]) 
            sk = pack_128(int(sk_d))
            payload_enc = encrypt(payload,sk)            
            #print "int_seq:",int_seq,"new_n[0]:",new_n[0]
            if  (int_epoch!=EPOCH_FLAG[0]) or (int_seq == new_n[0]-1):  #sent ack and clear the counters 
                n = new_policy(int_epoch)
                EPOCH_FLAG[0] = (EPOCH_FLAG[0]+1) % 256
                seq=random.randint(0, policy)   #random sequence for ack
                send_data(int_epoch,seq,ACK,0,payload_enc)
                for i in range(10):
                    sCounter[i]=0
                    fCounter[i]=0
                total[0]=0   
                print "average ms:",time_record[3]/1000/(n-1),"n:",n
                time_record[3] = 0 
                new_n[0] = new_policy(EPOCH_FLAG[0]) 
    sys.stdout.flush()

def verification(pkt,dataauth):
    int_current_label = int(pkt[trustke].label)
    int_pkt_mac = int(pkt[trustke].mac)
    int_seq = int(pkt[trustke].seq)
    int_epoch = int(pkt[trustke].epoch)    
    int_session = int(pkt[trustke].session)
    i = find_router(int_current_label,dataauth,int_session)
    f_flag= False
    
    
    mac = dataauth
    mac_add = 0
    if i<10:
        mac,mac_r =  send_marking(int_epoch,int_seq,int_session,i,dataauth)
        #print  "mac:",mac
        if mac_r != int_pkt_mac:
            fCounter[i]=fCounter[i]+1
            #print("verification failed at the switch, ",i+1,"false counter--",fCounter[i]) 
            if (mac+1) == int_pkt_mac:
                rec_counter[i].append(int_seq)
                #print ("reccounter:",rec_counter)
        else:
            sCounter[i]=sCounter[i]+1
            #print("verification successed at the switch",i+1,"successed counter--",sCounter[i])    
            f_flag=True              
    return f_flag

def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    logging.info("sniffing on %s" % iface)
    sniff(filter="", iface=iface, prn=handle_pkt, count=10000000, timeout=3000000)


if __name__ == '__main__':
    main()
