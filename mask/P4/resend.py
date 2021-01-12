#!/usr/bin/env python
import sys
import struct
import random

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import IP, UDP, Raw, Ether,TCP
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
from headerNew import *
from send import *


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):  
    if pkt.haslayer("maskh") and pkt[maskh].flag == 2 :
        policy=decrypt(str(pkt[TCP].payload),sk_d)
        policy_list=policy.split('p')
        print(policy_list)
        list_hop = policy_list[0].split('c')
        total=0
        if int(policy_list[1]) == src_dst[1] :
            for i in range(len(list_hop)):
                j=int(list_hop[i])
                while j>=0:
                    if j==0:
                        message_check=encrypt("check_point",sk_d)
                        send_req_ack_check(3,message_check)
                        break                           
                    else :
                        k=random.randint(0, 4)
                        send_data(k,j)
                        j=j-1
                        total += 1
            print("total:",total)
    sys.stdout.flush()

   



def main():
    iface = 'h1-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
