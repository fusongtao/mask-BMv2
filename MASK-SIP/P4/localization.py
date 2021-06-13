#!/usr/bin/env python
import sys
import struct
import random

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import IP, UDP, Ether,TCP
from scapy.layers.inet import _IPOption_HDR
from scapy.fields import *
from headerNew import *
from send import *
import headerNew
import send
import re


global ack_info



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
    if pkt.haslayer("trustke"):
        if int(pkt[trustke].flag) == ACK:
            pkt.show2()
            payload_enc = str(pkt[trustke].load)
            sk = pack_128(int(sk_d))
            payload = decrypt(payload_enc,sk)
            out_number=payload.split('c')
            print "counter epoch and success, failed,total, :",out_number            
    sys.stdout.flush()

   



def main():
    #initial_repu()
    iface = 'h1-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="", iface=iface, prn=handle_pkt, count=10000000, timeout=3000000)

if __name__ == '__main__':
    main()
