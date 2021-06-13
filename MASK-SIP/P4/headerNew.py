#!/usr/bRin/env python
from __future__ import division
import argparse
import sys
import socket
import random
import struct
import hashlib
import time,datetime
import hmac

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP,TCP,IPv6
from scapy.fields import *

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


policy=1
HOPS=5
SLEEP_TIME=25
DATA_UNSAV = 0
DATA_SAV = 1
PROBE=2
REPLY=3
ACK =4

SAMPLE_RATE=10
DROP_RATE = 0
FAULT_NODE=2

PRO_TURN=2

src=""

const_1 = 0x736f6d6570736575;
const_2 = 0x646f72616e646f6d;
const_3 = 0x6c7967656e657261;
const_4 = 0x7465646279746573;

EPOCH_FLAG=[0]

src_counter=[[] for i in range(10)]
rec_counter=[[] for i in range(10)]

sk_d=0x0123456789abcdef
sk_sw=[0xa83d9373,0x57682873,0xafd5d173,0x5e4f6273,0xbbc0f73]
list_label=[267772161,267772162,267772163,267772164,267772165,267772166,267772167,267772168,267772169,267772170]
sk_sw_origin=[123456789,223456789,323456789,423456789,523456789,623456789,
              723456789,823456789,923456789,23456789]#switch order
src_dst=[0x0a000001000000000000000000000001,0x0a000002000000000000000000000002]
src_dst_str=["0a00:0001::0001","0a00:0002::0002"]


def new_policy(epoch):
    sk_d_pack = pack_128(sk_d)
    f = (hmac.new(sk_d_pack,struct.pack("!I",epoch))).digest()  
    factor = f[0:4]                
    factor_int= struct.unpack("!I",factor)[0] 
    #print "factor_int before:", factor_int 
    factor_int= factor_int % 50   
    #print "factor_int:", factor_int 
    n = policy + factor_int
    return n

#Helper function for SipHash 
def sip_round(v0,v1,v2,v3):
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
    v1 =  (v1 << 13) & 0xFFFFFFFFFFFFFFFF
    v3 =  (v3 << 16) & 0xFFFFFFFFFFFFFFFF
    v1 = v1 ^ v0
    v3 = v3 ^ v2
    v0 = (v0 << 32) & 0xFFFFFFFFFFFFFFFF
    v2 = v2 + v1
    v0 = v0 + v3
    v1 = (v1 << 17) & 0xFFFFFFFFFFFFFFFF
    v3 = (v3 << 21) & 0xFFFFFFFFFFFFFFFF
    v1 = v1 ^ v2
    v3 = v3 ^ v0
    v2 = (v2 << 32) & 0xFFFFFFFFFFFFFFFF
    list_v=[v0,v1,v2,v3]
    #print(str(v0),str(v1),str(v2),str(v3))
    return list_v

#Performs SipHash 
def sip_hash(message, key_src, key_dst) :
    global v0
    global v1
    global v2
    global v3
    v0 = key_src ^ const_1
    v1 = key_dst ^ const_2
    v2 = key_src ^ const_3
    v3 = key_dst ^ const_4
    v3 = v3 ^ message

    list_vnew=sip_round(v0,v1,v2,v3)
    v0=list_vnew[0]
    v1=list_vnew[1]
    v2=list_vnew[2]
    v3=list_vnew[3] 

    v0 = v0 ^ message
    v2 = v2 ^ 0x00000000000000ff

    list_vnew=sip_round(v0,v1,v2,v3)
    v0=list_vnew[0]
    v1=list_vnew[1]
    v2=list_vnew[2]
    v3=list_vnew[3]
    list_vnew=sip_round(v0,v1,v2,v3)
    v0=list_vnew[0]
    v1=list_vnew[1]
    v2=list_vnew[2]
    v3=list_vnew[3]  

    result = (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF
    return result

def cal_sessionkey(session,i):
    src = src_dst[0]&0xffffffffffffffff
    dst = src_dst[1]&0xffffffffffffffff
    addr=src ^ dst
    skey = sip_hash(session& 0xffffffffffffffff,sk_sw_origin[i]& 0xffffffffffffffff,addr)
    #print ("i:",i,"skey:",hex(skey),skey)
    return skey

def send_marking(epoch,seq,session,i,dataauth):
    src_mark = 0
    last_label=0
    next_label=0
    flag = 0
    if i>=0:
        j=i
        if(j!=0):
            last_label=list_label[j-1]
        if(j<9):
            next_label=list_label[j+1]
        sk=cal_sessionkey(session,j)
        const_hdr = ((flag<<24) +(epoch<<16) + seq) & 0xffffffff
        const_hdr = (const_hdr<<32) + last_label;
        src_mark_temp=sip_hash(const_hdr, sk, next_label& 0xffffffff)
        src_mark = (src_mark_temp>>32) & 0xffffffff
        src_r = (src_mark_temp) & 0xffffffff
        #print "j:", j,"src_mark:",src_mark,"src_mark_whole:",src_mark_temp  
    #print "i**:", i,"src_mark:",hex(src_mark),"onion_mark:",hex(onion_mark),onion_mark,"mark_hop:",hex(mark_hop),mark_hop
    return src_mark,src_r

def send_ack_marking(epoch,seq,session,i,dataauth):
    onion_mark = dataauth& 0xffffffff
    ack_mark = 0
    last_label=0
    next_label=0
    j = HOPS-1
    while j >= 0:
        if(j==0):
            last_label=0
        if(j!=0):
            last_label=list_label[j-1]
        if(j<9):
            next_label=list_label[j+1]
        sk=cal_sessionkey(session,j)
        const_hdr = ((epoch<<16) + seq) & 0xffffffff
        const_hdr = const_hdr ^ last_label;
        const_hdr = (const_hdr ^ next_label)& 0xffffffff;
        src_mark_temp=sip_hash(onion_mark, sk, const_hdr)
        #print "j:", j,"src_mark:",src_mark,"onion_mark:",onion_mark
        if (j==i):  #calculate the source mark    
            ack_mark = src_mark_temp
        j=j-1
    
    #print "i**:", i,"src_mark:",hex(src_mark),"onion_mark:",hex(onion_mark),onion_mark,"mark_hop:",hex(mark_hop),mark_hop
    return ack_mark,onion_mark



def pack_128(rk):
    #print "rk:",rk 
    rkey=[(rk>>64)&0xffffffffffffffff,rk&0xffffffffffffffff]                  
    key=struct.pack(">QQ",rkey[0],rkey[1])
    #print "switch.key:", rkey[0],rkey[1]
    return key

def find_router(label,dataauth,session):
    mark_hop=11
    for k in range(HOPS): 
        if label== list_label[k]:
            mark_hop=k
            break   
    return mark_hop

def hash_toint(text,k,num):
    message_add=text+str(k)
    hash  = hashlib.md5()
    hash.update(message_add)
    ret_hash = hash.hexdigest()
    #print("wholehash:",ret_hash)
    int_hash=int(ret_hash[0:num],16)
    #print "inthash:",int_hash
    return int_hash

def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# '9999999999999999'
def encrypt(text,key):
    #key = k.encode('utf-8')  #(str(k)).encode('utf-8')
    print(key)
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)    #16
    return b2a_hex(cipher_text)


# strip()
def decrypt(text,key):
    #key = k.encode('utf-8') #'9999999999999999'
    iv = b'qqqqqqqqqqqqqqqq'
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    cryp_text=a2b_hex(text)
    plain_text = cryptos.decrypt(cryp_text)
    return bytes.decode(plain_text).rstrip('\0')



class trustke(Packet):
   fields_desc = [ BitField("flag", 0, 8),
                   BitField("epoch", 0, 8),
                   BitField("seq", 0, 16),
                   BitField("label", 0, 32),
                   BitField("session", 0, 32),                  
                   BitField("dataauth", 0, 32),
                   BitField("mac", 0, 32)]    



bind_layers(IPv6, trustke, nh=150)
#bind_layers(trustke, TCP)



if __name__ == '__main__':
    main()
