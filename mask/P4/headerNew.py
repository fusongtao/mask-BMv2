#!/usr/bRin/env python
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


policy="50"
DATA=0
NEG=1
ACK=2
sk_d="0123456789abcdef"
sk_sw=[0x875a1f386d09e375ab1f718b4ac08365,0xc18c0a7f1d6eb6cf02fdc3948716d6ec,0x68caba7dca8648c59785d4f41e2b4490,
       0x99b1cd33fe229ab329cfd45544907eda,0xdcbd520134bf2db3c757673bc1e69cd0]
'''
sk_sw_origin=[123456789012,223456789012,323456789012,423456789012,523456789012]  #switch order
'''
list_label=[0x0a000001,0x0a000002,0x0a000003,0x0a000004,0x0a000005]  #switch order
src_dst=[0x0a000001000000000000000000000001,0x0a000002000000000000000000000002]
src_dst_str=["0a00:0001::0001","0a00:0002::0002"]

def cal_sessionkey(i,session_hash):
    src1 = (src_dst[0]>>64 & 0xFFFFFFFFFFFFFFFF)
    src2 = (src_dst[0]& 0xFFFFFFFFFFFFFFFF)
    dst1 = (src_dst[1]>>64 & 0xFFFFFFFFFFFFFFFF)
    dst2 = (src_dst[1]& 0xFFFFFFFFFFFFFFFF)
    #print "src1:",src1,"src2:",src2,"dst1",dst1,"dst2:",dst2,"session_hash:",session_hash,hex(src_dst[0])
    src = struct.pack(">Q",src1) + struct.pack(">Q",src2)
    dst = struct.pack(">Q",dst1) + struct.pack(">Q",dst2)
    message = src + dst+struct.pack(">I",session_hash) 
    sk1 = (sk_sw_origin[i]>>64) & 0xFFFFFFFFFFFFFFFF
    sk2 = (sk_sw_origin[i]) & 0xFFFFFFFFFFFFFFFF
    #print "sk1:",sk1,"sk2:",sk2
    key= struct.pack("!QQ",sk1,sk2)
    #print ("key:",struct.unpack("!QQ",key))
    sk = (hmac.new(key,message)).digest()
    skey = struct.unpack("!QQ", sk)
    int_skey = (skey[0]<<64)+skey[1]
    print sk,"skey:",int_skey,hex(int_skey)
    return sk,hex(int_skey)

def send_marking(sk,message):
    cal_mac = ((hmac.new(sk,message)).digest())
    print "cal-fullmac:", struct.unpack("!2Q",cal_mac)
    mac = struct.unpack("!I",cal_mac[12:16])
    int_mac = mac[0]
    print "cal_mac:",hex(int_mac)
    return int_mac

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
def encrypt(text,k):
    key = k.encode('utf-8')  #(str(k)).encode('utf-8')
    print(key)
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)    #16
    return b2a_hex(cipher_text)


# strip()
def decrypt(text,k):
    key = k.encode('utf-8') #'9999999999999999'
    iv = b'qqqqqqqqqqqqqqqq'
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    cryp_text=a2b_hex(text)
    plain_text = cryptos.decrypt(cryp_text)
    return bytes.decode(plain_text).rstrip('\0')


class maskh(Packet):
   fields_desc = [ BitField("nHeader", 0, 8),
                   BitField("hLen", 0, 8),
                   BitField("flag", 0, 8),
                   BitField("label", 0, 32),
                   BitField("session", 0, 32),                  
                   BitField("datahash", 0, 32),
                   BitField("mac", 0, 32)]  



bind_layers(IPv6, maskh, nh=143)
bind_layers(maskh, TCP,nHeader=1)



if __name__ == '__main__':
    main()
