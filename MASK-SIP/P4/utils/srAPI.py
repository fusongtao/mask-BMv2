#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import threading
import time
import sys
import logging
import os
import struct
import csv

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.layers.inet import _IPOption_HDR
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, ICMP, Raw, Padding

from d_val_util import DVal

import log_config

RResp_PROTO_OPT = 253
RReq_PROTO_OPT = 254
MAX_THRESHOLD = 0.5
MIN_THRESHOLD = 0.32


def get_self_name():
    return get_if().split('-')[1]


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        logging.error("Cannot find eth0 interface")
        exit(1)
    return iface


def handle_pkt(pkts):
    # logging.info(("pkts:", type(pkts)))
    if pkts is not None and len(pkts) != 0:
        # sum_d_val = 0.0
        count = 0
        d_val_set = {}

        for p in pkts:
            if p.haslayer('IP') and p[IP].proto == RResp_PROTO_OPT and p.haslayer('Raw'):
                logging.info("got a deviation packet")
                # logging.info(str(p[Raw]))
                # p.show()
                # logging.info(p[Raw].load)
                # logging.info(p[Raw].load)
                # logging.info(type(p[Raw].payload))
                # logging.info(type(p[Raw][Padding].load))
                # logging.info(len(p[Raw].load))
                count += 1
                val = struct.unpack(">f", str(p[Raw][Padding].load))[0]
                d_val_set[str(p[IP].src)] = val
                # logging.info(type(val))
                # logging.info(val)
                # sum_d_val += val
                # logging.info("sum_d_val: %f" % sum_d_val)
            # if count != 0:
            #     logging.info("avg d_val: %f" % (sum_d_val / count))
            # else:
            #     logging.info("not recommender data")
        return d_val_set, count


def getDVal(dst):
    d_val = DVal.getDVal()
    self_name = get_self_name()
    if d_val.get(self_name) and d_val.get(self_name).get(dst):
        return d_val.get(self_name).get(dst)
    else:
        return None


def setDVal(dst, value):
    name = get_self_name()
    DVal.setDValItem(name, dst, value)


def beforSend(dst):
    """

    """
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    logging.info("sniffing on %s" % iface)
    pkts = sniff(filter="ip[9]=" + str(RResp_PROTO_OPT), prn=lambda x: x.summary(), iface=iface, count=0, timeout=5)
    d_val_set, count = {}, 0
    logging.info(("pkts:", pkts))
    if pkts:
        d_val_set, count = handle_pkt(pkts)
    return d_val_set, count


def send_pkt(iface, dst, payload):
    logging.info("sending on interface %s to %s" % (iface, dst))
    pkt = Ether(src=get_if_hwaddr(iface)) / IP(dst=dst) / payload
    sendp(pkt)


def writeTimeToFile(internal_time_arr, filepath='./assets/time.csv'):
    with open(filepath, 'w') as f:
        f_csv = csv.writer(f)
        f_csv.writerow(['index', 'time'])
        i = 1

        for inter_time in internal_time_arr:
            f_csv.writerow((i, inter_time))
            i += 1
