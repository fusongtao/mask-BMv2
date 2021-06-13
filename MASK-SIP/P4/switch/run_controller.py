#!/usr/bin/env python2
import argparse

import switch_controller



parser = argparse.ArgumentParser(description='P4Runtime Controller')
parser.add_argument('--p4info', help='p4info proto in text format from p4c', type=str, action="store", required=False,
                    default='../build/basic.p4info')
parser.add_argument('--bmv2-json', help='BMv2 JSON filename from p4c', type=str, action="store", required=False,
                    default='../build/basic.json')
parser.add_argument('--port-mapping', help='link and port number mapping info', type=str, action="store",
                    required=False,
                    default='../build/port_mapping.json')
parser.add_argument('--topo', help='network topology info', type=str, action="store", required=False,
                    default='../assets/topology.json')
parser.add_argument('--routing', help='routing configure', type=str, action="store", required=False,
                    default='../assets/routing.json')
parser.add_argument('-a', help='P4Runtime address', type=str, action="store", required=False,
                    default='127.0.0.1:50051')
parser.add_argument('-n', help='name of the switch (needs to be unique)', type=str, action="store", required=False,
                    default='s0')
parser.add_argument('-d', help='device id of the switch', type=str, action="store", required=False,
                    default='0')
parser.add_argument('--num-ports', help='number of ports excluding CPU port', type=str, action="store", required=False,
                    default='15')
parser.add_argument('--d-val-path', help='the filename path of d-val', type=str, action="store", required=False,
                    default='../assets/dval.json')
args = parser.parse_args()

switch_name = args.n
switch_ip = args.a
device_id = int(args.d)
num_ports = args.num_ports

# global ctrl
ctrl = switch_controller.SwitchController(args.p4info, args.bmv2_json, args.port_mapping, args.topo, args.routing,
                                          args.d_val_path)

# BMV2 switches
ctrl.add_switch_connection(switch_name,
                           address=switch_ip,
                           device_id=device_id,
                           debug=False,
                           type='bmv2',
                           num_ports=num_ports)
ctrl.startup()
