# -*-coding: utf-8 -*-

import os
import tempfile
from time import sleep

from mininet.log import info, error
from mininet.moduledeps import pathCheck
from mininet.node import Switch

from netstat import check_listening_on_port
from p4_mininet import P4Switch, SWITCH_START_TIMEOUT


class P4RuntimeSwitch(P4Switch):
    "BMv2 switch with gRPC support"
    next_grpc_port = 50051
    next_thrift_port = 9090

    def __init__(self, name, sw_path=None, json_path=None,
                 grpc_port=None,
                 thrift_port=None,
                 pcap_dump=False,
                 log_console=False,
                 verbose=False,
                 device_id=None,
                 enable_debugger=False,
                 log_file=None,
                 cpu_port=None,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert (sw_path)
        self.sw_path = sw_path
        # make sure that the provided sw_path is valid
        pathCheck(sw_path)

        if json_path is not None:
            # make sure that the provided JSON filename exists
            if not os.path.isfile(json_path):
                error("Invalid JSON filename.\n")
                exit(1)
            self.json_path = json_path
        else:
            self.json_path = None

        if grpc_port is not None:
            self.grpc_port = grpc_port
        else:
            self.grpc_port = P4RuntimeSwitch.next_grpc_port
            P4RuntimeSwitch.next_grpc_port += 1

        if thrift_port is not None:
            self.thrift_port = thrift_port
        else:
            self.thrift_port = P4RuntimeSwitch.next_thrift_port
            P4RuntimeSwitch.next_thrift_port += 1

        if check_listening_on_port(self.grpc_port):
            error('%s cannot bind port %d because it is bound by another process\n' % (self.name, self.grpc_port))
            exit(1)

        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console
        self.cpu_port = cpu_port
        if log_file is not None:
            self.log_file = log_file
        else:
            self.log_file = "/tmp/p4s.{}.log".format(self.name)
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)

    def check_switch_started(self, pid):
        for _ in range(SWITCH_START_TIMEOUT * 2):
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            if check_listening_on_port(self.grpc_port):
                return True
            sleep(0.5)

    def start(self, controllers):
        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        if self.pcap_dump:
            args.append("--pcap %s" % self.pcap_dump)
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")
        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")
        if self.thrift_port:
            args.append('--thrift-port ' + str(self.thrift_port))
        if self.grpc_port:
            args.append("-- --grpc-server-addr 0.0.0.0:" + str(self.grpc_port))
        if self.cpu_port:
            args.extend(['--cpu-port', str(self.cpu_port)])

        cmd = ' '.join(args)
        info(cmd + "\n")

        # retry at most 5 times
        pid = None
        for i in range(0, 5):
            with tempfile.NamedTemporaryFile() as f:
                self.cmd(cmd + ' >' + self.log_file + ' 2>&1 & echo $! >> ' + f.name)
                pid = int(f.read())
            print("P4 switch {} PID is {}.".format(self.name, pid))
            if not self.check_switch_started(pid):
                error("P4 switch {} did not start correctly on {} attempts.\n".format(self.name, i + 1))
            else:
                info("P4 Switch {} did start correctly.\n".format(self.name))
                break

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
