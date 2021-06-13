#!/usr/bin/env python2
# -*-coding: utf-8 -*-

import argparse
import json
import os
from time import sleep

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo

from p4_mininet import P4Host
from p4runtime_switch import P4RuntimeSwitch


def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        print('Thrift is not supported')

        return None


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
        A custom class is used because the exercises make a few topology
        assumptions, mostly about the IP and MAC addresses."""

    def __init__(self, hosts, switches, links, log_dir, cpu_port, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []
        self.sw_port_mapping = {}

        for link in links:
            if link['node1'][0] in ['h']:
                host_links.append(link)
            else:
                switch_links.append(link)

        link_sort_key = lambda x: x['node1'] + x['node2']
        # Links must be added in a sorted order so bmv2 port numbers are predictable
        host_links.sort(key=link_sort_key)
        switch_links.sort(key=link_sort_key)

        for sw in switches:
            self.addSwitch(sw, log_file="%s/%s.log" % (log_dir, sw), cpu_port=cpu_port)

        for link in host_links:
            host_name = link['node1']
            host_sw = link['node2']
            host_num = int(host_name[1:])
            sw_num = int(host_sw[1:])
            # host_ip = "10.0.%d.%d" % (sw_num, host_num)
            host_ip = hosts[host_name]
            host_mac = '00:00:00:00:%02x:%02x' % (sw_num, host_num)
            switch_mac = '00:00:00:11:%02x:%02x' % (sw_num, host_num)

            self.addHost(host_name, ip=host_ip + '/16', mac=host_mac)
            # self.addLink(host_name, host_sw,
            #              delay=link['latency'], bw=link['bandwidth'],
            #              addr1=host_mac, addr2=host_mac)
            self.addLink(host_name, host_sw,
                         delay=link['latency'], bw=link['bandwidth'],
                         addr1=host_mac, addr2=switch_mac)
            self.addSwitchPort(host_sw, host_name, host_mac)

        for link in switch_links:
            sw_num1 = int(link['node1'][1:])
            sw_num2 = int(link['node2'][1:])
            sw_mac_1 = '00:00:00:ff:%02x:%02x' % (sw_num1, sw_num2)
            sw_mac_2 = '00:00:00:ff:%02x:%02x' % (sw_num2, sw_num1)
            self.addLink(link['node1'], link['node2'],
                         delay=link['latency'], bw=link['bandwidth'], addr1=sw_mac_1, addr2=sw_mac_2)
            self.addSwitchPort(link['node1'], link['node2'], sw_mac_2)
            self.addSwitchPort(link['node2'], link['node1'], sw_mac_1)

        self.savePortMapping()

    def addSwitchPort(self, sw, node2, mac):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = {}
        portno = len(self.sw_port_mapping[sw])
        self.sw_port_mapping[sw][portno] = (node2, mac)

    def savePortMapping(self):
        print "Switch port mapping:"
        for sw in sorted(self.sw_port_mapping.keys()):
            print "%s: " % sw,
            for mp in sorted(self.sw_port_mapping[sw].keys()):
                print "%d:%s\t" % (mp, self.sw_port_mapping[sw][mp][0]),
            print

        with open('./build/port_mapping.json', 'w') as f:
            f.write(json.dumps(self.sw_port_mapping))


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : list<string>       // list of mininet host names
            switches : dict<string, dict> // mininet host names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance
    """

    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def formatLatency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"

    def __init__(self, topo_file, log_dir, pcap_dir,
                 switch_json, bmv2_exe='simple_switch', quiet=False, cpu_port=None):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json filename which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet
        self.logger('Reading topology filename.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)
        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe
        self.cpu_port = cpu_port

    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        self.do_net_cli()
        # stop right after the CLI is exited
        self.net.stop()

    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s, t = t, s

            link_dict = {'node1': s,
                         'node2': t,
                         'latency': '0ms',
                         'bandwidth': None
                         }

            if len(link) > 2:
                link_dict['latency'] = self.formatLatency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(
                    link_dict['node2'])
            if link_dict['node2'][0] == 'c':
                assert link_dict['node1'][0] == 'a', 'Controller should be connected to agents, not ' + str(
                    link_dict['node1'])
            if link_dict['node1'][0] == 'h' and link_dict['node2'][0] == 'h':
                assert self.switches[s].has_key[t], s + ' has no proper ip for ' + t
                assert self.switches[t].has_key[s], t + ' has no proper ip for ' + s
            links.append(link_dict)
        return links

    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")
        self.topo = ExerciseTopo(self.hosts, self.switches.keys(), self.links, self.log_dir, self.cpu_port)

        switchClass = configureP4Switch(
            sw_path=self.bmv2_exe,
            json_path=self.switch_json,
            log_console=True,
            pcap_dump=self.pcap_dir,
            cpu_port=self.cpu_port)

        self.net = Mininet(topo=self.topo,
                           link=TCLink,
                           host=P4Host,
                           switch=switchClass,
                           controller=None)

    def program_hosts(self):
        """ Adds static ARP entries and default routes to each mininet host.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for host_name in self.topo.hosts():
            h = self.net.get(host_name)
            h_iface = h.intfs.values()[0]
            link = h_iface.link

            sw_iface = link.intf1 if link.intf1 != h_iface else link.intf2
            sw_name = str(sw_iface).split('-')[0]
            # phony IP to lie to the host about
            assert self.switches[sw_name].has_key(host_name), 'Gateway IP for ' + host_name + ' is missed'
            sw_ip = self.switches[sw_name][host_name]

            # Ensure each host's interface name is unique, or else
            # mininet cannot shutdown gracefully
            h.defaultIntf().rename('%s-eth0' % host_name)
            # static arp entries and default routes
            h.cmd('arp -i %s -s %s %s' % (h_iface.name, sw_ip, sw_iface.mac))
            for name in self.hosts.keys():
                addr = self.hosts[name]
                if name != host_name:
                    h.cmd('arp -i %s -s %s %s' % (h_iface.name, addr, sw_iface.mac))

            h.cmd('ethtool --offload %s rx off tx off' % h_iface.name)
            h.cmd('ip route add %s dev %s' % (sw_ip, h_iface.name))
            h.setDefaultRoute("via %s" % sw_ip)

    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' % self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='../assets/topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                        type=str, required=False, default='simple_switch')
    parser.add_argument('-c', '--cpu-port', type=int, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    # from mininet.log import setLogLevel
    setLogLevel("info")

    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet, args.cpu_port)

    exercise.run_exercise()
