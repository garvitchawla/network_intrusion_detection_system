#!/usr/bin/env python

from scapy.all import sniff
import scapy.all as scapy
import sys
import oyaml as yaml
from collections import OrderedDict
import StringIO
from io import BytesIO as StringIO
import os
import re
import datetime, time
import nids

# from datetime import timezone, datetime

uniqipids = {}
ippackets = list()
fragmentedpackets = list()
fragmenttrain = list()

if (len(sys.argv) == 1):
    print "Please provide configuration yaml file as an argument."
    sys.exit()

with open(sys.argv[1], 'r') as stream:
    try:
        d = yaml.load(stream)
    except yaml.YAMLError as exc:
        print(exc)

# Breaking down Dictionary for Values.
# pcap_path = '/root/Desktop/ip_frag1.pcap'
# pcap_path = '/root/Desktop/tcp1.pcap'
# pcap_path = '/root/Desktop/facebook_random2.pcap'
pcap_path = d['pcap_path']
interface = d['interface']
network = d['network']
enable_checksums = d['enable_checksums']

ipv4_default_behavior = d['ipv4_fragment_reassembly']['default_behavior']
ipv4_endpoint_behavior = d['ipv4_fragment_reassembly']['endpoints'][0]['behavior']
ipv4_address = d['ipv4_fragment_reassembly']['endpoints'][0]['ipv4_address']

tcp_default_behavior = d['tcp_reassembly']['default_behavior']
tcp_endpoint_behavior = d['tcp_reassembly']['endpoints'][0]['behavior']
tcp_ipv4_address = d['tcp_reassembly']['endpoints'][0]['ipv4_address']

name = d['rules'][0]['name']
destination_port = d['rules'][0]['destination_port']

content = d['rules'][0]['content']
#content = "facebook"
frag_size = 8

# IDEA:
'''
First check if packets through Interface or through a pcap.
Find the network.
Then compute ipv4 and tcp checksums, if enabled.
For every packet, Do iPv4 fragment reassembly, based on default or current behavior.
Then for every packet, Do TCP reassembly, based on default or current behavior.
Then for those packets after TCP reassembly, check the destination port first and look for the content (regex) in the defragmented TCP and save it.
'''

##########################################################################################
# CHECKSUM
def iptcpchecksum():
    for packet in pcap_file:
        if packet.haslayer(scapy.IP) and not packet.haslayer(scapy.TCP):
            # packet.show()
            # packet.ttl = packet.ttl - 1
            # del packet.chksum
            del packet[scapy.IP].chksum
            # del packet[scapy.TCP].chksum
            x = packet.show2(dump=True)
            # print(packet[scapy.IP].chksum)
            # print(x)
            # print(type(x))
            # Get the four values of "0x" in output of show2(), 3rd IP, 4th TCP
            chksum_list = []
            for word in x.split():
                if "0x" in word:
                    chksum_list.append(word)

            ip_chksum = chksum_list[2]
            # tcp_chksum = chksum_list[3]
            # print("IP checksum ", ip_chksum)
            # print("TCP checksum ", tcp_chksum)

            # if 'chksum' in x:
            #    print("Yes")

        elif packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP) and not packet.haslayer(scapy.ICMP):
            # packet.show()
            # packet.ttl = packet.ttl - 1
            # del packet.chksum
            del packet[scapy.IP].chksum
            del packet[scapy.TCP].chksum
            x = packet.show2(dump=True)
            # print(packet[scapy.IP].chksum)
            # print(x)
            # print(type(x))
            # Get the four values of "0x" in output of show2(), 3rd IP, 4th TCP
            chksum_list = []
            for word in x.split():
                if "0x" in word:
                    chksum_list.append(word)

            ip_chksum = chksum_list[2]
            tcp_chksum = chksum_list[3]
            # print("IP checksum ", ip_chksum)
            # print("TCP checksum ", tcp_chksum)


##############################################################################################################
# IP FRAGMENT REASSEMBLY
def networkmonitor(network):
    ip, cidr = network.split('/')


def first(fragmentsin):
    buffer = StringIO()
    for pkt in fragmentsin[::-1]:
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def last(fragmentsin):
    buffer = StringIO()
    for pkt in fragmentsin[::1]:
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def linux(fragmentsin):
    buffer = StringIO()
    for pkt in sorted(fragmentsin, key=lambda x: x[scapy.IP].frag, reverse=True):
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def processfrags(fragmenttrain):
    if ipv4_default_behavior != "":
        if ipv4_endpoint_behavior == "":
            if ipv4_default_behavior == 'last':
                print
                last(fragmenttrain)
            elif ipv4_default_behavior == 'first':
                print
                first(fragmenttrain)
            elif ipv4_default_behavior == 'linux':
                print
                linux(fragmenttrain)
        elif ipv4_endpoint_behavior != "":
            if ipv4_endpoint_behavior == 'last':
                print
                last(fragmenttrain)
            elif ipv4_endpoint_behavior == 'first':
                print
                first(fragmenttrain)
            elif ipv4_endpoint_behavior == 'linux':
                print
                linux(fragmenttrain)


def getTime(pkt):
    pktTime = int(pkt.time)
    # print "Packet Time: ", pktTime

##########################################################################################

def collect_fragment():
    if enable_checksums == True:
        iptcpchecksum()

    for a in pcap_file:
        if a.haslayer(scapy.IP):
            ippackets.append(a)

    for frag_pkt in ippackets:
        if frag_pkt[scapy.IP].flags == 1 or frag_pkt[scapy.IP].frag > 0:
            fragmentedpackets.append(frag_pkt)

    for a in fragmentedpackets:
        uniqipids[a[scapy.IP].id] = ''
    for ipid in uniqipids.keys():
        print
        ""
    for x in fragmentedpackets:
        if x[scapy.IP].id == ipid:
            fragmenttrain.append(x)
            # getTime(x)
    processfrags(fragmenttrain)


##########################################################################################
def sniff_fragment(a):

    if a.haslayer(scapy.IP):
        ippackets.append(a)

for frag_pkt in ippackets:
    if frag_pkt[scapy.IP].flags == 1 or frag_pkt[scapy.IP].frag > 0:
        fragmentedpackets.append(frag_pkt)

for a in fragmentedpackets:
    uniqipids[a[scapy.IP].id] = ''

for ipid in uniqipids.keys():
    print ""

for x in fragmentedpackets:
    if x[scapy.IP].id == ipid:
        fragmenttrain.append(x)

processfrags(fragmenttrain)
##########################################################################################

# Packet through Interface OR PCAP check.
if pcap_path is not '':
    pcap_file = scapy.rdpcap(pcap_path)
    collect_fragment()
else:
    sniff(iface=interface, prn=sniff_fragment, store=0, count=1000)

##########################################################################################
# IP FRAGMENT REASSEMBLY

def networkmonitor(network):
    ip, cidr = network.split('/')


def first(fragmentsin):
    buffer = StringIO()
    for pkt in fragmentsin[::-1]:
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def last(fragmentsin):
    buffer = StringIO()
    for pkt in fragmentsin[::1]:
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def linux(fragmentsin):
    buffer = StringIO()
    for pkt in sorted(fragmentsin, key=lambda x: x[scapy.IP].frag, reverse=True):
        buffer.seek(pkt[scapy.IP].frag * frag_size)
        buffer.write(pkt[scapy.Raw].load)
    return buffer.getvalue()


def processfrags(fragmenttrain):
    if ipv4_default_behavior != "":
        if ipv4_endpoint_behavior == "":
            if ipv4_default_behavior == 'last':
                print
                last(fragmenttrain)
            elif ipv4_default_behavior == 'first':
                print
                first(fragmenttrain)
            elif ipv4_default_behavior == 'linux':
                print
                linux(fragmenttrain)
        elif ipv4_endpoint_behavior != "":
            if ipv4_endpoint_behavior == 'last':
                print
                last(fragmenttrain)
            elif ipv4_endpoint_behavior == 'first':
                print
                first(fragmenttrain)
            elif ipv4_endpoint_behavior == 'linux':
                print
                linux(fragmenttrain)


def getTime(pkt):
    pktTime = int(pkt.time)
    # print "Packet Time: ", pktTime


#################################################################################################################################
# TCP REASSEMBLY
# pcap_path = '/root/Desktop/facebook_random2.pcap'

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

globs = {'regexobj': re.compile(content)}

matchstats = {'start': 0, 'end': 0, 'size': 0}


def gettimestamp():
    sometime = int(nids.get_pkt_ts())
    return sometime


def inspect(data):
    matchobj = globs['regexobj'].search(data)

    if matchobj:
        matchstats['start'] = matchobj.start()
        matchstats['end'] = matchobj.end()
        matchstats['size'] = matchobj.end() - matchobj.start()
        return True
    else:
        return False


def tcpcallback(tcp):

    ((src, sport), (dst, dport)) = tcp.addr

    if tcp.nids_state == nids.NIDS_JUST_EST:
        tcp.client.collect = 1
        tcp.server.collect = 1

    elif tcp.nids_state == nids.NIDS_DATA:
        tcp.discard(0)

        if len(tcp.server.data[:tcp.server.count]) > 0 and dport == destination_port:
            matched = inspect(tcp.server.data[:tcp.server.count])
            if matched:
                print "---"

                data = OrderedDict([(
                    'timestamp', gettimestamp()),
                    ('source', dict(
                        ipv4_address=src,
                        tcp_port=sport,
                    )),
                    ('target', dict(
                        ipv4_address=dst,
                        tcp_port=dport,
                    )),
                    ('rule', name)]
                )

                print(yaml.dump(data, default_flow_style=False))

                tcp.client.collect = 0
                tcp.server.collect = 0

                tcp.kill

                return

        if len(tcp.client.data[:tcp.client.count]) > 0 and dport == destination_port:
            matched = inspect(tcp.client.data[:tcp.client.count])
            if matched:
                print "---"

                data = OrderedDict([(
                    'timestamp', gettimestamp()),
                    ('source', dict(
                        ipv4_address=src,
                        tcp_port=sport,
                    )),
                    ('target', dict(
                        ipv4_address=dst,
                        tcp_port=dport,
                    )),
                    ('rule', name)]
                )

                print(yaml.dump(data, default_flow_style=False))

                tcp.client.collect = 0
                tcp.server.collect = 0

                tcp.kill

                return


##############################################################################

def main():
    # Packet through Interface OR PCAP check.
    if pcap_path is not '':
        nids.param('filename', pcap_path)
    else:
        nids.param('device', interface)

    nids.init()
    nids.register_tcp(tcpcallback)

    nids.run()


if __name__ == '__main__':
    main()

'''
#  References:
https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
https://7h3ram.github.io/2013/libnids-pynids.html
https://www.sans.org/reading-room/whitepapers/detection/paper/33969
'''

'''
# Printing format
---
timestamp: 1548797500           # UNIX timestamp   # Get it from getTime()
source:
  ipv4_address: "8.8.8.8"       # Source IPv4 address  # Get 
  tcp_port: 34567               # Source TCP port
target:
  ipv4_address: "1.1.1.1"       # Target IPv4 address
  tcp_port: 1234                # Target TCP port
rule: "example_rule"

'''