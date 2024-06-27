#!/usr/bin/env python

import scapy.all as scapy
import argparse


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="Specify The IP/IP Range")
    options = parser.parse_args()
    if not options.ip:
        parser.error("[-] Specify The IP/IP Range, --help for more info")
    else:
        return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def print_result(results_list):
    print("     IP\t\t\t       MAC             ")
    print("-----------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = arguments()
scan_result = scan(options.ip)
print_result(scan_result)
