#!/usr/bin/env bash

#######################################
# Installation Script for proxy-bloxy #
# ___________________________________ #
# Must be run with root privileges    #
# ex. "sudo ./install.sh".            #
# In case of permissions error run    #
# "chmod +x install.sh"               #
# ___________________________________ #
#           by crowfunder             #
#######################################

GREEN="\033[0;32m"
NONE="\033[0m"
RED="\033[0;31m"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script has to be run as root (ex. "sudo ./install.sh")${NONE}"
    exit 1
fi

echo -e "Installing proxy-bloxy..."

read -p "Would you like to sync with the latest remote branch? (y/n): " opt
case $opt in
    [yY][eE][sS]|[yY])
        git fetch --prune
        echo -e "${GREEN}Success!${NONE}"
        ;;
esac

read -p "Would you like to download and/or update neccessary python packages? (y/n): " opt2
case $opt2 in
    [yY][eE][sS]|[yY])
        pip3 install scapy
        echo -e "${GREEN}Success!${NONE}"
        ;;
esac

if [ -f "/usr/local/bin/proxy-bloxy" ]; then
    echo -e "Detected other version installed, removing..."
    rm /usr/local/bin/proxy-bloxy
    echo -e "${GREEN}Success!${NONE}"
fi

cp proxy_bloxy.py /usr/local/bin
mv /usr/local/bin/proxy_bloxy.py /usr/local/bin/proxy-bloxy
chmod +x /usr/local/bin/proxy-bloxy
echo -e "${GREEN}Success, installation complete, you may now run the script with 'proxy-bloxy'${NONE}."
exit 0
