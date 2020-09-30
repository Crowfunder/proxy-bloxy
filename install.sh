#!/usr/bin/env bash

#######################################
# Installation Script for proxy-bloxy #
# ___________________________________ #
# In case of permissions error run    #
# "chmod +x install.sh"               #
# ___________________________________ #
#           by crowfunder             #
#######################################

GREEN="\033[0;32m"
NONE="\033[0m"
RED="\033[0;31m"


echo -e "Installing proxy-bloxy..."
echo -e "_______________________________________________________________"
if [ -f "proxy_bloxy.py" ]; then
    read -p "Would you like to sync with the latest remote branch? (y/n): " opt
    case $opt in
        [yY][eE][sS]|[yY])
            git fetch origin && git reset --hard origin/master && git clean -f -d
            echo -e "${GREEN}Success!${NONE}"
            ;;
    esac
else
    echo -e "Downloading..."
    echo -e "_______________________________________________________________"
    git clone https://github.com/crowfunder/proxy-bloxy.git
    cd proxy-bloxy
    echo -e "${GREEN}Success!${NONE}"
fi


echo -e "_______________________________________________________________"
read -p "Would you like to download and/or update neccessary python packages? (y/n): " opt2
case $opt2 in
    [yY][eE][sS]|[yY])
        sudo pip3 install scapy getmac
        echo -e "${GREEN}Success!${NONE}"
        ;;
esac

echo -e "_______________________________________________________________"
if [ -f "/usr/local/bin/proxy-bloxy" ]; then
    echo -e "Detected other version installed, removing..."
    sudo rm /usr/local/bin/proxy-bloxy
    echo -e "${GREEN}Success!${NONE}"
    echo -e "_______________________________________________________________"
fi

sudo cp proxy_bloxy.py /usr/local/bin
sudo mv /usr/local/bin/proxy_bloxy.py /usr/local/bin/proxy-bloxy
sudo chmod +x /usr/local/bin/proxy-bloxy
echo -e "${GREEN}Success, installation complete, you may now run the script with 'proxy-bloxy'${NONE}."
exit 0
