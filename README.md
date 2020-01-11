# proxy-bloxy
**proxy-bloxy** is a dead simple tool created for performing DoS attack over LAN by capturing traffic of all/selected local network devices and blocking it.
# Features
It's simple, yet feature-rich:
- Local network devices autodiscovery.
- Handling CSV files as input instead of auto-discovery.
- A nice installator script.
- Ability to run without any visual output.
- And some more!

# Installation
Before everything, you need [python3](https://www.python.org/downloads/) installed.
Then you've got to clone this repo with command:
```sh
$ git clone https://github.com/crowfunder/proxy-bloxy.git
```
Installation process is dead simple, you've got two options:
- Run a prepared installator (install.sh) with a command:
```sh
$ cd proxy-bloxy
$ sudo ./install.sh
```
You'll be able to run it from anywhere with command:
```
$ sudo proxy-bloxy {args}
```
- Or you can run it without installation, just install python requirements (scapy) and use:
```sh
$ cd proxy-bloxy
$ sudo python3 proxy_bloxy.py {args}
```
# Troubleshooting

**Permissions error prevent me from running "install.sh"**
1) run `chmod +x install.sh`

**I'm getting weird errors that like `/usr/bin/env: ‘python3\r’: No such file or directory`**
1. Install `dos2unix` package. 
2. Run `dos2unix proxy_bloxy.py`
3. Re-run install.sh.

**I lost my internet connection when using this script**
- That thing is caused by the fact that be block entire outgoing and forwarded traffic on iptables, and so we block ourselves too.

# Contributing
As always, feel free to contribute to this project if you wish to. Just don't break the license!
### How does that even work?
It's simple
1) First we ping all the devices in the local network to check if they're up, if they are we add them to ip list.
2) We block entire outgoing and forwarded traffic on iptables.
3) We start to send poisoned ARP packets to selected devices.
4) Their traffic is captured in the void, and so we perform a DoS attack locally.

### Disclaimer
I do not take any responsibility for anything done with this tool, As long as you aren't breaking the license i don't care.
### License
[GNU General Public License v3.0](https://github.com/Crowfunder/proxy-bloxy/blob/master/LICENSE)


