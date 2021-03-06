# proxy-bloxy
**proxy-bloxy** is a dead simple tool created for performing DoS attack over LAN by capturing traffic of all/selected local network devices and blocking it.
# Features
It's simple, yet feature-rich:
- Local network devices autodiscovery.
- Multiprocessing
- Handling CSV files as input instead of auto-discovery.
- A single-file installation script written in bash.
- Ability to run without any visual output.
- Fancy ASCII logo
- And some more!

### Options
proxy-bloxy has the following options:

```

-h, --help                                         show this help message and exit

-i INTERFACE, --interface INTERFACE                Pick an interface which'll be used.                                                               

-g GATEWAY, --gateway GATEWAY                      Pick your gateway IP Address.                                                                     

-t TIME, --time TIME                               Optional selection of delays between target poisons. (Default - 0.3)                                                                                   

-p PINGS, --pings PINGS                            Optional selection of number of pings sent to network targets when 
                                                   parsing ip list. (Default - 3)                                                       

-v CSV, --csv CSV                                  Optional selection of CSV file/file path containing ip's list in 
                                                   substitution for script-detected network targets. All addresses must be 
                                                   placed in the different lines.

-s {True,False}, --silent {True,False}             Optional selection of making the script return no status messages. 
                                                   (Default - False) 
                                                   
-l {True,False}, --logo {True,False}               Optional selection to turn off the logo visibility. (Default - False)

-b SUBPROCESSES, --subprocesses SUBPROCESSES       Choose the subprocesses number limit. 
                                                   (NOTE: If '0' is inputted script will automatically select the limit.)
                                                   
-c CYCLES, --cycles CYCLES                         Choose the number of poisoning cycles.


```

# Installation
Before everything, you need [python3](https://www.python.org/downloads/) installed.
Further on you've got two options:

### Option 1: Installation Script
- In case you're going to use the newest release, pick one of the [releases.](https://github.com/Crowfunder/proxy-bloxy/releases)
- Download **install.sh**.
- Run it.
```sh
$ ./install.sh
```


### Option 2: Manual
Clone this repo with command:
```sh
$ git clone https://github.com/crowfunder/proxy-bloxy.git
```

- Run a prepared installator (install.sh) with a command:
```sh
$ cd proxy-bloxy
$ ./install.sh
```
You'll be able to run it from anywhere with command:
```
$ sudo proxy-bloxy {args}
```
**OR**
- You can run it without installation, just install python requirements and use:
```sh
$ cd proxy-bloxy
$ sudo python3 proxy_bloxy.py {args}
```


# Troubleshooting

**Permissions error prevent me from running "install.sh"**
1. run `chmod +x install.sh`

**I'm getting weird errors that like `/usr/bin/env: ‘python3\r’: No such file or directory`**
1. Install `dos2unix` package. 
2. Run `dos2unix proxy_bloxy.py`
3. Re-run install.sh.

**I want to run this script without root permissions.**
- That's one of the most important things I'm trying to do with this script right now. For now i **don't know** how to do that. You can check [this answer](https://stackoverflow.com/questions/36215201/python-scapy-sniff-without-root) although i'm not sure if it works. Probably I'll have to find a better ARP packets sending method.

**I've used it in a big network (multiple devices) and it doesn't work, why?**
 - The thing is it **does** work, but it's too slow to handle constantly sending ARP requests to multiple clients, you can try to lower the delay between poisons with `-t` argument.

# Contributing
As always, feel free to contribute to this project if you wish to. Just don't break the license!
### How does that even work?
It's simple
1) First we ping all the devices in the local network to check if they're up, if they are we add them to ip list.
1.1) Unless we select a csv list of ip addresses. If we do - this step is ommited.
2) We start to send poisoned ARP packets to the selected devices.
3) Entire victims' traffic is captured in the void, because nothing is done by the attacker's machine with the incoming redirected packets (IP forwarding disabled by default). Therefore we perform a Denial of Service attack locally.

### TODOs
Listed by importance:
- Fully Supported Windows Port with a Batch Installer. 
- Rootless Usage. (Sending ARP packets with the used method requires superuser permissions)
- Optimization and Code Cleaning. (Especially vars and imports)
### Disclaimer
I do not take any responsibility for anything done with this tool, As long as you aren't breaking the license i don't care. This script is an experiment
### License
[GNU General Public License v3.0](https://github.com/Crowfunder/proxy-bloxy/blob/master/LICENSE)


