# proxy-bloxy
**proxy-bloxy** is a dead simple tool created for performing DoS attack over LAN by capturing traffic of all/selected local network devices and blocking it.
# Features
It's simple, yet feature-rich:
- Local network devices autodiscovery.
- Handling CSV files as input instead of auto-discovery.
- A nice installator script.
- Ability to run without any visual output.
- Fancy ASCII logo
- And some more!
### Options
Entire script has following options
```
-h, --help                                         show this help message and exit

-i INTERFACE, --interface INTERFACE                Pick an interface which'll be used.                                                               

-g GATEWAY, --gateway GATEWAY                      Pick your gateway IP Address.                                                                     

-t TIME, --time TIME                               Optional selection of delays between target poisons. (Default - 0.3)                                                                                   

-p PINGS, --pings PINGS                            Optional selection of number of pings sent to network targets when 
                                                   parsing ip list. (Default - 3)                                                       

-c CSV, --csv CSV                                  Optional selection of CSV file/file path containing ip's list in 
                                                   substitution for script-detected network targets. All addresses must be 
                                                   placed in the different lines.

-s {True,False}, --silent {True,False}             Optional selection of making the script return no status messages. 
                                                   (Default - False) 
                                                   
-l {True,False}, --logo {True,False}               Optional selection to turn off the logo visibility. (Default - False)
```

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
1. run `chmod +x install.sh`

**I'm getting weird errors that like `/usr/bin/env: ‘python3\r’: No such file or directory`**
1. Install `dos2unix` package. 
2. Run `dos2unix proxy_bloxy.py`
3. Re-run install.sh.

**I lost my internet connection when using this script**
- That thing is caused by the fact that we block entire outgoing and forwarded traffic on iptables, and so we block ourselves too.

**I lost my internet connection after force-exiting the script (ex. CTRL+Z)**
1. Rerun the script and exit it normally by clicking CTRL+C some times letting exit-handler to finish the job. (Until you see `Exiting...`)

**I've used it in a big network (multiple devices) and it doesn't work, why?**
 - The thing is it **does** work, but it's too slow to handle constantly sending ARP requests to multiple clients, you can try to lower the delay between poisons with `-t` argument.

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


