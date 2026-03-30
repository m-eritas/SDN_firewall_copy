# SDN_firewall
Basic SDN Firewall implemented with Ryu and tested with Mininet. Local-only web page as Network Switch Controller GUI.


## Installation & Usage
> Tested on Acer with i5-10210U, 16GB RAM, 512GB SSD — Ubuntu 24.04.3 LTS (and Linux Mint 22.2), kernel 6.17.0-14-generic

### Install & Run
```bash
# global libraries
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install -y git xterm python3-pip python3.12 python3.12-venv python3.12-dev python3-pip openvswitch-switch

# project istallation
git clone https://github.com/GioeleSe/SDN_firewall/
cd SDN_firewall

# local libraries (from patched source)
source ./.venv/bin/activate
 ./.venv/bin/python3 -m pip install ./ryu/
 ./.venv/bin/python3 -m pip install ./mininet/
make ./mininet/mnexec
sudo install -v ./mininet/mnexec /usr/local/bin/

# project start
sudo systemctl start openvswitch-switch  # enable ovs as background service 
.venv/bin/python3 main.py				        # on one terminal start the controller app
sudo ./.venv/bin/mn --controller remote		# on the other terminal start mininet


```

### Uninstall
```bash
# stopping the project
Ctrl+C                            # to stop the (foreground) process of the server (and the mininet on the other terminal)
deactivate                       # exit from the python virtual environment
sudo systemctl stop openvswitch-switch    # stop the background service

# uninstalling the project:	
cd .. && sudo rm -rf SDN_firewall
```

---
*The development was done cooperating with Claude - AI agent of Anthropic.
The agent decision was taken after seeing the company's stance against the massive use of AI for what's somehow called security but has been correctly defined as mass surveillance. I believe that the company's courage in questioning the military use of AI in the most controversial areas should be recognized, despite the other company's  implications. The CEO's statement is available at https://www.anthropic.com/news/statement-department-of-war*
> There was no vibe-coding behind it but a slow and steady reading of papers and docs to understand the logic of libraries and protocols involved. <br>
> The agent has been used to produce a first GUI schema and, in general, for the most lengthy sections. <br>
> The entire code has been (and will be) checked and revised. <br>
> No gray area o spaghetti code will be left (and if so, it will be caused only by my code skill-issue problem)
