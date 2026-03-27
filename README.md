# SDN_firewall
Basic SDN Firewall implemented with Ryu and tested with Mininet. Local-only web page as Network Switch Controller GUI.


## Installation & Usage
> Tested on Acer with i5-10210U, 16GB RAM, 512GB SSD — Ubuntu 24.04.3 LTS, kernel 6.17.0-14-generic

### Install & Run
```bash
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt-get install -y git python3.10 python3.10-venv python3-distutils python3.10-dev python3-pip python-is-python3 xterm # main prerequisites to use the libraries (xterm just for mininet external terminals, pythonispython3 just cause I tend to forget the 3 at the end)
git clone https://github.com/GioeleSe/SDN_firewall/
cd SDN_firewall
source .venv/bin/activate
python main.py
# on a split terminal start mininet with the command
sudo mn --controller remote # remote controller option to be able to connect it with the python-exposed controller at default port
```

### Uninstall
```bash
Ctrl+C  # to stop the (foreground) process of the server (and the mininet on the other terminal)
deactivate # exit from the python virtual environment
cd .. && sudo rm -rf SDN_firewall # just delete the directory
```

---
*The development was done cooperating with Claude - AI agent of Anthropic.
The agent decision was taken after seeing the company's stance against the massive use of AI for what's somehow called security but has been correctly defined as mass surveillance. I believe that the company's courage in questioning the military use of AI in the most controversial areas should be recognized, despite the other company's  implications. The CEO's statement is available at https://www.anthropic.com/news/statement-department-of-war*
> There was no vibe-coding behind it but a slow and steady reading of papers and docs to understand the logic of libraries and protocols involved. <br>
> The agent has been used to produce a first GUI schema and, in general, for the most lengthy sections. <br>
> The entire code has been (and will be) checked and revised. <br>
> No gray area o spaghetti code will be left (and if so, it will be caused only by my code skill-issue problem)
