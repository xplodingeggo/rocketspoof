
# Rocket Spoof

A Linux/Windows CLI tool that changes the display name Rocket League shows for you, without modifying or injecting into the game itself. It works by intercepting your own network traffic to Epic/Psyonix's servers with [mitmproxy](https://mitmproxy.org/) and rewriting your `displayName` in the responses before they reach the game. Respect to claude for most of this.

This is a linux-compatible version of the traffic-interception approach used by tools like RL-Spoofer[https://github.com/Kakapo-Labs/RL-Spoofer-GUI], with just a CLI instead of a gui which can break across different distros/platforms

# Usage and installation
you will need:
   * Python 3.9+
   *  mitmproxy
Do ```pip install mitmproxy```
(On Linux, if you hit an "externally managed environment" error: ```pip install mitmproxy --break-system-packages```)

That's the only pip dependency. Everything else is Python standard library.
Then do sudo python3 rl_name_spoof.py (or whatever the name of file is)
it will give you setup instructions for your distro and you just paste the thing in another terminal to install the certificates and its a one time thing
It will prompt you for the name you want and whether to enable debug mode and stuff. just make sure you say yes to auto proxy

# Systemd service setup
This makes it so you dont need to run the script every time you want your name to be spoofed and its done automatically. Only works if your pc uses systemd services. The name of the service is `rl-name-spoof`
* Place rl-name-spoof into /opt/rl-name-spoof (create the directory)
* create a config file called rl-name-spoof.conf in /etc/
* put something like this in it (replace the name to what you want)
```conf
NAME=FortniteKing69420.
AUTO_PROXY=true
DEBUG=false
