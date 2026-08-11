
# Rocket Spoof

A Linux/Windows CLI tool that changes the display name Rocket League shows for you, without modifying or injecting into the game itself. It works by intercepting your own network traffic to Epic/Psyonix's servers with [mitmproxy](https://mitmproxy.org/) and rewriting your `displayName` in the responses before they reach the game. Respect to claude for most of this. I did test this myself and test it works so like 6/10 vibecode sesh

This is a from-scratch Linux-compatible reimplementation of the traffic-interception approach used by tools like RL-Spoofer[https://github.com/Kakapo-Labs/RL-Spoofer-GUI], stripped down to just the proxy logic (no GUI, no OS-specific tray/startup dependencies).

## How it works

1. Rocket League fetches your account data from Epic's servers early in the login flow, including a JSON blob with your `displayName`.
2. This tool runs a local [mitmproxy](https://mitmproxy.org/) instance that watches for that specific response and rewrites `displayName` before it reaches the game.
3. Rocket League caches that value for the session, so your spoofed name sticks once it's been intercepted once.

## Dependencies

### Python
- Python 3.9+

### Python packages
```bash
pip install mitmproxy
```
(On Linux, if you hit an "externally managed environment" error: `pip install mitmproxy --break-system-packages`)

That's the only pip dependency. Everything else is Python standard library.

### System packages

**Linux — manual mode (no auto-proxy):** nothing beyond `mitmproxy` itself.

**Linux — auto-proxy mode:** also needs `nftables` and `pgrep`, both of which are standard on most distros already.

| Distro | Install command |
|---|---|
| Arch | `sudo pacman -S nftables procps-ng` |
| Debian/Ubuntu | `sudo apt install nftables procps` |
| Fedora | `sudo dnf install nftables procps-ng` |

**Windows:** just `pip install mitmproxy`. No extra system packages needed — auto-proxy uses Windows' built-in registry APIs via the Python standard library.

## Usage

```bash
python3 rl_name_spoof.py
```

The script is fully interactive — it'll prompt you for:
- **Name to spoof to**
- **Auto-proxy** (yes/no) — automatically routes Rocket League's traffic through the proxy without you toggling anything manually
- **Debug mode** (yes/no) — verbose logging of every request/response, not just spoofed ones
- Once it's running, open rocket league and **if you get a failed to connect to EOS error simply disable the proxy and reconnect. You will keep your spoofed name but be able to use EOS.** I can probably fix it somehow but idk how yet

### Auto-proxy mode

**Linux:** requires root, since it needs to create a dedicated unprivileged system user (`rlspoof-mitm`) for mitmproxy to run as, and manage `nftables` rules for transparent traffic redirection.
```bash
sudo python3 rl_name_spoof.py
```
It watches for a running `RocketLeague` process and enables/disables the redirect automatically around it.

**Windows:** just run normally — it toggles the system proxy setting via the registry automatically around `RocketLeague.exe`.
```powershell
python rl_name_spoof.py
```

### Manual mode

If you'd rather not grant root/admin, answer "no" to auto-proxy. You'll need to route Rocket League's traffic to `127.0.0.1:8080` yourself and time it around the game's launch — the tool will print the address to use.

## First-time certificate setup

The first time you run this, mitmproxy generates a CA certificate you'll need to trust so it can intercept HTTPS traffic. The script prints the exact path and OS-appropriate trust command after its first run — follow what it prints, since the path differs depending on whether you're using auto-proxy mode (it uses a separate cert store for the dedicated proxy user) or manual mode.

## Known limitations

- **Certificate pinning:** some Epic Online Services (EOS) authentication endpoints appear to use certificate pinning and will reject mitmproxy's certificate, showing `unknown ca` in the logs. This doesn't affect name spoofing (which happens on a different endpoint), but it might mean you aren't able to connect to EOS. **To fix this simply turn off the proxy once you are in the game and reconnect to it normally. You will keep your spoofed name.**
- **Launcher login traffic:** if you use Heroic Games Launcher or anything which uses legendary, routing its login traffic through the proxy can break login with an SSL error, since some launchers use their own bundled certificate store rather than the system's. Auto-proxy mode times around this by only enabling the redirect once rocket league is running, avoiding the launcher problems

