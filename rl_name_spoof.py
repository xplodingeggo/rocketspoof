#!/usr/bin/env python3
"""
rl_name_spoof.py
-----------------
Interactive Rocket League display-name spoofer.

Same core mechanism as before: an mitmproxy addon watches HTTP responses
from Epic/Psyonix domains and rewrites your displayName before it reaches
Rocket League.

What's different from rl_name_spoof_cli.py:
  - Fully interactive: prompts for name / auto-proxy / debug mode instead
    of CLI flags.
  - Linux auto-proxy is now a REAL implementation instead of gsettings
    (which doesn't work — RL doesn't consult GNOME desktop settings).
    It uses nftables transparent redirection + a dedicated unprivileged
    system user for mitmproxy, so mitmproxy's own outbound connections
    don't get redirected back into themselves (the classic transparent-
    proxy loop problem), while Rocket League's traffic (running as your
    normal user) does get redirected.
  - Windows auto-proxy is unchanged (registry-based, already worked).

Linux auto-proxy REQUIRES root (sudo) because it needs to:
  - create/use a dedicated system user for mitmproxy to run as
  - add/remove nftables rules

If you don't want to grant root, just answer "no" to auto-proxy and do
the manual toggle instead (same as before: proxy off during launcher
login, on once Rocket League/EAC takes over) — except manual toggling
on Linux ALSO needs an OS-level redirect method (there's no single
system-wide "proxy setting" on Linux the way Windows has one), so even
manual mode here uses nftables — it just does the add/remove itself
around Enter-key prompts instead of automatically around the process.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

TARGET_DOMAIN = "api.epicgames.dev"  # the one domain that actually serves displayName
REQUIRED_KEYS = ["accountId", "displayName", "preferredLanguage", "linkedAccounts", "cabinedMode"]
MAX_NAME_LENGTH = 32

MITM_CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
NFT_TABLE_NAME = "rl_spoof"          # our own isolated nftables table, easy cleanup
PROXY_USER = "rlspoof-mitm"          # dedicated unprivileged user mitmproxy runs as
DEBUG_MODE = False                   # toggled by prompt in main()


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def log(msg: str, level: str = "DEBUG") -> None:
    if level == "DEBUG" and not DEBUG_MODE:
        return
    print(f"[{level}] {msg}", flush=True)


def prompt_yes_no(question: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    ans = input(question + suffix).strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


# --------------------------------------------------------------------------
# Cert check (same as before)
# --------------------------------------------------------------------------

def check_cert_status(cert_path: Path) -> bool:
    log("Checking for mitmproxy CA certificate...", level="INFO")
    if cert_path.exists():
        log(f"Found generated CA cert at {cert_path}", level="INFO")
        return True
    log(f"No CA cert found at {cert_path}", level="WARN")
    log("It will be generated the first time the proxy runs.", level="WARN")
    log("You'll need to trust it afterward (instructions printed at the end).", level="WARN")
    return False


def print_cert_setup_instructions(port: int, cert_path: Path) -> None:
    print("\n--- Certificate setup (one-time) ---")
    print(f"1. After this script has run once, install the CA cert into your trust store:")
    if IS_LINUX:
        print(f"     [Arch]           sudo trust anchor --store {cert_path}")
        print(f"     [Debian/Ubuntu]  sudo cp {cert_path} /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt && sudo update-ca-certificates")
        print(f"     [Fedora/RHEL]    sudo cp {cert_path} /etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.crt && sudo update-ca-trust")
    elif IS_WINDOWS:
        print(f'     certutil -addstore -f "ROOT" "{cert_path}"   (run as Administrator)')
    print("2. Apps with their own bundled cert store (Heroic/legendary's Python 'certifi',")
    print("   Electron shells, some game launchers) may NOT read your system trust store —")
    print("   this is why launcher login can fail even after step 1. That's expected and")
    print("   is what auto-proxy timing (or manual toggling) works around.\n")


# --------------------------------------------------------------------------
# Dependency checks
# --------------------------------------------------------------------------

def check_dependencies(auto_proxy: bool) -> bool:
    """Returns True if everything needed is present, False if the caller
    should abort or fall back."""
    ok = True

    if shutil.which("mitmdump") is None:
        log("mitmdump (from the mitmproxy package) not found on PATH.", level="ERROR")
        log("Install it with: pip install mitmproxy --break-system-packages", level="ERROR")
        ok = False

    if auto_proxy and IS_LINUX:
        if shutil.which("nft") is None:
            log("nft (nftables) not found on PATH.", level="ERROR")
            log("Install it with: sudo pacman -S nftables", level="ERROR")
            ok = False
        if os.geteuid() != 0:
            log("Auto-proxy on Linux needs root (nftables rules + a dedicated user).", level="ERROR")
            log("Re-run this script with: sudo python3 rl_name_spoof.py", level="ERROR")
            ok = False

    return ok


# --------------------------------------------------------------------------
# Linux: dedicated unprivileged user for mitmproxy
# --------------------------------------------------------------------------

# Dedicated confdir for the unprivileged mitmproxy user — deliberately NOT
# nested under /root, since /root itself is 0700 and would block traversal
# by any other user regardless of the subdirectory's own permissions.
PROXY_CONFDIR = Path("/var/lib") / PROXY_USER


def ensure_proxy_user_exists() -> Path | None:
    """Creates the dedicated user (if needed) and its confdir. Returns the
    confdir path on success, None on failure."""
    result = subprocess.run(["id", "-u", PROXY_USER], capture_output=True, text=True)
    if result.returncode == 0:
        log(f"System user '{PROXY_USER}' already exists.")
    else:
        log(f"Creating dedicated system user '{PROXY_USER}' (mitmproxy runs as this user "
            f"so its own traffic can be excluded from redirection)...", level="INFO")
        try:
            subprocess.run(
                ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", PROXY_USER],
                check=True, capture_output=True, text=True
            )
            log(f"Created user '{PROXY_USER}'.")
        except subprocess.CalledProcessError as e:
            log(f"Failed to create user '{PROXY_USER}': {e.stderr}", level="ERROR")
            return None

    # Give mitmproxy its own cert/confdir outside of /root, owned by the
    # dedicated user, so nothing above it in the path tree blocks traversal.
    try:
        proxy_uid = int(subprocess.run(["id", "-u", PROXY_USER], capture_output=True, text=True, check=True).stdout.strip())
        PROXY_CONFDIR.mkdir(parents=True, exist_ok=True)
        os.chown(PROXY_CONFDIR, proxy_uid, -1)  # -1 leaves group unchanged
        PROXY_CONFDIR.chmod(0o700)  # only the proxy user needs access
        log(f"mitmproxy confdir ready at {PROXY_CONFDIR}, owned by '{PROXY_USER}'.")
        return PROXY_CONFDIR
    except Exception as e:
        log(f"Failed to set up {PROXY_CONFDIR}: {e}", level="ERROR")
        return None


def get_proxy_uid() -> int | None:
    result = subprocess.run(["id", "-u", PROXY_USER], capture_output=True, text=True)
    if result.returncode == 0:
        return int(result.stdout.strip())
    return None


# --------------------------------------------------------------------------
# Linux: nftables transparent redirect (isolated table, easy cleanup)
# --------------------------------------------------------------------------

def resolve_target_ips(domain: str) -> list[str]:
    """
    Resolve every A record for the target domain so we can scope the
    nftables redirect to ONLY those IPs, instead of all outbound 443
    traffic. This is what lets everything else (pinned auth endpoints,
    telemetry, etc.) go direct and untouched automatically, with no
    timing games or exclusion lists needed.
    """
    import socket
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        log(f"Resolved {domain} -> {', '.join(ips)}", level="INFO")
        return ips
    except socket.gaierror as e:
        log(f"Failed to resolve {domain}: {e}", level="ERROR")
        return []


def nft_rules_up(port: int, proxy_uid: int, target_ips: list[str]) -> bool:
    """
    Creates our own nftables table (kept separate from any of your existing
    rules) with:
      - an exclusion for traffic whose *socket owner* is the dedicated
        mitmproxy user (so mitmproxy's own outbound connections to the
        same target IPs aren't redirected back into itself)
      - a redirect of outbound TCP 443 traffic, but ONLY to target_ips
        (the resolved IPs for the one domain we actually need to
        intercept) — everything else, including pinned auth endpoints,
        is never touched by this rule at all.
    """
    if not target_ips:
        log("No target IPs to redirect — refusing to set up an empty rule.", level="ERROR")
        return False

    ip_set = ", ".join(target_ips)
    script = textwrap.dedent(f"""
        table ip {NFT_TABLE_NAME} {{
            chain output {{
                type nat hook output priority 0;
                meta skuid {proxy_uid} return
                ip daddr {{ {ip_set} }} tcp dport 443 redirect to :{port}
            }}
        }}
    """).strip()

    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False)
    try:
        tmp.write(script)
        tmp.close()
        result = subprocess.run(["nft", "-f", tmp.name], capture_output=True, text=True)
        if result.returncode != 0:
            log(f"nft rule setup failed: {result.stderr.strip()}", level="ERROR")
            return False
        log(f"nftables: redirecting outbound TCP 443 -> 127.0.0.1:{port}, scoped to "
            f"{ip_set} only (excluding uid {proxy_uid}).", level="INFO")
        return True
    finally:
        os.unlink(tmp.name)


def nft_rules_down() -> None:
    result = subprocess.run(["nft", "delete", "table", "ip", NFT_TABLE_NAME],
                             capture_output=True, text=True)
    if result.returncode == 0:
        log("nftables: redirect rules removed.", level="INFO")
    else:
        # Not fatal — table may not have existed if setup never ran/succeeded.
        log(f"nftables: cleanup returned: {result.stderr.strip()}", level="DEBUG")


def is_rl_running_linux() -> bool:
    result = subprocess.run(["pgrep", "-if", "rocketleague"], capture_output=True, text=True)
    return result.returncode == 0 and bool(result.stdout.strip())


# --------------------------------------------------------------------------
# Windows: registry proxy toggle (unchanged behavior from before)
# --------------------------------------------------------------------------

def is_rl_running_windows() -> bool:
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq RocketLeague.exe"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return "rocketleague.exe" in result.stdout.lower()
    except Exception:
        return False


def set_windows_system_proxy(enabled: bool, host: str, port: int) -> bool:
    import winreg
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
            if enabled:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        import ctypes
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
        return True
    except Exception as e:
        log(f"Failed to set Windows system proxy: {e}", level="ERROR")
        return False


# --------------------------------------------------------------------------
# Auto-proxy watcher threads
# --------------------------------------------------------------------------

def auto_manage_windows_proxy(host: str, port: int, stop_flag: dict) -> None:
    was_running = False
    log("Auto-proxy: watching for RocketLeague.exe ...", level="INFO")
    while not stop_flag.get("stop"):
        running = is_rl_running_windows()
        if running and not was_running:
            log("Auto-proxy: RocketLeague.exe detected, enabling system proxy.", level="INFO")
            set_windows_system_proxy(True, host, port)
        elif not running and was_running:
            log("Auto-proxy: RocketLeague.exe closed, disabling system proxy.", level="INFO")
            set_windows_system_proxy(False, host, port)
        was_running = running
        time.sleep(1)
    if was_running:
        set_windows_system_proxy(False, host, port)


def auto_manage_linux_proxy(port: int, proxy_uid: int, stop_flag: dict) -> None:
    was_running = False
    log("Auto-proxy: watching for a RocketLeague process (pgrep -f rocketleague) ...", level="INFO")
    while not stop_flag.get("stop"):
        running = is_rl_running_linux()
        if running and not was_running:
            log("Auto-proxy: RocketLeague process detected, enabling nftables redirect.", level="INFO")
            target_ips = resolve_target_ips(TARGET_DOMAIN)
            nft_rules_up(port, proxy_uid, target_ips)
        elif not running and was_running:
            log("Auto-proxy: RocketLeague process ended, removing nftables redirect.", level="INFO")
            nft_rules_down()
        was_running = running
        time.sleep(1)
    if was_running:
        nft_rules_down()


# --------------------------------------------------------------------------
# The addon itself — written to a temp file so mitmdump can load it as a
# subprocess (needed so it can run as the dedicated unprivileged user on
# Linux via `user=` in subprocess.Popen; on Windows it's just run normally).
# --------------------------------------------------------------------------

ADDON_TEMPLATE = '''
import json
from mitmproxy import http

TARGET_DOMAIN = {target_domain!r}
REQUIRED_KEYS = {required_keys!r}
NEW_NAME = {new_name!r}

class NameSpoofAddon:
    def request(self, flow: http.HTTPFlow):
        if TARGET_DOMAIN in flow.request.pretty_host:
            print(f"-> {{flow.request.method}} {{flow.request.pretty_host}}{{flow.request.path}}", flush=True)

    def response(self, flow: http.HTTPFlow):
        target = TARGET_DOMAIN in flow.request.pretty_host
        content_type = flow.response.headers.get("Content-Type", "")
        if target and "application/json" in content_type:
            print(f"<- {{flow.response.status_code}} {{flow.request.pretty_host}}{{flow.request.path}} (json)", flush=True)
            self._process(flow)
        elif target:
            print(f"<- {{flow.response.status_code}} {{flow.request.pretty_host}}{{flow.request.path}} (skip, not json)", flush=True)

    def _process(self, flow):
        try:
            body = flow.response.json()
        except json.JSONDecodeError:
            print("Response body was not valid JSON, skipping.", flush=True)
            return
        if isinstance(body, list) and len(body) == 1 and isinstance(body[0], dict):
            user_data = body[0]
            if all(k in user_data for k in REQUIRED_KEYS):
                if isinstance(user_data.get("linkedAccounts"), list) and isinstance(user_data.get("cabinedMode"), bool):
                    if user_data["displayName"] != NEW_NAME:
                        print(f"*** Spoofing displayName: '{{user_data['displayName']}}' -> '{{NEW_NAME}}' ***", flush=True)
                        user_data["displayName"] = NEW_NAME
                        flow.response.content = json.dumps(body, ensure_ascii=False).encode("utf-8")
                        if "Content-Length" in flow.response.headers:
                            flow.response.headers["Content-Length"] = str(len(flow.response.content))
                    else:
                        print("displayName already matches, nothing to do.", flush=True)
                else:
                    print("Shape matched but linkedAccounts/cabinedMode types wrong, skipping.", flush=True)
            else:
                print("JSON didn't match expected user-data shape, skipping.", flush=True)
        else:
            print("Response JSON wasn't a single-object list, skipping.", flush=True)

addons = [NameSpoofAddon()]
'''


def write_addon_file(new_name: str) -> Path:
    content = ADDON_TEMPLATE.format(
        target_domain=TARGET_DOMAIN,
        required_keys=REQUIRED_KEYS,
        new_name=new_name,
    )
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix="_rl_addon.py", delete=False)
    tmp.write(content)
    tmp.close()
    addon_path = Path(tmp.name)
    # Make readable by the unprivileged mitmproxy user (rlspoof-mitm on Linux).
    addon_path.chmod(0o644)
    return addon_path


def stream_subprocess_output(proc: subprocess.Popen) -> None:
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            log(line, level="PROXY")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    global DEBUG_MODE

    print("=== Rocket League Name Spoofer ===\n")

    new_name = input("Enter the name to spoof to: ").strip()
    if not new_name:
        print("No name entered, exiting.")
        sys.exit(1)
    if len(new_name) > MAX_NAME_LENGTH:
        print(f"Name too long, truncating to {MAX_NAME_LENGTH} chars.")
        new_name = new_name[:MAX_NAME_LENGTH]

    auto_proxy = prompt_yes_no("Enable auto-proxy (automatically route Rocket League's "
                                "traffic through the proxy without you toggling anything)?",
                                default=True)
    DEBUG_MODE = prompt_yes_no("Enable debug mode (verbose logging, including every "
                                "request/response, not just spoofed ones)?", default=False)

    print()

    if not check_dependencies(auto_proxy):
        print("\nFix the issues above and re-run.")
        sys.exit(1)

    port = 8080
    proxy_uid = None
    confdir = None

    if auto_proxy and IS_LINUX:
        confdir = ensure_proxy_user_exists()
        if confdir is None:
            sys.exit(1)
        proxy_uid = get_proxy_uid()
        if proxy_uid is None:
            log(f"Could not resolve uid for '{PROXY_USER}'.", level="ERROR")
            sys.exit(1)
        cert_path = confdir / "mitmproxy-ca-cert.pem"
    else:
        cert_path = MITM_CA_CERT

    check_cert_status(cert_path)
    print_cert_setup_instructions(port, cert_path)

    if not auto_proxy:
        print("--- Manual mode ---")
        if IS_LINUX:
            print(f"You'll need to route Rocket League's traffic to 127.0.0.1:{port} yourself.")
            print("There's no single system-wide proxy setting on Linux the way Windows has one.")
            print("If you want this automated, re-run and answer yes to auto-proxy.\n")
        else:
            print(f"Toggle your OS proxy to 127.0.0.1:{port}, timed around Rocket League's launch,")
            print("same as before.\n")

    # Write the addon out so mitmdump can load it as a subprocess.
    addon_path = write_addon_file(new_name)
    log(f"Addon written to {addon_path}")

    mitm_cmd = ["mitmdump", "-s", str(addon_path), "--listen-port", str(port)]
    if auto_proxy and IS_LINUX:
        mitm_cmd = ["mitmdump", "-s", str(addon_path), "--mode", "transparent",
                    "--listen-port", str(port), "--set", f"confdir={confdir}"]

    popen_kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    if auto_proxy and IS_LINUX:
        # Run mitmdump as the dedicated unprivileged user so its own outbound
        # connections are excluded from the nftables redirect (Python 3.9+).
        popen_kwargs["user"] = PROXY_USER

    log(f"Starting: {' '.join(mitm_cmd)}", level="INFO")
    try:
        proc = subprocess.Popen(mitm_cmd, **popen_kwargs)
    except FileNotFoundError:
        log("mitmdump not found — is mitmproxy installed and on PATH?", level="ERROR")
        sys.exit(1)

    stop_flag = {"stop": False}
    watcher_thread = None
    if auto_proxy:
        from threading import Thread
        if IS_WINDOWS:
            watcher_thread = Thread(target=auto_manage_windows_proxy,
                                     args=("127.0.0.1", port, stop_flag), daemon=True)
        else:
            watcher_thread = Thread(target=auto_manage_linux_proxy,
                                     args=(port, proxy_uid, stop_flag), daemon=True)
        watcher_thread.start()

    log("Press Ctrl+C to stop.", level="INFO")
    try:
        stream_subprocess_output(proc)
    except KeyboardInterrupt:
        log("Interrupted, shutting down.", level="INFO")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        if watcher_thread:
            stop_flag["stop"] = True
            watcher_thread.join(timeout=3)
        if auto_proxy and IS_LINUX:
            nft_rules_down()
        try:
            addon_path.unlink()
        except OSError:
            pass
        log("Stopped.", level="INFO")


if __name__ == "__main__":
    main()
