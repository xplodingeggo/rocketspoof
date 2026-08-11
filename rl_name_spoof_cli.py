#!/usr/bin/env python3
"""
rl_name_spoof_cli.py
---------------------
Linux CLI port of the Bakkboard-style Rocket League display-name spoofer.

This keeps ONLY the actual spoofing mechanism from the original Windows
tool: an mitmproxy addon that watches HTTP responses from Epic/Psyonix
domains, finds the JSON blob containing your account's displayName, and
rewrites it before it reaches Rocket League. All of the Windows-only GUI
chrome (tkinter, pystray, cv2 splash video, winreg, Task Scheduler
startup entries) has been stripped out — none of it was part of the
actual spoofing logic.

Usage:
    python3 rl_name_spoof_cli.py                  # prompts for a name
    python3 rl_name_spoof_cli.py --name "New Name"
    python3 rl_name_spoof_cli.py --name "New Name" --port 8080
    python3 rl_name_spoof_cli.py --check-cert-only

Setup you still need to do yourself (see --help / README below):
    1. Install mitmproxy's CA cert into your system/browser trust store.
    2. Point Rocket League's traffic at this proxy (system-wide proxy
       settings, or a launch wrapper / network namespace, since RL has
       no built-in proxy option).
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
RL_PROCESS_NAME = "RocketLeague.exe"

try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
except ImportError:
    print("ERROR: mitmproxy is not installed.", file=sys.stderr)
    print("Install it with:  pip install mitmproxy --break-system-packages", file=sys.stderr)
    sys.exit(1)

import asyncio

TARGET_DOMAINS = ["epicgames.dev", "epicgames.com", "psyonix.com", "live.psynet.gg"]
REQUIRED_KEYS = ["accountId", "displayName", "preferredLanguage", "linkedAccounts", "cabinedMode"]
MAX_NAME_LENGTH = 32

MITM_CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

# Common Linux system trust store locations where the cert would need to be
# copied/symlinked (with a .crt extension) and then registered via
# update-ca-certificates / update-ca-trust.
LINUX_TRUST_STORE_HINTS = [
    ("Debian/Ubuntu", "/usr/local/share/ca-certificates/", "sudo update-ca-certificates"),
    ("Fedora/RHEL", "/etc/pki/ca-trust/source/anchors/", "sudo update-ca-trust"),
    ("Arch", "/etc/ca-certificates/trust-source/anchors/", "sudo trust extract-compare"),
]


def log(msg: str, level: str = "DEBUG") -> None:
    """Simple leveled stdout logger, mirroring the original tool's log style."""
    print(f"[{level}] {msg}", flush=True)


def check_cert_status() -> bool:
    """
    Best-effort check for whether the mitmproxy CA cert exists at all.
    Linux doesn't have one universal 'is this cert trusted' query the
    way Windows PowerShell's cert store cmdlets do, so this only confirms
    the cert file has been generated (i.e. mitmproxy has run at least
    once) — it does NOT confirm it has been installed into a trust store.
    """
    log("Checking for mitmproxy CA certificate...")
    if MITM_CA_CERT.exists():
        log(f"Found generated CA cert at {MITM_CA_CERT}")
        log("NOTE: this only confirms the cert was generated, not that it's")
        log("      trusted system-wide. See setup instructions with --help.")
        return True
    else:
        log(f"No CA cert found at {MITM_CA_CERT}", level="WARN")
        log("It will be auto-generated the first time this script runs the proxy.")
        log("You'll still need to install it into your trust store afterward.")
        return False


def print_setup_instructions(port: int) -> None:
    print("\n--- One-time Linux setup ---")
    print(f"1. Run this script once so mitmproxy generates its CA cert at:")
    print(f"     {MITM_CA_CERT}")
    print("2. Install that cert into your system trust store, e.g.:")
    for name, path, cmd in LINUX_TRUST_STORE_HINTS:
        print(f"     [{name}] sudo cp {MITM_CA_CERT} {path}mitmproxy-ca-cert.crt && {cmd}")
    print("   (Steam is often bundled/sandboxed differently — if RL still shows")
    print("    TLS errors after this, you may need to trust the cert inside")
    print("    whatever runtime/Proton prefix or container RL's network stack uses.)")
    print(f"3. Point Rocket League's traffic at 127.0.0.1:{port}. RL has no")
    print("   built-in proxy setting, so this normally means setting your OS-wide")
    print("   or network-manager HTTP(S) proxy while RL is running, or routing")
    print("   just RL's process through the proxy via a network namespace / iptables")
    print("   redirect — same constraint the original Windows tool had.")
    print("4. Launch Rocket League, then run this script with --name.\n")


def is_rl_running() -> bool:
    """Check if RocketLeague.exe is currently running (Windows only)."""
    if not IS_WINDOWS:
        return False
    import subprocess
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {RL_PROCESS_NAME}"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return RL_PROCESS_NAME.lower() in result.stdout.lower()
    except Exception:
        return False


def set_windows_system_proxy(enabled: bool, host: str, port: int) -> bool:
    """Toggle the Windows system proxy setting (the same one you were flipping
    manually in Settings > Proxy). Returns True on success."""
    if not IS_WINDOWS:
        return False
    import winreg
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
            if enabled:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        # Notify the system that settings changed so apps/launcher pick it up
        # without needing a reboot or manual toggle.
        import ctypes
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        return True
    except Exception as e:
        log(f"Failed to set Windows system proxy: {e}", level="ERROR")
        return False


def auto_manage_windows_proxy(host: str, port: int, stop_flag: dict) -> None:
    """
    Background loop: waits for RocketLeague.exe to appear, then enables the
    system proxy (mirroring what you were doing by hand). Disables it again
    once the game closes, so Heroic/Epic login traffic isn't broken.
    """
    was_running = False
    log("Auto-proxy: watching for RocketLeague.exe ...")
    while not stop_flag.get("stop"):
        running = is_rl_running()
        if running and not was_running:
            log("Auto-proxy: RocketLeague.exe detected, enabling system proxy.")
            set_windows_system_proxy(True, host, port)
        elif not running and was_running:
            log("Auto-proxy: RocketLeague.exe closed, disabling system proxy.")
            set_windows_system_proxy(False, host, port)
        was_running = running
        time.sleep(1)
    if was_running:
        log("Auto-proxy: exiting, disabling system proxy.")
        set_windows_system_proxy(False, host, port)


class NameSpoofAddon:
    """Unmodified spoofing logic — only the print() calls changed to use log()."""

    def __init__(self, new_name: str):
        self.new_name = new_name
        log(f"Addon initialized: Preparing to spoof display names to '{self.new_name}'.")

    def update_name(self, new_name: str) -> None:
        old_name = self.new_name
        self.new_name = new_name
        log(f"Updated spoof name from '{old_name}' to '{self.new_name}'.")

    def request(self, flow: http.HTTPFlow):
        if any(domain in flow.request.pretty_host for domain in TARGET_DOMAINS):
            log(f"-> {flow.request.method} {flow.request.pretty_host}{flow.request.path}")

    def response(self, flow: http.HTTPFlow):
        target = any(domain in flow.request.pretty_host for domain in TARGET_DOMAINS)
        content_type = flow.response.headers.get("Content-Type", "")
        if target and "application/json" in content_type:
            log(f"<- {flow.response.status_code} {flow.request.pretty_host}{flow.request.path} (json, inspecting)")
            self._process_json_body(flow)
        elif target:
            log(f"<- {flow.response.status_code} {flow.request.pretty_host}{flow.request.path} "
                f"(content-type '{content_type}', skipping)")

    def _process_json_body(self, flow: http.HTTPFlow) -> None:
        message = flow.response
        try:
            body_data = message.json()
        except json.JSONDecodeError:
            log("Response body was not valid JSON, skipping.", level="WARN")
            return

        spoofed = False
        if isinstance(body_data, list) and len(body_data) == 1 and isinstance(body_data[0], dict):
            user_data = body_data[0]
            if all(key in user_data for key in REQUIRED_KEYS):
                if isinstance(user_data.get("linkedAccounts"), list) and isinstance(user_data.get("cabinedMode"), bool):
                    if user_data["displayName"] != self.new_name:
                        log(f"Identified user data response for accountId={user_data.get('accountId')}.")
                        log(f"Spoofing displayName: '{user_data['displayName']}' -> '{self.new_name}'")
                        user_data["displayName"] = self.new_name
                        spoofed = True
                    else:
                        log("displayName already matches spoof target, nothing to do.")
                else:
                    log("JSON shape partially matched but 'linkedAccounts'/'cabinedMode' "
                        "types were wrong. Skipping.", level="WARN")
            else:
                log("JSON did not match expected user-data shape. Skipping.")
        else:
            log("Response JSON was not a single-object list. Skipping.")

        if spoofed:
            message.content = json.dumps(body_data, ensure_ascii=False).encode("utf-8")
            if "Content-Length" in message.headers:
                message.headers["Content-Length"] = str(len(message.content))
            log(f"*** Name spoofing applied to {flow.request.url} ***", level="INFO")


async def run_proxy(new_name: str, host: str, port: int) -> None:
    import socket
    # Fail fast with a clear message if the port is already taken, instead
    # of letting mitmproxy's own vague "Error logged during startup" message
    # be the only thing printed.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    in_use = probe.connect_ex((host, port)) == 0
    probe.close()
    if in_use:
        log(f"Port {port} on {host} is already in use by another process.", level="ERROR")
        log(f"Pick a different port with --port, e.g. --port {port + 1}", level="ERROR")
        return

    options = Options(listen_host=host, listen_port=port, mode=["regular"])
    master = DumpMaster(options, with_termlog=False)
    addon = NameSpoofAddon(new_name)
    master.addons.add(addon)
    master.options.block_global = False

    log(f"Starting proxy on {host}:{port} ...")
    log("Waiting for traffic from: " + ", ".join(TARGET_DOMAINS))
    log("Press Ctrl+C to stop.")

    try:
        await master.run()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        import traceback
        log(f"Proxy crashed during startup/run: {e}", level="ERROR")
        traceback.print_exc()
    finally:
        master.shutdown()
        log("Proxy stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rocket League display-name spoofer (Linux CLI)")
    parser.add_argument("--name", help="Name to spoof to. If omitted, you'll be prompted.")
    parser.add_argument("--host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Proxy listen port (default: 8080)")
    parser.add_argument("--check-cert-only", action="store_true",
                         help="Just check/report CA cert status and print setup steps, then exit.")
    parser.add_argument("--auto-proxy", action="store_true",
                         help="Windows only: automatically enable the system proxy once "
                              "RocketLeague.exe starts, and disable it when the game closes, "
                              "so launcher login traffic (Heroic/Epic) isn't broken.")
    args = parser.parse_args()

    if args.auto_proxy and not IS_WINDOWS:
        log("--auto-proxy is only supported on Windows (uses the registry proxy setting).",
            level="ERROR")
        sys.exit(1)

    if args.check_cert_only:
        check_cert_status()
        print_setup_instructions(args.port)
        return

    new_name = args.name
    if not new_name:
        new_name = input("Enter the name to spoof to: ").strip()
    if not new_name:
        log("No name provided, exiting.", level="ERROR")
        sys.exit(1)
    if len(new_name) > MAX_NAME_LENGTH:
        log(f"Name too long ({len(new_name)} > {MAX_NAME_LENGTH}), truncating.", level="WARN")
        new_name = new_name[:MAX_NAME_LENGTH]

    check_cert_status()
    print_setup_instructions(args.port)

    stop_flag = {"stop": False}
    proxy_thread = None
    if args.auto_proxy:
        from threading import Thread
        proxy_thread = Thread(target=auto_manage_windows_proxy,
                               args=(args.host, args.port, stop_flag), daemon=True)
        proxy_thread.start()

    try:
        asyncio.run(run_proxy(new_name, args.host, args.port))
    except KeyboardInterrupt:
        log("Interrupted by user, shutting down.")
    finally:
        if proxy_thread:
            stop_flag["stop"] = True
            proxy_thread.join(timeout=3)


if __name__ == "__main__":
    main()
