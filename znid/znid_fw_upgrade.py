#!/usr/bin/env python3
"""Upgrade the firmware of a ZNID-24xxA1 ONT through its web GUI (System > Software Update).

Standalone single file: only needs Python 3.8+ and ``requests`` (pip install requests).
It does what the GUI page does (micro_httpd, HTTP Basic auth):

  1. reads the running / alternate firmware version (Status > info.html)
  2. POSTs the image as multipart/form-data, field "filename", to upload.cgi
     (exactly the form of upload.html; that form carries no sessionKey)
  3. waits for the ONT to go down (flash + reboot) and come back, then reads the version again

The ONT reboots during the upgrade: the LAN link drops for a few minutes. Do not power it off
while it is flashing.

Examples
  python znid_fw_upgrade.py --info
  python znid_fw_upgrade.py --image ZNID-24xxA1-S4.2.040.img
  python znid_fw_upgrade.py --image ZNID-24xxA1-S4.2.040.img --expect-version S4.2.040 --yes
  python znid_fw_upgrade.py --host 192.168.100.189 --port 28080 --info

Exit code: 0 = ONT back and running the new version (or --info done), 1 = error / image rejected,
2 = upload accepted but the version afterwards is not the expected one (or the ONT did not come
back within --wait seconds).
"""

from __future__ import annotations

import argparse
import os
import re
import ssl
import sys
import time
import warnings

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)  # TLSv1 floor for the ONT's old HTTPS stack

# words of the pages the device answers with when it refuses an image
REJECT = re.compile(r"fail|illegal|invalid|not (a )?valid|error|too (big|large)|incorrect", re.I)


class GuiError(RuntimeError):
    pass


class _LegacyTls(HTTPAdapter):
    """The ONT's HTTPS server only offers RSA key exchange / old TLS: accept it (management only)."""

    def init_poolmanager(self, *a, **k):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.options |= getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0)
        k["ssl_context"] = ctx
        return super().init_poolmanager(*a, **k)


class ZnidGui:
    def __init__(self, host, port=None, scheme="http", user="admin", password="zhone", timeout=15):
        port = int(port) if port else (443 if scheme == "https" else 80)
        default = 443 if scheme == "https" else 80
        self.base = f"{scheme}://{host}" + ("" if port == default else f":{port}")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = False
        self.s.mount("https://", _LegacyTls())

    def get(self, path, timeout=None):
        try:
            r = self.s.get(f"{self.base}/{path}", timeout=timeout or self.timeout)
        except requests.RequestException as e:
            raise GuiError(f"cannot reach {self.base}: {e}") from e
        if r.status_code == 401:
            raise GuiError("login rejected (HTTP 401): check --user / --password "
                           "(too many failures lock the GUI for a while)")
        if r.status_code != 200:
            raise GuiError(f"GET /{path} -> HTTP {r.status_code}")
        return r.text

    def info(self):
        """{label: value} of Status > Device Info (Firmware Version, Alternate Firmware Version, ...)."""
        page = self.get("info.html")
        out = {}
        for label, value in re.findall(r"<td class='hd'>([^<:]+):?</td>\s*<td>([^<]*)</td>", page):
            out.setdefault(label.strip(), value.strip())
        if "Firmware Version" not in out:
            raise GuiError("no 'Firmware Version' on info.html (not a ZNID GUI?)")
        return out

    def upload(self, path, timeout):
        """POST the image to upload.cgi. Returns (accepted, page text)."""
        name = os.path.basename(path)
        with open(path, "rb") as f:
            files = {"filename": (name, f, "application/octet-stream")}
            try:
                r = self.s.post(f"{self.base}/upload.cgi", files=files, timeout=timeout)
            except (requests.ConnectionError, requests.ReadTimeout) as e:
                # the device may cut the connection once it starts flashing / rebooting
                return None, f"(no answer: {e.__class__.__name__})"
        if r.status_code == 401:
            raise GuiError("login rejected (HTTP 401) on upload.cgi")
        text = re.sub(r"<[^>]+>", " ", r.text)
        text = re.sub(r"\s+", " ", text).strip()
        if r.status_code != 200 or REJECT.search(text):
            return False, f"HTTP {r.status_code}: {text[:400]}"
        return True, text[:400]

    def alive(self):
        try:
            self.s.get(f"{self.base}/info.html", timeout=5)
            return True
        except requests.RequestException:
            return False


def wait_back(gui, total):
    """Wait until the GUI goes away (reboot) and answers info.html again. Returns info or None."""
    end = time.time() + total
    went_down = False
    while time.time() < end:
        if not gui.alive():
            if not went_down:
                print("[*] ONT is down (flashing / rebooting) ...")
            went_down = True
        elif went_down:
            try:
                return gui.info()
            except GuiError:
                pass  # web server up but pages not ready yet
        time.sleep(10)
    if not went_down:  # never saw it go down: report what it runs now
        try:
            return gui.info()
        except GuiError:
            return None
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("ONT web GUI")
    g.add_argument("--host", default="192.168.1.1", help="ONT GUI address (default 192.168.1.1)")
    g.add_argument("--port", type=int, help="GUI port (default 80, or 443 with --https)")
    g.add_argument("--https", action="store_true", help="use HTTPS instead of HTTP")
    g.add_argument("--user", default="admin", help="GUI user (default admin)")
    g.add_argument("--password", default="zhone", help="GUI password (default zhone)")
    u = ap.add_argument_group("upgrade")
    u.add_argument("--image", help="firmware image file (.img)")
    u.add_argument("--expect-version", help="version the ONT must run afterwards, e.g. S4.2.040")
    u.add_argument("--wait", type=int, default=600, help="seconds to wait for the ONT to come back (default 600)")
    u.add_argument("--no-wait", action="store_true", help="return right after the upload is accepted")
    u.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    u.add_argument("--info", action="store_true", help="only print the firmware versions and exit")
    args = ap.parse_args(argv)

    gui = ZnidGui(args.host, args.port, "https" if args.https else "http", args.user, args.password)
    try:
        before = gui.info()
        print(f"[*] {gui.base}: model {before.get('Model Number', '?')}, serial {before.get('Serial Number', '?')}")
        print(f"    running   {before['Firmware Version']}")
        print(f"    alternate {before.get('Alternate Firmware Version', '?')}")
        if args.info:
            return 0

        if not args.image:
            raise GuiError("--image is required (or use --info)")
        if not os.path.isfile(args.image):
            raise GuiError(f"image file not found: {args.image}")
        size = os.path.getsize(args.image)
        if size < 1024 * 1024:
            raise GuiError(f"{args.image} is only {size} bytes: not a firmware image")
        if not args.image.lower().endswith(".img"):
            print("[!] the GUI only offers .img files; uploading anyway")
        if args.expect_version and args.expect_version == before["Firmware Version"]:
            print(f"[!] the ONT already runs {args.expect_version}")

        print(f"[*] image {os.path.basename(args.image)} ({size / 1048576:.1f} MiB)")
        if not args.yes:
            answer = input("    The ONT will flash the image and REBOOT. Continue? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("[=] cancelled")
                return 1

        print("[*] uploading (do not power off the ONT) ...")
        t0 = time.time()
        accepted, text = gui.upload(args.image, timeout=max(300, args.wait))
        print(f"    answer after {time.time() - t0:.0f}s: {text}")
        if accepted is False:
            raise GuiError("the ONT rejected the image (see answer above)")

        if args.no_wait:
            print("[+] upload sent; not waiting for the reboot (--no-wait)")
            return 0
        print(f"[*] waiting up to {args.wait}s for the ONT to reboot and come back ...")
        after = wait_back(gui, args.wait)
        if after is None:
            print(f"[-] the GUI did not come back within {args.wait}s (check the LAN link / the ONT LEDs)")
            return 2
        print(f"    running   {after['Firmware Version']}")
        print(f"    alternate {after.get('Alternate Firmware Version', '?')}")
        want = args.expect_version
        if want and after["Firmware Version"] != want:
            print(f"[-] the ONT runs {after['Firmware Version']}, expected {want}")
            return 2
        if not want and after["Firmware Version"] == before["Firmware Version"]:
            print("[-] the version did not change (image rejected, same version, or not committed)")
            return 2
        print(f"[+] firmware upgraded: {before['Firmware Version']} -> {after['Firmware Version']}")
        return 0
    except GuiError as e:
        print(f"[-] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
