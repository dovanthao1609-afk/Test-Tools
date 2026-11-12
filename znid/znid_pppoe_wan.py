#!/usr/bin/env python3
"""Set up (or show / remove) a PPPoE WAN on a ZNID-24xxA1 ONT through its web GUI.

Standalone single file: only needs Python 3.8+ and ``requests`` (pip install requests).
It sends exactly the requests the GUI's own pages send (micro_httpd, HTTP Basic auth,
per-page sessionKey):

  1. Configuration > VLAN > Add       : VLAN <id> with connection type "PPPoE Routed"
                                        (skipped when the VLAN already exists as PPPoE)
  2. Configuration > PPPoE > Edit     : account, authentication, MTU, NAT, ... then Apply/Save
  3. reads the form back to verify the settings were stored

The script stops once the settings are stored in the GUI: it does not wait for or check the
PPP session (that needs the OLT service and the BRAS, which this script does not touch).

Examples
  python znid_pppoe_wan.py --host 192.168.1.1 --vlan 135 --pppoe-user zhone --pppoe-password 123456
  python znid_pppoe_wan.py --host 192.168.100.189 --port 28080 --vlan 135 \
         --pppoe-user zhone --pppoe-password 123456 --auth CHAP --mtu 1492
  python znid_pppoe_wan.py --host 192.168.1.1 --vlan 135 --show
  python znid_pppoe_wan.py --host 192.168.1.1 --vlan 135 --remove

Exit code: 0 = done (settings stored and read back), 1 = error.
"""

from __future__ import annotations

import argparse
import html
import re
import ssl
import sys
import time

import requests
import urllib3
import warnings
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)  # TLSv1 floor for the ONT's old HTTPS stack

AUTH_MODES = ("AUTO_AUTH", "CHAP", "MS-CHAP", "PAP")
SESSION_KEY = re.compile(r"sessionKey\s*=\s*'?(\d+)")
# form field name on the PPPoE edit page -> key used by this script
FIELDS = {"ipAddress": "ip", "subnetmask": "mask", "gateway": "gateway", "maxMtu": "mtu",
          "username": "username", "password": "password", "servicename": "service_name",
          "idledisconnect": "idle_timeout", "retryinterval": "retry_interval",
          "lcpecho": "lcp_echo", "lcpechoretry": "lcp_echo_retry"}
SELECTS = {"dhcpclient": "mode", "nat": "nat", "upnp": "upnp", "derivedMac": "derived_mac",
           "authentication": "authentication"}


class GuiError(RuntimeError):
    pass


class _LegacyTls(HTTPAdapter):
    """The ONT's HTTPS server only offers RSA key exchange / old TLS: accept it (management only)."""

    def _ctx(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.options |= getattr(ssl, "OP_IGNORE_UNEXPECTED_EOF", 0)
        return ctx

    def init_poolmanager(self, *a, **k):
        k["ssl_context"] = self._ctx()
        return super().init_poolmanager(*a, **k)


class ZnidGui:
    def __init__(self, host, port=None, scheme="http", user="admin", password="zhone", timeout=20):
        port = int(port) if port else (443 if scheme == "https" else 80)
        default = 443 if scheme == "https" else 80
        self.base = f"{scheme}://{host}" + ("" if port == default else f":{port}")
        self.timeout = timeout
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = False
        self.s.mount("https://", _LegacyTls())

    # ---------------------------------------------------------------- basics
    def get(self, path, params=None):
        try:
            r = self.s.get(f"{self.base}/{path}", params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise GuiError(f"cannot reach {self.base}: {e}") from e
        if r.status_code == 401:
            raise GuiError("login rejected (HTTP 401): check --user / --password "
                           "(too many failures lock the GUI for a while)")
        if r.status_code != 200:
            raise GuiError(f"GET /{path} -> HTTP {r.status_code}")
        return r.text

    def session_key(self, page_text, page):
        m = SESSION_KEY.search(page_text)
        if not m:
            raise GuiError(f"no sessionKey in {page}")
        return m.group(1)

    # ----------------------------------------------------------------- VLANs
    def vlans(self):
        """{vlan_id: connection type} of Configuration > VLAN."""
        page = self.get("zhnvlanconfig.html")
        m = re.search(r"var string = '([^']*)'", page)
        if not m:
            return {}
        rows = {}
        for block in m.group(1).split("/"):
            cells = block.split("|")
            if cells and cells[0]:
                rows[cells[0]] = cells[1:]
        ids = [v for v in rows.get("VLAN ID", []) if v]
        types = next((v for k, v in rows.items() if "type" in k.lower()), [])
        return {int(v): (types[i] if i < len(types) else "") for i, v in enumerate(ids)}

    def add_vlan(self, vlan, name):
        page = self.get("zhnvlanadd.html")
        key = self.session_key(page, "zhnvlanadd.html")
        self.get(f"editPortDefault.cmd?action=add&vlanid={vlan}&vlanname={name}&secforward=Disable"
                 f"&connectiontype=PPPoE_Routed&sessionKey={key}")
        if vlan not in self.vlans():
            raise GuiError(f"VLAN {vlan} was not created (VLAN ID already used by a bridge/OMCI service?)")

    def remove_vlan(self, vlan):
        page = self.get("zhnvlanconfig.html")
        key = self.session_key(page, "zhnvlanconfig.html")
        self.get(f"editPortDefault.cmd?action=remove&rmLst={vlan}, &sessionKey={key}")
        if vlan in self.vlans():
            raise GuiError(f"VLAN {vlan} still present after remove")

    # ----------------------------------------------------------------- PPPoE
    def _edit_page(self, vlan, ifname):
        lst = self.get("zhnpppoeconfig.html")
        key = self.session_key(lst, "zhnpppoeconfig.html")
        page = self.get(f"zhnpppoecfg.cmd?action=edit&editLst={ifname}.v{vlan}.ppp&sessionKey={key}&userId=admin")
        if "savepppoe" not in page:
            raise GuiError(f"no PPPoE interface {ifname}.v{vlan}.ppp (VLAN {vlan} is not 'PPPoE Routed')")
        return page

    def pppoe(self, vlan, ifname="eth0"):
        """Configuration > PPPoE > Edit as the form is filled (includes the stored password)."""
        page = self._edit_page(vlan, ifname)
        out = {}
        for field, key in SELECTS.items():
            block = re.search(rf"name='{field}'.*?</td>", page, re.S)
            m = block and re.search(r"<option value = '([^']*)'\s*Selected", block.group(0), re.I)
            out[key] = m.group(1) if m else None
        for field, key in FIELDS.items():
            m = re.search(rf"name='{field}'[^>]*value='([^']*)'", page)
            out[key] = html.unescape(m.group(1)) if m else None
        out["_key"] = self.session_key(page, "PPPoE edit page")
        return out

    def save_pppoe(self, vlan, ifname="eth0", **wanted):
        cur = self.pppoe(vlan, ifname)
        cur.update({k: str(v) for k, v in wanted.items() if v is not None})
        params = {"action": "savepppoe", "sessionKey": cur["_key"], "vlanname": f"{ifname}.v{vlan}.ppp",
                  "vlanid": vlan, "uplink": 1, "ifalias": "Fiber WAN", "userId": "admin",
                  "dhcpcli": cur["mode"], "ipaddr": cur["ip"], "ipmask": cur["mask"], "gateway": cur["gateway"],
                  "useMac": cur["derived_mac"], "maxmtu": cur["mtu"], "nat": cur["nat"], "upnp": cur["upnp"],
                  "username": cur["username"], "password": cur["password"], "servicename": cur["service_name"],
                  "authentication": cur["authentication"], "idledisconnect": cur["idle_timeout"],
                  "retryinterval": cur["retry_interval"], "lcpecho": cur["lcp_echo"],
                  "lcpechoretry": cur["lcp_echo_retry"]}
        self.get("zhnpppoecfg.cmd", params=params)
        after = self.pppoe(vlan, ifname)
        wrong = {k: (str(v), after.get(k)) for k, v in wanted.items() if v is not None and after.get(k) != str(v)}
        if wrong:
            raise GuiError("settings did not apply (wanted, read back): "
                           + ", ".join(f"{k}={w!r}/{g!r}" for k, (w, g) in wrong.items() if k != "password"))
        return after


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("ONT web GUI")
    g.add_argument("--host", default="192.168.1.1", help="ONT GUI address (default 192.168.1.1)")
    g.add_argument("--port", type=int, help="GUI port (default 80, or 443 with --https)")
    g.add_argument("--https", action="store_true", help="use HTTPS instead of HTTP")
    g.add_argument("--user", default="admin", help="GUI user (default admin)")
    g.add_argument("--password", default="zhone", help="GUI password (default zhone)")
    w = ap.add_argument_group("PPPoE WAN")
    w.add_argument("--vlan", type=int, required=True, help="WAN VLAN ID delivered by the OLT (e.g. 135)")
    w.add_argument("--name", default=None, help="VLAN name when it is created (default PPPoE<vlan>)")
    w.add_argument("--pppoe-user", help="PPPoE account user name")
    w.add_argument("--pppoe-password", help="PPPoE account password")
    w.add_argument("--auth", choices=AUTH_MODES, default="AUTO_AUTH",
                   help="authentication (default AUTO_AUTH = negotiate; PAP sends the password in clear)")
    w.add_argument("--service-name", help="PPPoE service name (default: leave as is / empty)")
    w.add_argument("--mtu", type=int, help="max MTU (GUI default 1492)")
    w.add_argument("--nat", choices=("NAPT", "NAT", "NAPT-FC", "Disable"),
                   help="NAT mode (a new PPPoE WAN starts with Disable; NAPT = usual Internet access)")
    w.add_argument("--ifname", default="eth0", help="WAN uplink interface (default eth0)")
    a = ap.add_argument_group("actions")
    a.add_argument("--show", action="store_true", help="only print the current PPPoE settings")
    a.add_argument("--remove", action="store_true", help="delete the VLAN and its PPPoE WAN")
    args = ap.parse_args(argv)

    gui = ZnidGui(args.host, args.port, "https" if args.https else "http", args.user, args.password)
    vlan = args.vlan
    try:
        vlans = gui.vlans()
        print(f"[*] {gui.base}: VLANs {sorted(vlans)}")

        if args.remove:
            if vlan not in vlans:
                print(f"[=] VLAN {vlan} does not exist, nothing to remove")
                return 0
            gui.remove_vlan(vlan)
            print(f"[+] VLAN {vlan} and its PPPoE WAN removed")
            return 0

        if args.show:
            cfg = gui.pppoe(vlan, args.ifname)
            cfg.pop("_key")
            cfg["password"] = "*" * len(cfg["password"] or "")
            for k, v in cfg.items():
                print(f"    {k:15} {v}")
            return 0

        if vlan not in vlans:
            name = args.name or f"PPPoE{vlan}"
            print(f"[*] creating VLAN {vlan} '{name}' as PPPoE Routed")
            gui.add_vlan(vlan, name)
            time.sleep(3)
        else:
            print(f"[=] VLAN {vlan} already exists ({vlans[vlan] or 'type ?'}), reusing it")

        if not args.pppoe_user or args.pppoe_password is None:
            raise GuiError("--pppoe-user and --pppoe-password are required to configure the account")
        print(f"[*] saving PPPoE account '{args.pppoe_user}', authentication {args.auth}")
        cfg = gui.save_pppoe(vlan, args.ifname, username=args.pppoe_user, password=args.pppoe_password,
                             authentication=args.auth, service_name=args.service_name, mtu=args.mtu, nat=args.nat)
        print(f"[+] saved and verified: user={cfg['username']} auth={cfg['authentication']} "
              f"mtu={cfg['mtu']} nat={cfg['nat']} service='{cfg['service_name'] or ''}'")
        if args.auth == "PAP":
            print("[!] PAP sends the PPPoE password in clear text over the PON")
        return 0
    except GuiError as e:
        print(f"[-] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
