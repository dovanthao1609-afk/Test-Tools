"""Auto-run `bridge add` on a Zhone MXK for every ONU in an `onu set ...` register file.

VLAN plan (by meprof):
    zhone-2424  (2424GN)  -> PPPoE VLAN 135,  DHCP VLAN 200
    dzs-2411gn  (2411GN)  -> PPPoE VLAN 2021, DHCP VLAN 200
    dzs-2401gn  (2401GN)  -> PPPoE VLAN 2021, DHCP VLAN 200

Usage: edit the "USER SETTINGS" block below, then run:
    python onu_bridge.py create    # add the bridges
    python onu_bridge.py delete    # remove the same bridges
"""
import re
import socket
import sys
import time

# ------------------------------------------------------- USER SETTINGS ------
MXK_IP = "192.168.100.147"      # MXK IP / hostname
USERNAME = "admin"
PASSWORD = "zhone"
CMD_DELAY = 0.5          # seconds to wait before sending each command
GTP = "1100000000"      # GEM traffic profile used in every `bridge add ... gtp <GTP>`
DRY_RUN = False          # True = only print the commands (no connection); False = really connect and run

# ---------------------------------------------------------------- config ----
VLAN_PLAN = {
    "zhone-2424": {"pppoe": 135, "dhcp": 200},   # 2424GN
    "dzs-2411gn": {"pppoe": 2021, "dhcp": 200},  # 2411GN
    "dzs-2401gn": {"pppoe": 2021, "dhcp": 200},  # 2401GN
}
# Bridge names are generated in order, one per `bridge add`: data1, data2, ... (see build_jobs).
# With 10 ONUs x 2 bridges (PPPoE + DHCP) that is data1 .. data20.

# Paste your `onu set ...` lines here (other lines are ignored).
ONU_REGISTER = """
onu set 1/2/31 vendorid ZNTS serno fsan 0544AC53 meprof zhone-2424 ch 1
onu set 1/2/32 vendorid ZNTS serno fsan 05440475 meprof dzs-2411gn ch 1
onu set 1/2/33 vendorid ZNTS serno fsan 0544AC93 meprof zhone-2424 ch 1
onu set 1/2/34 vendorid ZNTS serno fsan 0543FECD meprof dzs-2411gn ch 1
onu set 1/2/35 vendorid ZNTS serno fsan 0509DE87 meprof dzs-2401gn ch 1
onu set 1/2/36 vendorid ZNTS serno fsan 0544AC55 meprof zhone-2424 ch 1
onu set 1/2/37 vendorid ZNTS serno fsan 0544AA4F meprof zhone-2424 ch 1
onu set 1/2/38 vendorid ZNTS serno fsan 0544AC2F meprof zhone-2424 ch 1
onu set 1/2/39 vendorid ZNTS serno fsan 050F80E9 meprof dzs-2401gn ch 1
onu set 1/2/40 vendorid ZNTS serno fsan 0544AC85 meprof zhone-2424 ch 1
"""

PROMPT_RE = re.compile(rb"zSH>\s*$")  # a command is sent only after this prompt appears
PAGER_RE = re.compile(rb"<SPACE> for next page[^\r\n]*Q to quit\s*$")  # the OLT paginates long output
ERROR_RE = re.compile(r"error|invalid|fail|not found|unknown|already", re.I)

ONU_RE = re.compile(r"onu\s+set\s+(\d+)/(\d+)/(\d+)\s.*?\bmeprof\s+(\S+)", re.I)

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


# ------------------------------------------------------------- 1. parse -----
def parse_onus(text):
    """Read the `onu set` lines in `text` -> list of (onu_id, meprof).

    `onu set 1/2/31 ... meprof zhone-2424 ...` becomes onu_id `1-1-2-31`
    (the leading `1-` is the shelf, same as in `bridge add 1-1-2-31/gpononu`).
    """
    onus = []
    for line in text.splitlines():
        m = ONU_RE.search(line)
        if not m:
            continue
        a, b, c, meprof = m.groups()
        onus.append((f"1-{a}-{b}-{c}", meprof.lower()))
    return onus


# ------------------------------------------------------------- 2. telnet ----
class Telnet:
    """Minimal telnet client (stdlib `telnetlib` was removed in Python 3.13).

    Raw TCP + refuses every telnet option negotiation, enough for a plain CLI session.
    """

    def __init__(self, host, port=23, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(1)  # short poll; the real wait limit is in _read_until
        self.echo = False  # True = print everything received from the OLT as it arrives

    def _read_until(self, pattern, timeout=60):
        """Wait (up to `timeout` s) until `pattern` shows up at the END of the output, e.g. the zSH> prompt."""
        buf, end = b"", time.time() + timeout
        while time.time() < end:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue  # nothing yet - keep waiting
            if not data:
                raise ConnectionError("OLT closed the connection")
            chunk = self._strip_iac(data)
            buf += chunk
            if self.echo:
                sys.stdout.write(chunk.decode(errors="replace").replace("\r", ""))
                sys.stdout.flush()
            if PAGER_RE.search(buf[-200:]):
                # Long output: "<SPACE> for next page, ... A for all, Q to quit" - ask for all of it.
                self.sock.sendall(b"a")
                buf = PAGER_RE.sub(b"", buf)
                end = time.time() + timeout
                continue
            if pattern.search(buf[-200:]):
                return buf.decode(errors="replace")
        raise TimeoutError(f"timeout waiting for {pattern.pattern!r}; got: {buf[-200:]!r}")

    def _strip_iac(self, data):
        """Remove telnet IAC sequences; answer DO -> WONT, WILL -> DONT."""
        out, i = bytearray(), 0
        while i < len(data):
            if data[i] != IAC:
                out.append(data[i])
                i += 1
            elif i + 2 < len(data) and data[i + 1] in (DO, DONT, WILL, WONT):
                cmd, opt = data[i + 1], data[i + 2]
                if cmd == DO:
                    self.sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd == WILL:
                    self.sock.sendall(bytes([IAC, DONT, opt]))
                i += 3
            elif i + 1 < len(data) and data[i + 1] == SB:
                j = data.find(bytes([IAC, SE]), i)
                i = len(data) if j < 0 else j + 2
            else:
                i += 2
        return bytes(out)

    def login(self, user, password):
        self._read_until(re.compile(rb"(?i)(login|user(name)?)\s*:\s*$"))
        self.sock.sendall(user.encode() + b"\r\n")
        self._read_until(re.compile(rb"(?i)password\s*:\s*$"))
        self.sock.sendall(password.encode() + b"\r\n")
        self._read_until(PROMPT_RE)

    def run(self, cmd):
        """Send one CLI command, return its output (up to the next prompt)."""
        time.sleep(CMD_DELAY)  # small pause before every command so we don't hammer the OLT
        self.sock.sendall(cmd.encode() + b"\r\n")
        return self._read_until(PROMPT_RE)

    def close(self):
        self.sock.close()


# ---------------------------------------------------------- 3. add bridge ---
def add_bridge(tn, onu_id, vlan, name):
    """Run `bridge add <onu>/gpononu gtp <GTP> downlink vlan <vlan> tagged rg name <name>`.

    Returns (ok, command, output). ok=False if the CLI output looks like an error.
    """
    cmd = f"bridge add {onu_id}/gpononu gtp {GTP} downlink vlan {vlan} tagged rg name {name}"
    out = tn.run(cmd)
    return (not ERROR_RE.search(out)), cmd, out


# -------------------------------------------------------- 4. delete bridge ---
def delete_bridge(tn, onu_id, vlan, name):
    """Run `bridge delete <name>/bridge` (undo of add_bridge).

    Deletes by bridge NAME (data1, data2, ...), so it only removes the bridge we created
    and never touches other existing bridges/ports. onu_id and vlan are unused here.
    Returns (ok, command, output).
    """
    cmd = f"bridge delete {name}/bridge"
    out = tn.run(cmd)
    return (not ERROR_RE.search(out)), cmd, out


# --------------------------------------------------- 5. show on success -----
def show_bridge(tn, vlan):
    """Run `bridge show vlan <vlan>` to confirm. Called once per VLAN, after all add/delete commands finished."""
    return tn.run(f"bridge show vlan {vlan}")


# -------------------------------------------------------------- main --------
def build_jobs():
    """ONU_REGISTER -> list of (onu_id, service, vlan, bridge_name), 2 per ONU.

    Every bridge add gets its own sequential name: data1, data2, data3, ... (no repeats).
    """
    onus = parse_onus(ONU_REGISTER)
    if not onus:
        sys.exit("No `onu set` lines found.")
    jobs = []
    n = 0
    for onu_id, meprof in onus:
        plan = VLAN_PLAN.get(meprof)
        if not plan:
            sys.exit(f"ONU {onu_id}: meprof '{meprof}' has no VLAN plan - add it to VLAN_PLAN.")
        for svc in ("pppoe", "dhcp"):
            n += 1
            jobs.append((onu_id, svc, plan[svc], f"data{n}"))
    return jobs


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("create", "delete"):
        sys.exit("Usage: python onu_bridge.py create   (add the bridges)\n"
                 "       python onu_bridge.py delete   (remove the same bridges)")
    mode = sys.argv[1]
    action = add_bridge if mode == "create" else delete_bridge

    # Build the whole job list first so an unknown meprof is caught before touching the OLT.
    jobs = build_jobs()

    if DRY_RUN:
        print(f"*** DRY RUN ({mode}): NOT connecting to the OLT, nothing is sent. "
              f"Set DRY_RUN = False to run for real. ***")
        for onu_id, svc, vlan, name in jobs:
            cmd = (f"bridge add {onu_id}/gpononu gtp {GTP} downlink vlan {vlan} tagged rg name {name}"
                   if mode == "create" else
                   f"bridge delete {name}/bridge")
            print(f"{cmd}   # {svc}")
        return

    print(f"Connecting to {MXK_IP} ...")
    tn = Telnet(MXK_IP)
    failed = []
    try:
        tn.login(USERNAME, PASSWORD)
        # From here on, everything the OLT sends is printed live, exactly like a terminal
        # (prompt, echoed command, OLT reply, prompt...). The password is never echoed.
        tn.echo = True
        print("zSH> ", end="", flush=True)

        # Phase 1: run every add/delete first.
        done_vlans = []  # VLANs with at least one successful command, in order, no duplicates
        for onu_id, svc, vlan, name in jobs:
            ok, cmd, out = action(tn, onu_id, vlan, name)
            if ok:
                if vlan not in done_vlans:
                    done_vlans.append(vlan)
            else:
                failed.append(cmd)

        # Phase 2: only after ALL commands are done, show each VLAN once.
        for vlan in done_vlans:
            show_bridge(tn, vlan)
    finally:
        tn.close()

    print(f"\n\nDone: {len(jobs) - len(failed)}/{len(jobs)} succeeded.")
    for cmd in failed:
        print("  failed:", cmd)


if __name__ == "__main__":
    main()
