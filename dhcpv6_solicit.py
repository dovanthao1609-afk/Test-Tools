"""
DHCPv6 Solicit sender — gửi DHCPv6 SOLICIT và in ra ADVERTISE nhận được.

Ví dụ:
    python dhcpv6_solicit.py --list
    python dhcpv6_solicit.py -i "Ethernet 2" -m 08:67:4E:CD:DA:88
    python dhcpv6_solicit.py -i "Ethernet 2" -m 08:67:4E:CD:DA:88 --vlan 100 --pcp 0 --pd
    python dhcpv6_solicit.py -i "Ethernet 2" -n 5 --rapid-commit

Yêu cầu: scapy + Npcap (Windows), chạy với quyền Administrator.
"""

import argparse
import random
import sys

from scapy.all import AsyncSniffer, Dot1Q, Ether, IPv6, NoPayload, UDP, conf, sendp
from scapy.layers.dhcp6 import (
    DHCP6_Advertise, DHCP6_Reply, DHCP6_Solicit,
    DHCP6OptClientId, DHCP6OptServerId, DHCP6OptElapsedTime, DHCP6OptOptReq,
    DHCP6OptIA_NA, DHCP6OptIA_PD, DHCP6OptRapidCommit,
    DHCP6OptIAAddress, DHCP6OptIAPrefix, DHCP6OptDNSServers, DHCP6OptStatusCode,
    DUID_LL,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def random_mac():
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] = (mac[0] & 0xFE) | 0x02   # locally administered, unicast
    return ':'.join(f'{b:02x}' for b in mac)


def increment_mac(base_mac: str, n: int) -> str:
    val = int.from_bytes(bytes.fromhex(base_mac.replace(':', '').replace('-', '')), 'big')
    val = (val + n) & 0xFFFFFFFFFFFF
    return ':'.join(f'{b:02x}' for b in val.to_bytes(6, 'big'))


def mac_to_link_local(mac: str) -> str:
    """Convert MAC to IPv6 link-local address (EUI-64, fe80::/64)."""
    b = [int(x, 16) for x in mac.replace('-', ':').split(':')]
    b[0] ^= 0x02
    return "fe80::{:02x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}".format(
        b[0], b[1], b[2], b[3], b[4], b[5])


def list_ifaces():
    """Print numbered interface list, return list of interface names."""
    names = []
    for name, iface in conf.ifaces.items():
        desc = getattr(iface, 'description', '') or getattr(iface, 'name', name)
        ip   = getattr(iface, 'ip', '')
        names.append(getattr(iface, 'name', name))
        print(f"  [{len(names)}] {names[-1]:<30} {desc}  [{ip}]")
    return names


def ask(prompt, default=""):
    val = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return val or default


def interactive(args):
    """Hỏi các thông số khi chạy không có tham số (vd. bấm Run trong VS Code)."""
    names = list_ifaces()
    while not args.iface:
        sel = ask("Chọn interface (số hoặc tên)")
        if sel.isdigit() and 1 <= int(sel) <= len(names):
            args.iface = names[int(sel) - 1]
        elif sel in names:
            args.iface = sel
    args.mac   = ask("Client MAC (Enter = random)", args.mac or "") or None
    args.count = int(ask("Số client", str(args.count)))
    args.vlan  = int(ask("VLAN ID (0 = untagged)", str(args.vlan)))
    if args.vlan:
        args.pcp = int(ask("PCP", str(args.pcp)))
    args.pd = ask("Thêm IA_PD? (y/n)", "y" if args.pd else "n").lower().startswith("y")


def build_solicit(mac, trid, iaid, args):
    eth = Ether(dst="33:33:00:01:00:02", src=mac)
    l2  = eth / Dot1Q(vlan=args.vlan, prio=args.pcp) if args.vlan else eth

    pkt = (l2 /
           IPv6(src=mac_to_link_local(mac), dst="ff02::1:2") /
           UDP(sport=546, dport=547) /
           DHCP6_Solicit(trid=trid) /
           DHCP6OptClientId(duid=DUID_LL(lladdr=mac)) /
           DHCP6OptElapsedTime(elapsedtime=0))
    if not args.no_na:
        pkt /= DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0)
    if args.pd:
        pkt /= DHCP6OptIA_PD(iaid=iaid, T1=0, T2=0)
    if args.rapid_commit:
        pkt /= DHCP6OptRapidCommit()
    pkt /= DHCP6OptOptReq(reqopts=[23, 24])   # DNS servers, domain list
    return pkt


def print_reply(pkt):
    kind = "REPLY (rapid-commit)" if DHCP6_Reply in pkt else "ADVERTISE"
    print(f"    <<< {kind} from {pkt[IPv6].src}  (MAC {pkt[Ether].src})")
    opt = pkt[DHCP6_Reply if DHCP6_Reply in pkt else DHCP6_Advertise].payload
    while opt and not isinstance(opt, NoPayload):
        if isinstance(opt, DHCP6OptServerId):
            print(f"        Server DUID : {bytes(opt.duid).hex()}")
        elif isinstance(opt, DHCP6OptIA_NA):
            for a in opt.ianaopts:
                if hasattr(a, 'addr'):
                    print(f"        IA_NA addr  : {a.addr}  pref={a.preflft} valid={a.validlft}")
        elif isinstance(opt, DHCP6OptIA_PD):
            for p in opt.iapdopt:
                if hasattr(p, 'prefix'):
                    print(f"        IA_PD prefix: {p.prefix}/{p.plen}  pref={p.preflft} valid={p.validlft}")
        elif isinstance(opt, DHCP6OptDNSServers):
            print(f"        DNS servers : {', '.join(opt.dnsservers)}")
        elif isinstance(opt, DHCP6OptStatusCode):
            print(f"        Status      : code={opt.statuscode} {opt.statusmsg}")
        opt = opt.payload


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Send DHCPv6 SOLICIT and show ADVERTISE")
    ap.add_argument("-i", "--iface", help="interface name (xem --list)")
    ap.add_argument("-m", "--mac", help="client MAC (mặc định: random)")
    ap.add_argument("-n", "--count", type=int, default=1, help="số client (MAC tăng dần)")
    ap.add_argument("--vlan", type=int, default=0, help="VLAN ID (0 = untagged)")
    ap.add_argument("--pcp", type=int, default=0, help="802.1p priority")
    ap.add_argument("--pd", action="store_true", help="thêm IA_PD (prefix delegation)")
    ap.add_argument("--no-na", action="store_true", help="không gửi IA_NA")
    ap.add_argument("--rapid-commit", action="store_true", help="thêm option Rapid Commit")
    ap.add_argument("-t", "--timeout", type=float, default=3.0, help="thời gian chờ ADVERTISE (s)")
    ap.add_argument("--list", action="store_true", help="liệt kê interface rồi thoát")
    args = ap.parse_args()

    if args.list:
        list_ifaces()
        return
    if not args.iface:
        interactive(args)

    base_mac = args.mac or random_mac()
    for i in range(args.count):
        mac  = increment_mac(base_mac, i)
        trid = random.randint(1, 0xFFFFFF)
        iaid = random.randint(1, 0xFFFFFFFF)
        pkt  = build_solicit(mac, trid, iaid, args)

        print(f"[{i + 1}/{args.count}] >>> SOLICIT  mac={mac}  ll={mac_to_link_local(mac)}  "
              f"trid=0x{trid:06x}  iaid={iaid}"
              + (f"  vlan={args.vlan}" if args.vlan else ""))

        sniffer = AsyncSniffer(
            iface=args.iface,
            filter="udp and src port 547 and dst port 546",
            lfilter=lambda p, _t=trid: (
                (DHCP6_Advertise in p and p[DHCP6_Advertise].trid == _t) or
                (DHCP6_Reply in p and p[DHCP6_Reply].trid == _t)
            ),
            timeout=args.timeout,
        )
        sniffer.start()
        sendp(pkt, iface=args.iface, verbose=False)
        sniffer.join()

        replies = sniffer.results or []
        if not replies:
            print("    (không nhận được ADVERTISE)")
        for r in replies:
            print_reply(r)


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        sys.exit("Cần chạy với quyền Administrator.")
