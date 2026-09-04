#!/usr/bin/env python3
"""Check dịch vụ Multicast từ PC (NIC cắm vào port LAN của ONT).

Luồng check:
  1. Lấy IP DHCP trên interface (renew nếu chưa có)
  2. Join group multicast QUA ĐÚNG interface đó -> IGMP report đi ra ONT -> OLT
  3. Đếm traffic của stream (PPS phải > 0)
  4. Trong lúc VẪN CÒN JOIN, đọc 'show ip igmp group' trên OLT và so group

Điểm quan trọng: membership phải được giữ mở khi query OLT. Đóng socket là
gửi IGMP Leave, OLT sẽ xoá entry ngay -> check trên OLT sẽ FAIL oan.
"""

import re
import socket
import subprocess
import time

from ping_check import log, GREEN, RED, YELLOW, CYAN, RESET

APIPA_PREFIX = "169.254."      # IP tự sinh khi KHÔNG có DHCP -> coi như chưa có IP

IGMP_V2_REPORT = 0x16
IGMP_V2_LEAVE  = 0x17

try:
    from scapy.all import Ether, sendp, get_if_hwaddr
    from scapy.layers.inet import IP as _ScapyIP, IPOption_Router_Alert
    from scapy.contrib.igmp import IGMP
    _SCAPY_OK = True
except Exception as _e:          # noqa: BLE001
    _SCAPY_OK = False
    _SCAPY_ERR = str(_e)


def _mcast_mac(ip_addr):
    """MAC multicast tương ứng 1 địa chỉ IP multicast (RFC 1112)."""
    o = [int(x) for x in ip_addr.split(".")]
    return "01:00:5e:%02x:%02x:%02x" % (o[1] & 0x7f, o[2], o[3])


def send_igmpv2(iface, src_ip, group, typ=IGMP_V2_REPORT):
    """Gửi IGMPv2 Report / Leave bằng Scapy. Trả (ok, thông tin).

    LÝ DO PHẢI TỰ GỬI: Windows chỉ phát IGMPv3 Report (type 0x22) tới
    224.0.0.22. IGMP snooping của OLT không nhận ra loại gói đó nên bảng
    'show ip igmp snooping explicit-tracking groups' không có entry nào,
    dù OS đã join thật (netsh interface ip show joins có thấy group).
    Gửi thêm v2 Report (type 0x16, gửi thẳng tới địa chỉ group) thì OLT
    hiện đúng group kèm Reporter = IP của interface.
    """
    if not _SCAPY_OK:
        return False, f"scapy không dùng được: {_SCAPY_ERR}"

    dst = group if typ == IGMP_V2_REPORT else "224.0.0.2"
    try:
        pkt = (Ether(src=get_if_hwaddr(iface), dst=_mcast_mac(dst)) /
               _ScapyIP(src=src_ip, dst=dst, ttl=1,
                        options=[IPOption_Router_Alert()]) /
               IGMP(type=typ, gaddr=group))
        sendp(pkt, iface=iface, verbose=0)
        return True, dst
    except Exception as e:
        return False, str(e)


def _run(args, timeout):
    """Chạy 1 command, trả (rc, output). Không bao giờ treo quá `timeout`.

    Cần thiết vì 'ipconfig /renew' treo ~3 phút khi không có DHCP server.
    """
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return None, f"TIMEOUT sau {timeout}s: {' '.join(args)}"
    except Exception as e:
        return None, f"ERROR: {e}"


def get_iface_ipv4(iface, timeout=30):
    """IPv4 hiện tại của interface, bỏ qua APIPA. None nếu chưa có IP hợp lệ."""
    alias = iface.replace("'", "''")
    rc, out = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        f"Get-NetIPAddress -InterfaceAlias '{alias}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress",
    ], timeout=timeout)

    for line in (out or "").splitlines():
        ip = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip) and not ip.startswith(APIPA_PREFIX):
            return ip
    return None


def renew_dhcp(iface, timeout=60):
    """ipconfig /renew trên 1 interface, có cắt timeout."""
    log(f"[MCAST] ipconfig /renew \"{iface}\" ...", CYAN)
    rc, out = _run(["ipconfig", "/renew", iface], timeout=timeout)
    if rc is None:
        log(f"[MCAST] renew bị cắt: {out}", YELLOW)
    return out


def wait_dhcp_ip(iface, wait_sec=30, renew=True, renew_timeout=60):
    """Chờ interface có IP DHCP. Trả về IP hoặc None."""
    ip = get_iface_ipv4(iface)
    if ip:
        log(f"[MCAST] {iface} đã có IP {ip}", GREEN)
        return ip

    if renew:
        renew_dhcp(iface, timeout=renew_timeout)

    deadline = time.time() + wait_sec
    while time.time() < deadline:
        ip = get_iface_ipv4(iface)
        if ip:
            log(f"[MCAST] {iface} nhận IP DHCP {ip}", GREEN)
            return ip
        time.sleep(2)

    log(f"[MCAST] {iface} KHÔNG nhận được IP DHCP sau {wait_sec}s", RED)
    return None


class MulticastJoin:
    """Join 1 group multicast qua 1 interface cụ thể và đếm traffic.

    Dùng như context manager để membership sống đủ lâu cho việc query OLT:

        with MulticastJoin(group, port, iface_ip) as mj:
            traffic = mj.measure(5)
            out = olt_show_igmp_group()     # OLT vẫn còn thấy group ở đây

    port = 0 -> chỉ join để OLT thấy group, còn việc đếm packet dùng raw
    socket (bắt mọi UDP port của group) — chế độ này CẦN quyền Administrator.
    """

    def __init__(self, group, port, iface_ip, iface=None):
        self.group    = group
        self.port     = int(port or 0)
        self.iface_ip = iface_ip
        self.iface    = iface     # cần cho Scapy gửi IGMPv2
        self.sock     = None
        self.raw      = None

    @property
    def mreq(self):
        return socket.inet_aton(self.group) + socket.inet_aton(self.iface_ip)

    def __enter__(self):
        # Socket join: bind INADDR_ANY (Windows không cho bind vào địa chỉ group).
        # IP_ADD_MEMBERSHIP với iface_ip đảm bảo IGMP report đi ra ĐÚNG NIC
        # cắm vào ONT, không đi ra interface default route.
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.port))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, self.mreq)
        self.sock.settimeout(1.0)
        log(f"[MCAST] OS joined {self.group}:{self.port or '(any)'} qua {self.iface_ip}", CYAN)

        # OS join ở trên chỉ đủ để NHẬN stream. Muốn OLT thấy group thì phải
        # gửi thêm IGMPv2 Report (xem docstring send_igmpv2).
        self.send_reports()

        if not self.port:
            self.raw = self._open_raw()
        return self

    def send_reports(self, times=3, gap=0.3):
        """Gửi IGMPv2 Membership Report để OLT học được group + Reporter."""
        if not self.iface:
            return False
        sent = 0
        for _ in range(times):
            ok, info = send_igmpv2(self.iface, self.iface_ip, self.group)
            if not ok:
                log(f"[MCAST] KHÔNG gửi được IGMPv2 Report: {info} "
                    f"-> OLT sẽ không thấy group", RED)
                return False
            sent += 1
            time.sleep(gap)
        log(f"[MCAST] đã gửi {sent} IGMPv2 Report {self.group} "
            f"từ {self.iface_ip} qua {self.iface}", CYAN)
        return True

    def refresh(self):
        """Gửi lại 1 Report — dùng ngay trước khi đọc OLT cho chắc."""
        return self.send_reports(times=1, gap=0)

    def _open_raw(self):
        """Bắt mọi packet tới group bất kể UDP port. Cần Administrator."""
        if not hasattr(socket, "SIO_RCVALL"):
            log("[MCAST] raw sniff chỉ có trên Windows -> bỏ qua", YELLOW)
            return None
        try:
            r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            r.bind((self.iface_ip, 0))
            r.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            r.settimeout(1.0)
            log(f"[MCAST] raw sniff {self.group} (mọi port)", CYAN)
            return r
        except Exception as e:
            log(f"[MCAST] không mở được raw socket ({e}). "
                f"Chạy script bằng Administrator, hoặc set MCAST_PORT = port thật.", RED)
            return None

    def measure(self, seconds):
        """Đếm packet của stream trong `seconds` giây -> dict pps/mbps."""
        src = self.raw if self.raw is not None else self.sock
        if not self.port and self.raw is None:
            return {"packets": 0, "bytes": 0, "seconds": 0.0, "pps": 0.0,
                    "bitrate_kb": 0.0, "mbps": 0.0,
                    "error": "cần Administrator cho chế độ any-port"}

        pkts = octets = 0
        t0 = time.time()
        deadline = t0 + seconds
        while time.time() < deadline:
            try:
                data = src.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            if src is self.raw:
                # raw = cả IP header, địa chỉ đích nằm ở byte 16:20
                if len(data) < 20 or socket.inet_ntoa(data[16:20]) != self.group:
                    continue

            pkts   += 1
            octets += len(data)

        elapsed = max(time.time() - t0, 0.001)
        return {
            "packets": pkts,
            "bytes":   octets,
            "seconds": round(elapsed, 2),
            "pps":     round(pkts / elapsed, 1),
            # Bitrate tính giống DHCP_PPPoE_Client_Emulator_Final 6.py
            # (_igmp_update_stats: g_kb = cur_bytes / 1024) -> KB tích luỹ.
            # Khác 0 nghĩa là có luồng thực tế.
            "bitrate_kb": round(octets / 1024, 1),
            # rate thật, giữ thêm để biết stream nặng bao nhiêu
            "mbps":    round(octets * 8 / elapsed / 1_000_000, 3),
        }

    def __exit__(self, *exc):
        # báo Leave để OLT xoá entry ngay, tránh loop sau thấy entry cũ mà
        # tưởng là join mới thành công
        if self.iface:
            send_igmpv2(self.iface, self.iface_ip, self.group, IGMP_V2_LEAVE)
        if self.raw is not None:
            try:
                self.raw.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                self.raw.close()
            except Exception:
                pass
        if self.sock is not None:
            try:
                self.sock.setsockopt(socket.IPPROTO_IP,
                                     socket.IP_DROP_MEMBERSHIP, self.mreq)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        return False


IPV4_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def parse_igmp_group(output, group, reporter=None):
    """Parse 'show ip igmp snooping explicit-tracking groups' trên OLT.

    Format thật:
        IGMP Connected Group Membership
        VLAN Group Address       Port      Uptime   Expires  Reporter
        1237 237.0.0.23          gpon0/3   00:17:37 00:02:29 192.168.237.56

    Điều kiện PASS: có dòng đúng group ĐỒNG THỜI Reporter trùng IP của
    interface đã join. Chỉ thấy group là chưa đủ — group có thể do client
    khác trên cùng PON join.
    """
    rows = []
    for line in output.splitlines():
        parts = line.split()
        # dòng header không chứa IP nên tự bị loại
        if group not in parts:
            continue

        # Reporter là IPv4 cuối dòng và khác địa chỉ group
        rep = next((p for p in reversed(parts)
                    if IPV4_RE.fullmatch(p) and p != group), None)

        rows.append({
            "raw":      line.strip(),
            "vlan":     parts[0] if parts and parts[0].isdigit() else None,
            "group":    group,
            "port":     parts[2] if len(parts) >= 6 else None,
            "reporter": rep,
        })

    found     = bool(rows)
    reporters = [r["reporter"] for r in rows if r["reporter"]]
    rep_match = (reporter is None) or (reporter in reporters)

    return {
        "group":           group,
        "found":           found,
        "rows":            rows,
        "reporters":       reporters,
        "expect_reporter": reporter,
        "reporter_match":  rep_match,
        "ok":              found and rep_match,
    }


def check_multicast(iface, group, port, olt_igmp_reader,
                    sample_sec=5, min_pps=1, dhcp_renew=True,
                    dhcp_wait=30, renew_timeout=60):
    """Check đủ 3 điều kiện: có IP DHCP + stream có traffic + OLT thấy group.

    olt_igmp_reader: callable không tham số, trả output 'show ip igmp group'.
    """
    res = {
        "iface": iface, "group": group, "port": port, "ip": None,
        "dhcp_ok": False, "traffic": None, "traffic_ok": False,
        "igmp": None, "igmp_ok": False, "igmp_output": "", "ok": False,
    }

    print(f"\n[STEP] MULTICAST check: {iface} -> group {group}")

    # 1. IP DHCP
    ip = wait_dhcp_ip(iface, wait_sec=dhcp_wait, renew=dhcp_renew,
                      renew_timeout=renew_timeout)
    res["ip"] = ip
    res["dhcp_ok"] = bool(ip)
    if not ip:
        # chưa có IP thì join cũng vô nghĩa -> FAIL sớm cho nhanh
        res["error"] = f"{iface} chưa có IP DHCP"
        log(f"[MCAST] FAIL - {res['error']}", RED)
        return res

    # 2 + 3. Join, đo PPS, rồi query OLT trong lúc còn join
    try:
        with MulticastJoin(group, port, ip, iface=iface) as mj:
            log(f"[MCAST] đo traffic {sample_sec}s ...", CYAN)
            traffic = mj.measure(sample_sec)
            res["traffic"] = traffic
            # có luồng thực tế = PPS # 0 VÀ bitrate # 0
            res["traffic_ok"] = (traffic["pps"] >= min_pps
                                 and traffic["bitrate_kb"] > 0)
            log(f"[MCAST] {traffic['packets']} packets / {traffic['seconds']}s "
                f"=> {traffic['pps']} pps, {traffic['bitrate_kb']} KB "
                f"({traffic['mbps']} Mbps)",
                GREEN if res["traffic_ok"] else RED)

            log("[MCAST] đọc IGMP snooping trên OLT (PC đang còn join) ...", CYAN)
            mj.refresh()          # telnet vào OLT mất ~10s, gửi lại cho chắc
            out = olt_igmp_reader() or ""
            res["igmp_output"] = out
            # reporter phải đúng IP của interface đã join
            res["igmp"] = parse_igmp_group(out, group, reporter=ip)
            res["igmp_ok"] = res["igmp"]["ok"]
            g = res["igmp"]
            log(f"[MCAST] OLT group {group}: "
                f"{'FOUND' if g['found'] else 'NOT FOUND'} | "
                f"Reporter={g['reporters'] or 'none'} (cần {ip}) -> "
                f"{'MATCH' if g['reporter_match'] else 'MISMATCH'}",
                GREEN if res["igmp_ok"] else RED)
            for row in g["rows"]:
                log(f"[MCAST]   {row['raw']}", YELLOW)
    except Exception as e:
        res["error"] = str(e)
        log(f"[MCAST] lỗi khi join/đo multicast: {e}", RED)
        return res

    res["ok"] = res["dhcp_ok"] and res["traffic_ok"] and res["igmp_ok"]
    status = f"{GREEN}OK{RESET}" if res["ok"] else f"{RED}FAIL{RESET}"
    log(f"[MCAST] Multicast service: {status}", CYAN)
    return res


def summarize(res):
    """1 dòng gọn để ghi vào log file."""
    t = res.get("traffic") or {}
    g = res.get("igmp") or {}
    parts = [
        f"{res['iface']}",
        f"ip={res.get('ip') or 'none'}",
        f"pps={t.get('pps', 0)}",
        f"bitrate={t.get('bitrate_kb', 0)} KB",
        f"group={res['group']}:{'found' if g.get('found') else 'not-found'}",
        f"reporter={','.join(g.get('reporters') or []) or 'none'}"
        f"{'' if g.get('reporter_match') else '(MISMATCH)'}",
    ]
    if res.get("error"):
        parts.append(f"error={res['error']}")
    return " | ".join(parts)


if __name__ == "__main__":
    # Test nhanh phần PC, không cần OLT
    IFACE = "Ethernet 4"
    GROUP = "237.0.0.23"
    PORT  = 5000
    r = check_multicast(IFACE, GROUP, PORT, lambda: "Total Entries: 0",
                        sample_sec=5)
    print("\nRESULT:", summarize(r))
    print("OK =", r["ok"])
