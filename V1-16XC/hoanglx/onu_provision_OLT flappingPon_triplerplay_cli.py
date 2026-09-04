
import telnetlib
import time
import re

from ping_check import *
from multicast_check import check_multicast, summarize as mcast_summary

# ==================================================
# OLT INFO
# ==================================================
LOOP_COUNT = 1

# ── FLAPPING PON ──────────────────────────────────
# Flap (shutdown / no shutdown) PON port nhiều lần TRƯỚC khi check dịch vụ,
# mô phỏng đứt/nối sợi quang nhiều lần như thực tế.
FLAP_PON_PORT   = "gpon 0/3"  # interface đem đi flap
FLAP_TIMES      = 3           # số lần flap trong mỗi loop (điều chỉnh tại đây)
FLAP_DOWN_SEC   = 10          # giữ port DOWN bao lâu (giây)
FLAP_UP_SEC     = 10          # giữ port UP giữa 2 lần flap (giây)
FLAP_SETTLE_SEC = 60          # chờ ONU/dịch vụ ổn định sau lần flap cuối

# ── MULTICAST ─────────────────────────────────────
# NIC của PC cắm vào port LAN của ONT, dùng để query IP DHCP + stream multicast.
MCAST_ENABLE        = True          # False để tạm tắt step multicast
MCAST_IFACE         = "Ethernet 4"  # tên interface trên PC (Get-NetAdapter)
MCAST_GROUP         = "237.0.0.23"  # group multicast cần query
MCAST_PORT          = 5000          # UDP port của stream. 0 = bắt mọi port (cần Administrator)
MCAST_SAMPLE_SEC    = 10             # thời gian đo PPS
MCAST_MIN_PPS       = 1             # PPS tối thiểu để coi là CÓ traffic (PPS # 0)
MCAST_DHCP_RENEW    = True          # ipconfig /renew trước khi lấy IP
MCAST_DHCP_WAIT     = 30            # chờ tối đa để interface có IP DHCP
MCAST_RENEW_TIMEOUT = 60            # cắt ipconfig /renew (không có DHCP nó treo ~3 phút)

TIMESTAMP    = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE     = f"terminal_log_{TIMESTAMP}.txt"
RESULT_FILE  = f"result_{TIMESTAMP}.txt"
SUMMARY_FILE = f"summary_{TIMESTAMP}.txt"

RESULT_SUMMARY = []
OLT_HOST = "192.168.100.248"
OLT_PORT = 23
OLT_USERNAME = "admin"
OLT_PASSWORD = r"Zhone1234%^&"

ONU_KEYWORD = "onu010"
ONU_USERNAME   = "admin"
ONU_PASSWORD   = "dzsi"
DEV_PASS     = "g4GwshWN"
ZNID_AP_HOST = "192.168.90.1"

VERIFY_PPPOE = [
    "gpon0/3/103",
]
 
VERIFY_IPV6_DHCP = [
    "gpon0/3/104",
]
 
VERIFY_IP_DHCP = [
    "gpon0/3/101",
    "gpon0/3/104",
]
 
VERIFY_MAC = [
    "gpon0/3/101",
    "gpon0/3/103",
    "gpon0/3/104",
    "gpon0/3/106",
]

def write_result(loop, phase, section_results):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(RESULT_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"LOOP {loop}  |  {phase}  |  {ts}\n")
        f.write(f"{'=' * 60}\n")

        for section_name, raw_output, check_list in section_results:
            f.write(f"\n--- {section_name} ---\n")
            f.write(raw_output.strip() + "\n")
            f.write("\n[VERIFY]\n")
            for target, status in check_list:
                f.write(f"  {status}: {target}\n")
def write_log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


def olt_login(tn):
    tn.write(b"\r\n")
    time.sleep(2)

    out = tn.read_very_eager().decode(errors="ignore")
    print(out)

    tn.write((OLT_USERNAME + "\r\n").encode())
    time.sleep(1)

    tn.write((OLT_PASSWORD + "\r\n").encode())
    time.sleep(2)

    out = tn.read_very_eager().decode(errors="ignore")
    print(out)

    if "incorrect" in out.lower():
        raise Exception("OLT login failed")

def send_olt_cmd(tn, cmd, wait=2):
    tn.write((cmd + "\r\n").encode())
    time.sleep(wait)
    out = tn.read_very_eager().decode(errors="ignore")
    print(out)
    return out
def OLT_CLI(file):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    olt_login(tn)
    time.sleep(1)
    send_olt_cmd(tn, "enable", 1)
    time.sleep(1)
    send_olt_cmd(tn, "terminal length 0", 1)
    time.sleep(1)
    with open(file, "r") as f:
        for line in f:
            cmd = line.strip()
            if cmd and not cmd.startswith("#"):
                send_olt_cmd(tn, cmd, wait=3)
def flap_pon_port(loop, port=FLAP_PON_PORT, times=FLAP_TIMES,
                  down_sec=FLAP_DOWN_SEC, up_sec=FLAP_UP_SEC):
    """Shutdown / no shutdown PON port `times` lần liên tiếp.

    Dùng 1 session telnet cho cả chuỗi flap. Nếu bị gián đoạn giữa chừng thì
    cố gắng 'no shutdown' lại để không bỏ PON port ở trạng thái DOWN.
    """
    print(f"\n[STEP] FLAP PON {port} x {times} "
          f"(down {down_sec}s / up {up_sec}s)")
    write_log(f"[LOOP {loop}] [FLAP] START {port} x {times} "
              f"(down={down_sec}s, up={up_sec}s)")

    def check(out, what, n):
        if "Invalid input" in out or "% Error" in out:
            write_log(f"[LOOP {loop}] [FLAP] FAIL - lệnh '{what}' bị từ chối "
                      f"tại lần {n}/{times}")
            return False
        return True

    done = 0
    ok   = False
    try:
        tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    except Exception as e:
        write_log(f"[LOOP {loop}] [FLAP] ERROR - không kết nối được OLT "
                  f"{OLT_HOST}:{OLT_PORT}: {e}")
        print(f"[FLAP] ERROR - không kết nối được OLT {OLT_HOST}:{OLT_PORT}: {e}")
        return False

    try:
        olt_login(tn)
        time.sleep(1)
        send_olt_cmd(tn, "enable", 1)
        send_olt_cmd(tn, "terminal length 0", 1)
        send_olt_cmd(tn, "configure terminal", 1)
        send_olt_cmd(tn, f"interface {port}", 1)

        for n in range(1, times + 1):
            out = send_olt_cmd(tn, "shutdown", wait=2)
            if not check(out, "shutdown", n):
                break
            write_log(f"[LOOP {loop}] [FLAP] {n}/{times} {port} DOWN")
            time.sleep(down_sec)

            out = send_olt_cmd(tn, "no shutdown", wait=2)
            if not check(out, "no shutdown", n):
                break
            write_log(f"[LOOP {loop}] [FLAP] {n}/{times} {port} UP")
            done = n

            # lần cuối không chờ up_sec, đã có FLAP_SETTLE_SEC ở main
            if n < times:
                time.sleep(up_sec)

        ok = (done == times)
        send_olt_cmd(tn, "end", 1)
        write_log(f"[LOOP {loop}] [FLAP] "
                  f"{'DONE' if ok else 'INCOMPLETE'} {done}/{times} lần trên {port}")
    except Exception as e:
        write_log(f"[LOOP {loop}] [FLAP] ERROR sau {done}/{times} lần: {e}")
    finally:
        if not ok:
            # port có thể đang bị để DOWN -> vào lại config và bật lên
            try:
                send_olt_cmd(tn, "end", 1)
                send_olt_cmd(tn, "configure terminal", 1)
                send_olt_cmd(tn, f"interface {port}", 1)
                send_olt_cmd(tn, "no shutdown", wait=2)
                send_olt_cmd(tn, "end", 1)
                write_log(f"[LOOP {loop}] [FLAP] đã recover {port} về no shutdown")
            except Exception as e:
                write_log(f"[LOOP {loop}] [FLAP] WARNING - không recover được {port}: {e}")
        tn.close()

    return ok


OLT_IGMP_CMD = "show ip igmp snooping explicit-tracking groups"


def olt_show_igmp_group():
    """Đọc bảng IGMP snooping trên OLT (lệnh này mới có cột Reporter).

    Được gọi TRONG lúc PC còn đang join group, nếu không OLT đã xoá entry.
    """
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
        olt_login(tn)
        time.sleep(1)
        send_olt_cmd(tn, "enable", 1)
        send_olt_cmd(tn, "terminal length 0", 1)
        return send_olt_cmd(tn, OLT_IGMP_CMD, wait=4)
    finally:
        tn.close()


def check_multicast_service(loop):
    """Step check dịch vụ multicast: IP DHCP + PPS # 0 + OLT thấy group."""
    if not MCAST_ENABLE:
        write_log(f"[LOOP {loop}] [MCAST] SKIP - MCAST_ENABLE=False")
        return True

    res = check_multicast(
        MCAST_IFACE, MCAST_GROUP, MCAST_PORT, olt_show_igmp_group,
        sample_sec=MCAST_SAMPLE_SEC,
        min_pps=MCAST_MIN_PPS,
        dhcp_renew=MCAST_DHCP_RENEW,
        dhcp_wait=MCAST_DHCP_WAIT,
        renew_timeout=MCAST_RENEW_TIMEOUT,
    )

    # log gọn từng điều kiện để biết cái nào làm FAIL
    igmp = res["igmp"] or {}
    for label, ok in (("DHCP-IP", res["dhcp_ok"]),
                      ("STREAM-TRAFFIC", res["traffic_ok"]),
                      ("OLT-GROUP", bool(igmp.get("found"))),
                      ("OLT-REPORTER", bool(igmp.get("reporter_match")) and bool(igmp.get("found")))):
        write_log(f"[LOOP {loop}] [MCAST] {'PASS' if ok else 'FAIL'} - {label}")
    write_log(f"[LOOP {loop}] [MCAST] {'PASS' if res['ok'] else 'FAIL'} - "
              f"{mcast_summary(res)}")

    if not igmp.get("found"):
        igmp_status = "FAIL - GROUP NOT FOUND"
    elif not igmp.get("reporter_match"):
        igmp_status = (f"FAIL - REPORTER MISMATCH (OLT={igmp.get('reporters')}, "
                       f"cần {res.get('ip')})")
    else:
        igmp_status = f"PASS - FOUND, Reporter={res.get('ip')}"

    write_result(loop, "MULTICAST", [
        (OLT_IGMP_CMD, res["igmp_output"] or "(không đọc được)",
         [(MCAST_GROUP, igmp_status)]),
    ])
    return res["ok"]


def get_ONU_IP(PON_ID):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    olt_login(tn)
    time.sleep(1)
    send_olt_cmd(tn, "enable", 1)
    time.sleep(1)
    onu_dhcpip_vlan_200=send_olt_cmd(tn, f"show ip dhcp snooping binding vlan 200", wait=3)

    def parse_binding(output, ipv6=False):
        result = []
        pattern = r'^[\da-f:.]+$' if ipv6 else r'^\d+\.\d+\.\d+\.\d+$'
        for line in output.splitlines():
            if not line.strip() or line.startswith('=') or line.startswith('V') \
               or 'IP Address' in line or 'Total' in line:
                continue
            cols = [c.strip() for c in line.split('|')]
            if len(cols) >= 7:
                ip = cols[0].strip()
                subif_name = cols[6].strip()
                if PON_ID in subif_name and re.match(pattern, ip):
                    result.append(ip)
        return result

    onu_ipv4_vlan200 = parse_binding(onu_dhcpip_vlan_200, ipv6=False)
    print(f"IPv4 VLAN 200 for {PON_ID}: {onu_ipv4_vlan200}")
    return onu_ipv4_vlan200
 
def ping_onu(onu_ipv4_vlan200, HOSTS):
    for ip in onu_ipv4_vlan200:
        ping_znid_check(ip, HOSTS)

def check_targets(output, targets, label, expect_present=True):
    results  = []
    all_pass = True

    for t in targets:
        found = t in output
        if expect_present:
            ok     = found
            status = "PASS - FOUND" if ok else "FAIL - NOT FOUND"
        else:
            ok     = not found
            status = "PASS - NOT FOUND" if ok else "FAIL - STILL FOUND"

        if not ok:
            all_pass = False

        results.append((t, status))
        print(f"  [{label}] {status}: {t}")
        write_log(f"[{label}] {status}: {t}")

    return all_pass, results

def verify_provision(loop):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    olt_login(tn)
    time.sleep(1)
    send_olt_cmd(tn, "enable", 1)
    time.sleep(1)
    send_olt_cmd(tn, "terminal length 0", 1)
    time.sleep(1)
    send_olt_cmd(tn, f"show onu firmware version gpon 0/3 10",wait=3)
    out_mac    = send_olt_cmd(tn, f"show mac address-table",wait=3)
    out_pppoe  = send_olt_cmd(tn, f"show pppoe session all",wait=3)
    out_ipv6   = send_olt_cmd(tn, f"show ipv6 dhcp snooping binding",wait=3)
    out_ipdhcp = send_olt_cmd(tn, f"show ip dhcp snooping binding ", wait=3)

    tn.close()

    print(f"\n[LOOP {loop}] === VERIFY PROVISION ===")
    write_log(f"[LOOP {loop}] === VERIFY PROVISION ===")

    ok4, res4 = check_targets(out_mac,    VERIFY_MAC,        "MAC",      expect_present=True)
    ok1, res1 = check_targets(out_pppoe,  VERIFY_PPPOE,     "PPPoE",    expect_present=True)
    ok2, res2 = check_targets(out_ipv6,   VERIFY_IPV6_DHCP, "IPv6-DHCP",expect_present=True)
    ok3, res3 = check_targets(out_ipdhcp, VERIFY_IP_DHCP,   "IP-DHCP",  expect_present=True)

    write_result(loop, "AFTER PROVISION", [
        (f"show pppoe session all ",              out_pppoe,  res1),
        (f"show ipv6 dhcp snooping binding ",     out_ipv6,   res2),
        (f"show ip dhcp snooping binding ",       out_ipdhcp, res3),
        (f"show mac address-table",              out_mac,    res4),
    ])
    return ok1 and ok2 and ok3 and ok4

HOST1 = [
    "-I ppp0.35 192.168.35.1",
    "-I eth0.v200 192.168.200.254",
    "-I eth0.v1234 31.1.1.254",
    "-I eth0.v30 192.168.30.254",
]
HOST2 = [
    "-I ppp0.35 192.168.35.1",
    "-I eth0.v200 192.168.200.254",
    "-I eth0.v1234 31.1.1.254",
    "-I eth0.v30 192.168.30.254",
    "-I eth0.v1234 3031:3031::1",
]

# ==================================================
# MAIN LOOP
# ==================================================
def preflight():
    """Check nhanh trước khi chạy: OLT có tới được không.

    Không có bước này thì OLT chết sẽ đẻ ra 200 loop FAIL với message khó hiểu.
    """
    import socket as _s
    try:
        with _s.create_connection((OLT_HOST, OLT_PORT), timeout=10):
            print(f"[PREFLIGHT] OLT {OLT_HOST}:{OLT_PORT} OK")
            return True
    except Exception as e:
        msg = (f"[PREFLIGHT] KHÔNG kết nối được OLT {OLT_HOST}:{OLT_PORT} ({e}). "
               f"Kiểm tra mạng/route tới OLT rồi chạy lại.")
        print(msg)
        write_log(msg)
        return False


def main():
    print(f"Starting test | Loops: {LOOP_COUNT} | ONU: {ONU_KEYWORD}")
    write_log(f"START | LOOP_COUNT={LOOP_COUNT} | ONU={ONU_KEYWORD}")

    if not preflight():
        return

    for i in range(1, LOOP_COUNT + 1):
        print(f"\n{'=' * 55}")
        print(f"  LOOP {i} / {LOOP_COUNT}")
        print(f"{'=' * 55}")
        write_log(f"LOOP {i} START")

        start  = datetime.now()
        result = "FAIL"

        try:
            # ── 1. FLAPPING PON PORT ────────────────────────────
            # ONU_Provision_cli_shutport.txt cũng chỉ shut/no-shut 1 lần nên
            # đã bỏ, flap_pon_port() lo toàn bộ -> đúng FLAP_TIMES lần.
            # Nếu cần chạy lệnh provision từ file: OLT_CLI("<file>.txt")
            flap_ok = flap_pon_port(i)
            print(f"[WAIT] {FLAP_SETTLE_SEC}s for ONU/services to settle after flapping")
            time.sleep(FLAP_SETTLE_SEC)

            # ── 2. PING Check ────────────────────────────────────
            print("[STEP] Run PING checks")
            GPON_ID="gpon0/3"
            XGS_ID="xgspon0/3"
            gpon_onu_ipv4_vlan200 = get_ONU_IP(GPON_ID)
            # xgs_onu_ipv4_vlan200 = get_ONU_IP(XGS_ID)
            ping_onu(gpon_onu_ipv4_vlan200, HOST1)
            # ping_onu(xgs_onu_ipv4_vlan200, HOST2)
            voip_passed = bool(gpon_onu_ipv4_vlan200)
            if not voip_passed:
                write_log("[VOIP] FAIL - không lấy được IP ONU vlan 200")
            for onu_ip in gpon_onu_ipv4_vlan200:
                voip_res = check_voip_status(onu_ip)
                voip_passed = voip_passed and voip_res["ok"]
                detail = ", ".join(
                    f"Line {n}={s['registration_status'] or 'Unknown'}"
                    for n, s in voip_res["lines"].items()
                ) or voip_res.get("error", "no line parsed")
                write_log(f"[VOIP] {'PASS' if voip_res['ok'] else 'FAIL'} - {onu_ip}: {detail}")
            # check_voip_status(xgs_onu_ipv4_vlan200)

            # ── 3. MULTICAST Check ──────────────────────────────
            mcast_passed = check_multicast_service(i)

            # ── 4. VERIFY PROVISION ──────────────────────────
            print("[WAIT] 5s before OLT verify (provision)...")
            time.sleep(5)
            passed1 = verify_provision(i)
            passed1 = passed1 and voip_passed and flap_ok and mcast_passed
            result = "PASS" if passed1 else "FAIL"

            print("[WAIT] 60s before next loop...")
            time.sleep(60)

        except Exception as e:
            print(f"[ERROR] {e}")
            write_log(f"[ERROR] {e}")

        end      = datetime.now()
        duration = str(end - start)

        RESULT_SUMMARY.append({
            "loop":     i,
            "result":   result,
            "duration": duration,
        })

        write_log(f"LOOP {i} => {result} | duration={duration}")
        print(f"\n  >> LOOP {i} RESULT: {result}  (duration: {duration})")

    # ==================================================
    # FINAL SUMMARY
    # ==================================================
    pass_c = sum(1 for r in RESULT_SUMMARY if r["result"] == "PASS")
    fail_c = len(RESULT_SUMMARY) - pass_c

    summary_lines = [
        "=" * 60,
        f"FINAL SUMMARY  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        f"TOTAL : {len(RESULT_SUMMARY)}",
        f"PASS  : {pass_c}",
        f"FAIL  : {fail_c}",
        "-" * 60,
    ]
    for r in RESULT_SUMMARY:
        line = f"  Loop {r['loop']:>3} | {r['result']:4} | {r['duration']}"
        summary_lines.append(line)

    print("\n" + "\n".join(summary_lines))

    with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines) + "\n")

    write_log(f"DONE | PASS={pass_c} FAIL={fail_c}")


if __name__ == "__main__":
    main()

