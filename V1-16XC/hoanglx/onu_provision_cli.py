
import telnetlib
import time
import re

from ping_check import *

# ==================================================
# OLT INFO
# ==================================================
LOOP_COUNT = 1
TIMESTAMP    = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE     = f"terminal_log_{TIMESTAMP}.txt"
RESULT_FILE  = f"result_{TIMESTAMP}.txt"
SUMMARY_FILE = f"summary_{TIMESTAMP}.txt"

RESULT_SUMMARY = []
OLT_HOST = "192.168.100.248"
OLT_PORT = 23
OLT_USERNAME = "admin"
OLT_PASSWORD = r"Zhone1234%^&"

ONU_KEYWORD = "onu004"
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
def main():
    print(f"Starting test | Loops: {LOOP_COUNT} | ONU: {ONU_KEYWORD}")
    write_log(f"START | LOOP_COUNT={LOOP_COUNT} | ONU={ONU_KEYWORD}")

    for i in range(1, LOOP_COUNT + 1):
        print(f"\n{'=' * 55}")
        print(f"  LOOP {i} / {LOOP_COUNT}")
        print(f"{'=' * 55}")
        write_log(f"LOOP {i} START")

        start  = datetime.now()
        result = "FAIL"

        try:
            # ── 1. PROVISION ────────────────────────────────────
            print("\n[STEP] Run PROVISION commands via CLI")
            OLT_CLI("ONU_Provision_cli.txt")
            print("[WAIT] before checking connectivity from ZNID to Uplink")
            time.sleep(120)

            # ── 2. PING Check ────────────────────────────────────
            print("[STEP] Run PING checks")
            GPON_ID="gpon0/3"
            XGS_ID="xgspon0/3"
            gpon_onu_ipv4_vlan200 = get_ONU_IP(GPON_ID)
            # xgs_onu_ipv4_vlan200 = get_ONU_IP(XGS_ID)
            ping_onu(gpon_onu_ipv4_vlan200, HOST1)
            # ping_onu(xgs_onu_ipv4_vlan200, HOST2)
            voip_passed = bool(gpon_onu_ipv4_vlan200) and all(
                check_voip_status(onu_ip)["ok"]
                for onu_ip in gpon_onu_ipv4_vlan200
            )
            # check_voip_status(xgs_onu_ipv4_vlan200)            

            # ── 2. VERIFY PROVISION ──────────────────────────
            print("[WAIT] 5s before OLT verify (provision)...")
            time.sleep(5)
            passed1 = verify_provision(i)
            passed1 = passed1 and voip_passed
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

