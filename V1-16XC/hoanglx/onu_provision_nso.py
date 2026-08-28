import paramiko
import telnetlib
import time
import re
import sys
from pathlib import Path
from datetime import datetime

from ping_check import *

PROVISION_COMMAND_FILE = "ONU_Provision_nso.txt"

# ==================================================
# CONFIG
# ==================================================
LOOP_COUNT = 1

TIMESTAMP    = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE    = f"terminal_log_nso_{TIMESTAMP}.txt"
RESULT_FILE = f"result_nso_{TIMESTAMP}.txt"

RESULT_SUMMARY = []

# ==================================================
# OLT INFO  (telnet để get IP + verify)
# ==================================================
OLT_HOST = "192.168.100.248"
OLT_PORT = 23

OLT_USERNAME = "admin"
OLT_PASSWORD = r"Zhone1234%^&"

ONU_KEYWORD = "onu007"

# ==================================================
# NSO INFO  
# ==================================================
NSO_HOST = "192.168.100.148"
NSO_PORT = 22

NSO_USERNAME  = "ducpct"
NSO_PASSWORD  = r"zh1234$$"
SUDO_PASSWORD = r"zh1234$$"

# ==================================================
# HOSTS cho ping (từ ZNID lên uplink)
# ==================================================
HOST1 = [
    "-I ppp0.35 192.168.35.1",
    "-I eth0.v200 192.168.200.254",
    "-I eth0.v1234 31.1.1.254",
    "-I eth0.v2211 172.16.221.254",
]
HOST2 = [
    "-I ppp0.35 192.168.35.1",
    "-I eth0.v200 192.168.200.254",
    "-I eth0.v1234 31.1.1.254",
    "-I eth0.v2211 172.16.221.254",
    "-I eth0.v1234 3031:3031::1",
]

# ==================================================
# VERIFY TARGETS — sau PROVISION
# ==================================================
VERIFY_PPPOE = [
    "xgspon0/3_onu007_o_venet1_1_c0035_any",
    "gpon0/3_onu007_o_venet1_1_c0035_any",
]

VERIFY_IPV6_DHCP = [
    "xgspon0/3_onu007_o_venet1_1_c1234_any",
    "gpon0/3_onu007_o_venet1_1_c1234_any",
]

VERIFY_IP_DHCP = [
    "xgspon0/3_onu007_o_venet1_1_c0200_any",
    "gpon0/3_onu007_o_venet1_1_c0200_any",
    "xgspon0/3_onu007_o_venet1_1_c1234_any",
    "gpon0/3_onu007_o_venet1_1_c1234_any",
    "xgspon0/3_onu007_o_venet1_1_c2211_any",
    "gpon0/3_onu007_o_venet1_1_c2211_any",
]

VERIFY_MAC = [
    "xgspon0/3_onu007_o_venet1_1_c0035_any",
    "gpon0/3_onu007_o_venet1_1_c0035_any",
    "xgspon0/3_onu007_o_venet1_1_c0200_any",
    "gpon0/3_onu007_o_venet1_1_c0200_any",
    "xgspon0/3_onu007_o_venet1_1_c1234_any",
    "gpon0/3_onu007_o_venet1_1_c1234_any",
    "xgspon0/3_onu007_o_venet1_1_c2211_any",
    "gpon0/3_onu007_o_venet1_1_c2211_any",
]


# ==================================================
# LOG
# ==================================================
def write_log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


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


# ==================================================
# READ COMMAND FILE
# ==================================================
def read_commands(file_path):
    path = Path(file_path)
    if not path.exists():
        raise Exception(f"Missing file: {file_path}")
    cmds = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            c = line.strip()
            if c and not c.startswith("#") and not c.startswith("!"):
                cmds.append(c)
    return cmds


# ==================================================
# OLT TELNET  (dùng cho get IP & verify)
# ==================================================
def olt_login(tn):
    tn.write(b"\r\n")
    time.sleep(2)

    out = tn.read_very_eager().decode(errors="ignore")
    print(out)
    write_log(out)

    tn.write((OLT_USERNAME + "\r\n").encode())
    time.sleep(1)

    tn.write((OLT_PASSWORD + "\r\n").encode())
    time.sleep(2)

    out = tn.read_very_eager().decode(errors="ignore")
    print(out)
    write_log(out)

    if "incorrect" in out.lower():
        raise Exception("OLT login failed")


def send_olt_cmd(tn, cmd, wait=2):
    print(f"[OLT] {cmd}")
    write_log(f"[OLT CMD] {cmd}")

    tn.write((cmd + "\r\n").encode())
    time.sleep(wait)

    out = tn.read_very_eager().decode(errors="ignore")
    print(out)
    write_log(out)
    return out


# ==================================================
# NSO SSH
# ==================================================
def send_cmd(shell, cmd, timeout=60):
    shell.send(cmd + "\n")

    out   = ""
    start = time.time()

    while True:
        while shell.recv_ready():
            c = shell.recv(65535).decode(errors="ignore")
            out += c
            print(c, end="")
            write_log(c)

        if "commit complete" in out.lower():
            break

        if "#" in out.strip() and time.time() - start > 2:
            break

        if time.time() - start > timeout:
            break

        time.sleep(0.3)

    return out


def connect_nso():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(NSO_HOST, NSO_PORT, NSO_USERNAME, NSO_PASSWORD)

    shell = ssh.invoke_shell()
    time.sleep(1)

    send_cmd(shell, "request system shell", 5)
    shell.send("sudo su -\n")
    time.sleep(1)
    shell.send(SUDO_PASSWORD + "\n")
    time.sleep(1)

    send_cmd(shell, "ncs_cli -C -u admin", 5)
    send_cmd(shell, "config", 2)
    send_cmd(shell, "devices device V1_16XC_2", 2)
    send_cmd(shell, "sync-from", 60)
    send_cmd(shell, "ssh fetch-host-keys", 60)
    send_cmd(shell, "sync-from", 60)
    send_cmd(shell, "devices device V1_16XC_2 config", 2)

    return ssh, shell


def run_nso(shell, file):
    cmds = read_commands(file)
    for c in cmds:
        if c == "commit":
            send_cmd(shell, c, 300)
            print("[INFO] Commit executed")
        else:
            send_cmd(shell, c, 0.05)


# ==================================================
# GET ONU IP  (telnet OLT, đọc dhcp snooping vlan 200)
# ==================================================
def get_ONU_IP(PON_ID):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    olt_login(tn)
    time.sleep(1)
    send_olt_cmd(tn, "enable", 1)
    time.sleep(1)
    onu_dhcpip_vlan_200 = send_olt_cmd(tn, "show ip dhcp snooping binding vlan 200", wait=3)
    tn.close()

    def parse_binding(output, ipv6=False):
        result  = []
        pattern = r'^[\da-f:.]+$' if ipv6 else r'^\d+\.\d+\.\d+\.\d+$'
        for line in output.splitlines():
            if not line.strip() or line.startswith('=') or line.startswith('V') \
               or 'IP Address' in line or 'Total' in line:
                continue
            cols = [c.strip() for c in line.split('|')]
            if len(cols) >= 7:
                ip         = cols[0].strip()
                subif_name = cols[6].strip()
                if PON_ID in subif_name and re.match(pattern, ip):
                    result.append(ip)
        return result

    onu_ipv4_vlan200 = parse_binding(onu_dhcpip_vlan_200, ipv6=False)
    print(f"IPv4 VLAN 200 for {PON_ID}: {onu_ipv4_vlan200}")
    write_log(f"IPv4 VLAN 200 for {PON_ID}: {onu_ipv4_vlan200}")
    return onu_ipv4_vlan200


def ping_onu(onu_ipv4_vlan200, HOSTS):
    for ip in onu_ipv4_vlan200:
        ping_znid_check(ip, HOSTS)


# ==================================================
# VERIFY HELPER
# ==================================================
def check_targets(output, targets, label, expect_present=True):
    """
    expect_present=True  → PASS nếu target TÌM THẤY   (dùng sau PROVISION)
    expect_present=False → PASS nếu target KHÔNG TỒN TẠI (dùng sau REMOVE)
    """
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


# ==================================================
# VERIFY PROVISION  (telnet OLT, grep theo onu007)
# ==================================================
def verify_provision(loop):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    olt_login(tn)
    time.sleep(1)
    send_olt_cmd(tn, "enable", 1)
    time.sleep(1)
    send_olt_cmd(tn, "terminal length 0", 1)
    time.sleep(1)

    out_pppoe  = send_olt_cmd(tn, f"show pppoe session all | grep {ONU_KEYWORD}",          wait=3)
    out_ipv6   = send_olt_cmd(tn, f"show ipv6 dhcp snooping binding | grep {ONU_KEYWORD}", wait=3)
    out_ipdhcp = send_olt_cmd(tn, f"show ip dhcp snooping binding | grep {ONU_KEYWORD}",   wait=3)
    out_mac    = send_olt_cmd(tn, f"show mac address-table | grep {ONU_KEYWORD}",          wait=3)
    tn.close()

    print(f"\n[LOOP {loop}] === VERIFY PROVISION ===")
    write_log(f"[LOOP {loop}] === VERIFY PROVISION ===")

    ok4, res4 = check_targets(out_mac,    VERIFY_MAC,       "MAC",       expect_present=True)
    ok1, res1 = check_targets(out_pppoe,  VERIFY_PPPOE,     "PPPoE",     expect_present=True)
    ok2, res2 = check_targets(out_ipv6,   VERIFY_IPV6_DHCP, "IPv6-DHCP", expect_present=True)
    ok3, res3 = check_targets(out_ipdhcp, VERIFY_IP_DHCP,   "IP-DHCP",   expect_present=True)

    write_result(loop, "AFTER PROVISION", [
        (f"show pppoe session all | grep {ONU_KEYWORD}",          out_pppoe,  res1),
        (f"show ipv6 dhcp snooping binding | grep {ONU_KEYWORD}", out_ipv6,   res2),
        (f"show ip dhcp snooping binding | grep {ONU_KEYWORD}",   out_ipdhcp, res3),
        (f"show mac address-table | grep {ONU_KEYWORD}",          out_mac,    res4),
    ])
    return ok1 and ok2 and ok3 and ok4


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
        ssh    = None

        try:
            # ── 1. Kết nối NSO ──────────────────────────────────
            ssh, shell = connect_nso()

            # ── 2. PROVISION qua NSO ─────────────────────────────
            print("\n[STEP] Run PROVISION commands via NSO")
            run_nso(shell, PROVISION_COMMAND_FILE)
            print("[WAIT] 6 min before checking connectivity from ZNID to Uplink")
            time.sleep(360)

            # ── 3. PING Check ────────────────────────────────────
            print("[STEP] Run PING checks")
            GPON_ID = "gpon0/3"
            XGS_ID  = "xgspon0/3"
            gpon_onu_ipv4_vlan200 = get_ONU_IP(GPON_ID)
            xgs_onu_ipv4_vlan200  = get_ONU_IP(XGS_ID)
            ping_onu(gpon_onu_ipv4_vlan200, HOST2)
            # ping_onu(xgs_onu_ipv4_vlan200,  HOST1)
            check_voip_status(gpon_onu_ipv4_vlan200)
            

            # ── 4. VERIFY PROVISION ──────────────────────────────
            print("[WAIT] 5s before OLT verify (provision)...")
            time.sleep(5)
            passed1 = verify_provision(i)
            result  = "PASS" if passed1 else "FAIL"

            print("[WAIT] 60s before next loop...")
            time.sleep(60)

        except Exception as e:
            print(f"[ERROR] {e}")
            write_log(f"[ERROR] {e}")
        finally:
            if ssh is not None:
                try:
                    ssh.close()
                except Exception:
                    pass

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

    # Ghi summary vào cuối RESULT_FILE (không tạo file summary riêng nữa)
    with open(RESULT_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(summary_lines) + "\n")

    write_log(f"DONE | PASS={pass_c} FAIL={fail_c}")


if __name__ == "__main__":
    main()