
import telnetlib
import time
import re
import os
import subprocess
import queue
import threading
import tkinter as tk
from tkinter import ttk

from ping_check import *

# ==================================================
# OLT INFO
# ==================================================
LOG_DIR = "D:/aging_log"
os.makedirs(LOG_DIR, exist_ok=True)

DEFAULT_LOOP_COUNT = 150
LOOP_COUNT = DEFAULT_LOOP_COUNT
TIMESTAMP    = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE     = os.path.join(LOG_DIR, f"terminal_log_{TIMESTAMP}.txt")
set_ping_log_file(LOG_FILE)

RESULT_SUMMARY = []
OLT_HOST = "192.168.100.247"
OLT_PORT = 23
OLT_USERNAME = "admin"
# OLT_PASSWORD = r"Zhone1234%^&"
OLT_PASSWORD = r"DZSone23456!"

ONU_KEYWORD = "onu002"
ONU_USERNAME   = "admin"
ONU_PASSWORD   = "dzsi"
DEV_PASS     = "g4GwshWN"
ZNID_AP_HOST = "192.168.100.1"
ZNID_5228XG_HOST = "192.168.1.1"
ZNID_2466GN_HOST = "192.168.9.1"

VERIFY_IPV6_DHCP = [
    "gpon0/3/24",
    "xgspon0/3/24",
]
 
VERIFY_IP_DHCP = [
    "gpon0/3/21",
    "gpon0/3/22",
    "gpon0/3/24",
    "gpon0/3/25",
    "xgspon0/3/21",
    "xgspon0/3/22",
    "xgspon0/3/24",
    "xgspon0/3/25",
]
 
VERIFY_MAC = [
    "gpon0/3/21",
    "gpon0/3/22",
    "gpon0/3/23",
    "gpon0/3/24",
    "gpon0/3/25",
    "xgspon0/3/21",
    "xgspon0/3/22",
    "xgspon0/3/23",
    "xgspon0/3/24",
    "xgspon0/3/25",
]

def write_result(loop, phase, section_results):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
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


def write_summary_to_log(summary_lines):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "\n".join(summary_lines) + "\n")


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
def _olt_cli_once(file):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
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
    finally:
        tn.close()


def OLT_CLI(file):
    return retry_telnet(lambda: _olt_cli_once(file), "OLT provision")


def _get_onu_ip_once(PON_ID):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
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
    finally:
        tn.close()


def get_ONU_IP(PON_ID):
    return retry_telnet(
        lambda: _get_onu_ip_once(PON_ID),
        f"OLT get ONU IP {PON_ID}",
    )
 
def ping_ip_reachable(ip: str, count: int = 2, timeout_ms: int = 2000) -> tuple[bool, str]:
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = (result.stdout or "") + (result.stderr or "")
        reachable = (
            "reply from" in output.lower()
            or "bytes=" in output.lower()
            or "ttl=" in output.lower()
        ) and "100% loss" not in output.lower()
        return reachable, output.strip()
    except Exception as exc:
        return False, str(exc)


def _olt_reboot_ont_once(port: str, onu_id: str = "4"):
    """Reboot chỉ ONT đang lỗi trên đúng cổng gpon/xgspon."""
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
        olt_login(tn)
        time.sleep(1)
        send_olt_cmd(tn, "enable", 1)
        time.sleep(1)
        send_olt_cmd(tn, "configure terminal", 1)
        time.sleep(1)
        send_olt_cmd(tn, f"interface {port} 0/3", 1)
        time.sleep(1)
        send_olt_cmd(tn, f"onu reset {onu_id}", 1)
        send_olt_cmd(tn, "y", 1)
        send_olt_cmd(tn, "end", 1)
        send_olt_cmd(tn, "write", 2)
        write_log(f"[OLT-REBOOT] SUCCESS - reboot ONT {onu_id} trên {port} 0/3")
    finally:
        tn.close()


def olt_reboot_ont(port: str, onu_id: str = "4"):
    try:
        retry_telnet(
            lambda: _olt_reboot_ont_once(port, onu_id),
            f"OLT reboot ONT {onu_id} on {port}",
        )
    except Exception as exc:
        write_log(f"[OLT-REBOOT] FAIL - reboot ONT {onu_id} trên {port} 0/3 | error={exc}")


def _olt_fallback_check_once(label: str, onu_ip: str = "") -> str:
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
        olt_login(tn)
        time.sleep(1)
        send_olt_cmd(tn, "enable", 1)
        time.sleep(1)
        send_olt_cmd(tn, "terminal length 0", 1)
        time.sleep(1)

        commands = [
            "show ip dhcp snooping binding vlan 200",
            "show mac address-table",
            "show onu status",
        ]

        output_chunks = []
        for cmd in commands:
            out = send_olt_cmd(tn, cmd, wait=3)
            output_chunks.append(f"--- {cmd} ---\n{out}\n")

        final_output = "\n".join(output_chunks)
        write_log(f"[OLT-FALLBACK] {label} | ONU={onu_ip or 'N/A'}")
        write_log(final_output[:2000])
        return final_output
    finally:
        tn.close()


def olt_fallback_check(label: str, onu_ip: str = "") -> str:
    try:
        return retry_telnet(
            lambda: _olt_fallback_check_once(label, onu_ip),
            f"OLT fallback check {label}",
        )
    except Exception as exc:
        write_log(f"[OLT-FALLBACK] FAIL | {label} | ONU={onu_ip or 'N/A'} | error={exc}")
        return ""


def ping_onu(onu_ipv4_vlan200, HOSTS):
    for ip in onu_ipv4_vlan200:
        reachable, output = ping_ip_reachable(ip, count=10, timeout_ms=2000)
        if not reachable:
            write_log(f"[PING-ONU] FAIL - IP {ip} không ping được trước khi telnet. Output: {output[:300]}")
            olt_fallback_check("ONU VLAN 200 unreachable before telnet", ip)
            olt_reboot_ont("gpon", "4")
            continue

        write_log(f"[PING-ONU] PASS - IP {ip} ping được trước khi telnet")
        ping_znid_check(ip, HOSTS)


def check_targets(output, targets, label, expect_present=True, failures=None):
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
            if failures is not None:
                failures.append(f"{label}: {status} - {t}")

        results.append((t, status))
        print(f"  [{label}] {status}: {t}")
        write_log(f"[{label}] {status}: {t}")

    return all_pass, results

def _verify_provision_once(loop):
    tn = telnetlib.Telnet(OLT_HOST, OLT_PORT, timeout=10)
    try:
        olt_login(tn)
        time.sleep(1)
        send_olt_cmd(tn, "enable", 1)
        time.sleep(1)
        send_olt_cmd(tn, "terminal length 0", 1)
        time.sleep(1)
        send_olt_cmd(tn, f"show onu firmware version gpon 0/3 2",wait=3)
        send_olt_cmd(tn, f"show onu firmware version xgspon 0/3 2",wait=3)
        out_mac    = send_olt_cmd(tn, f"show mac address-table",wait=3)
        out_ipv6   = send_olt_cmd(tn, f"show ipv6 dhcp snooping binding",wait=3)
        out_ipdhcp = send_olt_cmd(tn, f"show ip dhcp snooping binding ", wait=3)
    finally:
        tn.close()

    print(f"\n[LOOP {loop}] === VERIFY PROVISION ===")
    write_log(f"[LOOP {loop}] === VERIFY PROVISION ===")

    failures = []
    ok4, res4 = check_targets(
        out_mac, VERIFY_MAC, "MAC", expect_present=True, failures=failures
    )
    ok2, res2 = check_targets(
        out_ipv6, VERIFY_IPV6_DHCP, "IPv6-DHCP", expect_present=True, failures=failures
    )
    ok3, res3 = check_targets(
        out_ipdhcp, VERIFY_IP_DHCP, "IP-DHCP", expect_present=True, failures=failures
    )

    write_result(loop, "AFTER PROVISION", [
        (f"show ipv6 dhcp snooping binding ",     out_ipv6,   res2),
        (f"show ip dhcp snooping binding ",       out_ipdhcp, res3),
        (f"show mac address-table",              out_mac,    res4),
    ])
    return ok2 and ok3 and ok4, failures


def verify_provision(loop):
    return retry_telnet(
        lambda: _verify_provision_once(loop),
        f"OLT verify loop {loop}",
    )

HOST1 = [
    "-I eth0.v40 192.168.40.254",
    "-I eth0.v200 192.168.200.254",
    "-I ppp0.2021 10.10.10.1",
    "-I eth0.v2022 20.20.20.1",
    "-I eth0.v2211 172.16.221.25",
    "-6 2001:db8:8000::1",
    "-6 2001:db8:20::1",
]
HOST2 = [
    "-I ppp0.35 192.168.35.1",
    "-I eth0.v200 192.168.200.254",
    "-I eth0.v1234 31.1.1.254",
    "-I eth0.v30 192.168.30.254",
    "-I eth0.v1234 3031:3031::1",
]


class RunDashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ONT Provisioning Test Summary")
        self.root.geometry("1180x700")
        self.root.minsize(900, 520)
        self.events = queue.Queue()
        self.completed = 0
        self.passed = 0
        self.failed = 0
        self.total_loops = DEFAULT_LOOP_COUNT
        self.worker = None

        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        container = ttk.Frame(self.root, padding=18)
        container.pack(fill="both", expand=True)
        ttk.Label(
            container,
            text="ONT Provisioning Test",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=(0, 10))
        ttk.Label(controls, text="Loop count:", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
        self.loop_entry = ttk.Entry(controls, width=12)
        self.loop_entry.insert(0, str(DEFAULT_LOOP_COUNT))
        self.loop_entry.pack(side="left")
        self.start_button = ttk.Button(controls, text="Start", command=self._start_test)
        self.start_button.pack(side="left", padx=(8, 0))

        cards = ttk.Frame(container)
        cards.pack(fill="x", pady=(0, 16))
        self.loop_value = self._create_card(cards, "LOOPS DONE", f"0 / {self.total_loops}", 0)
        self.pass_value = self._create_card(cards, "PASS", "0", 1, "#16834a")
        self.fail_value = self._create_card(cards, "FAIL", "0", 2, "#d93636")
        self.state_value = self._create_card(cards, "STATUS", "READY", 3, "#365bd6")

        table_frame = ttk.Frame(container)
        table_frame.pack(fill="both", expand=True)
        columns = ("loop", "result", "duration", "reason")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.table.heading("loop", text="Loop")
        self.table.heading("result", text="Result")
        self.table.heading("duration", text="Duration")
        self.table.heading("reason", text="Failure reason")
        self.table.column("loop", width=70, anchor="center", stretch=False)
        self.table.column("result", width=90, anchor="center", stretch=False)
        self.table.column("duration", width=130, anchor="center", stretch=False)
        self.table.column("reason", width=700, anchor="w")
        self.table.tag_configure("PASS", foreground="#16834a")
        self.table.tag_configure("FAIL", foreground="#c62828")
        vertical_scroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.table.yview
        )
        horizontal_scroll = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set,
        )
        self.table.grid(row=0, column=0, sticky="nsew")
        vertical_scroll.grid(row=0, column=1, sticky="ns")
        horizontal_scroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.root.after(150, self._process_events)

    def _start_test(self):
        if self.worker is not None and self.worker.is_alive():
            return

        try:
            value = int(self.loop_entry.get().strip())
        except ValueError:
            self.state_value.configure(text="INVALID")
            return
        if value <= 0:
            self.state_value.configure(text="INVALID")
            return

        self.total_loops = value
        self.completed = 0
        self.passed = 0
        self.failed = 0
        self.loop_value.configure(text=f"0 / {self.total_loops}")
        self.pass_value.configure(text="0")
        self.fail_value.configure(text="0")
        self.state_value.configure(text="RUNNING")
        self.table.delete(*self.table.get_children())
        self.start_button.configure(state="disabled")
        self.root.update_idletasks()

        global LOOP_COUNT
        LOOP_COUNT = value
        log_path = os.path.join(LOG_DIR, f"terminal_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        set_ping_log_file(log_path)

        self.worker = threading.Thread(target=run_test, args=(self.publish,), daemon=True)
        self.worker.start()

    @staticmethod
    def _create_card(parent, title, value, column, color="#365bd6"):
        card = ttk.LabelFrame(parent, text=title, padding=(14, 10))
        card.grid(row=0, column=column, sticky="nsew", padx=5)
        value_label = ttk.Label(
            card, text=value, font=("Segoe UI", 19, "bold"), foreground=color
        )
        value_label.pack(anchor="center", pady=4)
        parent.columnconfigure(column, weight=1)
        return value_label

    def publish(self, event, payload=None):
        self.events.put((event, payload))

    def _process_events(self):
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break

            if event == "loop":
                self._add_loop_result(payload)
            elif event == "finished":
                self.state_value.configure(text="COMPLETED")
                if self.start_button.winfo_exists():
                    self.start_button.configure(state="normal")

        self.root.after(150, self._process_events)

    def _add_loop_result(self, record):
        self.completed += 1
        if record["result"] == "PASS":
            self.passed += 1
        else:
            self.failed += 1

        self.loop_value.configure(text=f"{self.completed} / {self.total_loops}")
        self.pass_value.configure(text=str(self.passed))
        self.fail_value.configure(text=str(self.failed))
        self.table.insert(
            "",
            "end",
            values=(
                record["loop"],
                record["result"],
                record["duration"],
                "; ".join(record["failure_reasons"]) or "-",
            ),
            tags=(record["result"],),
        )
        self.table.yview_moveto(1)

    def run(self):
        self.root.mainloop()


def run_test(publish):
    loop_count = LOOP_COUNT
    print(f"Starting test | Loops: {loop_count} | ONU: {ONU_KEYWORD}")
    write_log(f"START | LOOP_COUNT={loop_count} | ONU={ONU_KEYWORD}")
    RESULT_SUMMARY.clear()

    for i in range(1, loop_count + 1):
        print(f"\n{'=' * 55}")
        print(f"  LOOP {i} / {loop_count}")
        print(f"{'=' * 55}")
        write_log(f"LOOP {i} START")

        start  = datetime.now()
        result = "FAIL"
        failure_reasons = []

        try:
            # ── 1. PROVISION ────────────────────────────────────
            print("\n[STEP] Run PROVISION commands via CLI")
            OLT_CLI("ONU_Provision_cli.txt")

            znid_checks = [
                ("GPON", ZNID_2466GN_HOST),
                ("XGS", ZNID_5228XG_HOST),
            ]

            # ── 2. Reboot ONTs before running the service checks ──
            for label, device_ip in znid_checks:
                print(f"[STEP] Telnet to {label} ONT {device_ip} and reboot")
                reboot_znid(device_ip)

            print("[WAIT] 180s for ONTs to reboot before service checks")
            time.sleep(200)

            # ── 3. Service Check ────────────────────────────────────
            print("[STEP] Run PING checks")
            GPON_ID = "gpon0/3"
            XGS_ID = "xgspon0/3"
            # gpon_onu_ipv4_vlan200 = get_ONU_IP(GPON_ID)
            # xgs_onu_ipv4_vlan200 = get_ONU_IP(XGS_ID)

            for label, znid_host in znid_checks:
                print(f"[STEP] PING from {label} ZNID {znid_host} to upstream hosts")
                ping_results = ping_znid_check(znid_host, HOST1)
                for host, ping_result in ping_results.items():
                    if ping_result.get("loss_pct", 0) == 100:
                        failure_reasons.append(
                            f"PING {label} {host}: "
                            f"{ping_result.get('loss_pct')}% loss"
                        )
            ping_passed = not failure_reasons

            voip_passed = True
            write_log("[VOIP] START - begin GPON/XGS ONT voice status check")

            for label, device_ip in znid_checks:
                voip_res = check_voip_status(device_ip)
                voip_passed = voip_passed and voip_res["ok"]
                detail = ", ".join(
                    f"Line {n}={s['registration_status'] or 'Unknown'}"
                    for n, s in voip_res["lines"].items()
                ) or voip_res.get("error", "no line parsed")
                write_log(f"[VOIP][{label}] RESULT: {'PASS' if voip_res['ok'] else 'FAIL'} | {detail}")
                if not voip_res["ok"]:
                    failure_reasons.append(f"VOIP {label}: {detail}")

            write_log(
                f"[VOIP] FINAL: {'PASS' if voip_passed else 'FAIL'} | "
                f"GPON={bool(ZNID_2466GN_HOST)} | XGS={bool(ZNID_5228XG_HOST)}"
            )
            # ── 4. VERIFY PROVISION ──────────────────────────
            print("[WAIT] 5s before OLT verify (provision)...")
            time.sleep(5)
            provision_passed, provision_failures = verify_provision(i)
            failure_reasons.extend(provision_failures)
            result = "PASS" if ping_passed and voip_passed and provision_passed else "FAIL"

            print("[WAIT] 60s before next loop...")
            time.sleep(60)

        except Exception as e:
            print(f"[ERROR] {e}")
            write_log(f"[ERROR] {e}")
            failure_reasons.append(str(e))

        end      = datetime.now()
        duration = str(end - start)

        record = {
            "loop":     i,
            "result":   result,
            "duration": duration,
            "failure_reasons": failure_reasons,
        }
        if result == "FAIL" and not failure_reasons:
            record["failure_reasons"].append("One or more checks failed without details")
        RESULT_SUMMARY.append(record)
        publish("loop", record)

        write_log(f"LOOP {i} => {result} | duration={duration}")
        if record["failure_reasons"]:
            write_log(f"LOOP {i} FAILURE REASONS: {'; '.join(record['failure_reasons'])}")
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
        if r["failure_reasons"]:
            summary_lines.append(f"    Reason: {'; '.join(r['failure_reasons'])}")

    print("\n" + "\n".join(summary_lines))

    write_summary_to_log(summary_lines)
    write_log(f"DONE | PASS={pass_c} FAIL={fail_c}")
    publish("finished")


def main():
    dashboard = RunDashboard()
    dashboard.run()


if __name__ == "__main__":
    main()
