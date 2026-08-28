#!/usr/bin/env python3

import telnetlib
import time
import re
import sys
from datetime import datetime

TELNET_PORT  = 23
LOGIN_USER   = "admin"
LOGIN_PASS   = "dzsi"
ENABLE_PASS  = "development"
DEV_PASS     = "g4GwshWN"
PING_COUNT   = 10
TIMEOUT      = 10
PING_TIMEOUT = 30

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg, color=""):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{ts}] {msg}{RESET}")

def send(tn, cmd, delay=1):
    tn.write(cmd.encode("ascii") + b"\n")
    time.sleep(delay)

def read_until(tn, expected, timeout=TIMEOUT):
    try:
        return tn.read_until(expected.encode(), timeout=timeout).decode("ascii", errors="replace")
    except Exception as e:
        log(f"read_until lỗi: {e}", YELLOW)
        return ""

def parse_ping(output):
    m = re.search(
        r"(\d+)\s+packets?\s+transmitted[,\s]+(\d+)\s+(?:packets?\s+)?received"
        r"[,\s]+(\d+)%\s+packet\s+loss",
        output, re.IGNORECASE
    )
    if m:
        sent, recv, loss = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return {"sent": sent, "received": recv, "lost": sent - recv, "loss_pct": loss}

    m2 = re.search(r"(\d+)%\s+packet\s+loss", output, re.IGNORECASE)
    if m2:
        loss = int(m2.group(1))
        recv = PING_COUNT - round(PING_COUNT * loss / 100)
        return {"sent": PING_COUNT, "received": recv, "lost": PING_COUNT - recv, "loss_pct": loss}

    return None


def parse_voip_status(output: str) -> dict:
    lines = {}
    current_line = None

    for raw_line in output.splitlines():
        line_match = re.match(r"\s*Line\s+(\d+)\s*:", raw_line, re.IGNORECASE)
        if line_match:
            current_line = line_match.group(1)
            lines[current_line] = {"registration_status": None}
            continue

        if current_line is None:
            continue

        status_match = re.match(
            r"\s*Registration Status\s*:\s*(\S+)",
            raw_line,
            re.IGNORECASE,
        )
        if status_match:
            lines[current_line]["registration_status"] = status_match.group(1)

    for line in lines.values():
        line["ok"] = line["registration_status"].lower() == "up" if line["registration_status"] else False

    return {
        "lines": lines,
        "ok": bool(lines) and all(line["ok"] for line in lines.values()),
    }


def check_voip_status(onu_ip: str) -> dict:
    log(f"Telnet {onu_ip}:{TELNET_PORT} ...", CYAN)
    tn = telnetlib.Telnet(onu_ip, TELNET_PORT, timeout=TIMEOUT)

    try:
        read_until(tn, "login:", timeout=15)
        send(tn, LOGIN_USER)
        read_until(tn, "Password:")
        send(tn, LOGIN_PASS)
        time.sleep(2)
        tn.read_very_eager()

        send(tn, "enable")
        read_until(tn, "Password:")
        send(tn, ENABLE_PASS)
        time.sleep(1)
        tn.read_very_eager()

        time.sleep(1)
        tn.read_very_eager()

        send(tn, "show voice status", delay=2)
        output = tn.read_very_eager().decode("ascii", errors="replace")
        result = parse_voip_status(output)

        log(output.strip(), YELLOW)
        status = f"{GREEN}OK{RESET}" if result["ok"] else f"{RED}FAIL{RESET}"
        log(f"VOIP registration: {status}", CYAN)
        for line_number, line_status in result["lines"].items():
            log(
                f"Line {line_number}: Registration Status = "
                f"{line_status['registration_status'] or 'Unknown'}",
                GREEN if line_status["ok"] else RED,
            )

        return result
    finally:
        tn.close()


def ping_znid_check(router_ip: str, hosts: list[str]) -> dict:
    results = {}

    log(f"Telnet {router_ip}:{TELNET_PORT} ...", CYAN)
    try:
        tn = telnetlib.Telnet(router_ip, TELNET_PORT, timeout=TIMEOUT)
    except Exception as e:
        log(f"Không kết nối được: {e}", RED)
        sys.exit(1)

    out = read_until(tn, "login:", timeout=15)
    log(out.strip(), YELLOW)
    send(tn, LOGIN_USER)

    out = read_until(tn, "Password:")
    log(out.strip(), YELLOW)
    send(tn, LOGIN_PASS)
    time.sleep(2)
    log(tn.read_very_eager().decode("ascii", errors="replace").strip(), YELLOW)

    send(tn, "enable")
    out = read_until(tn, "Password:")
    log(out.strip(), YELLOW)
    send(tn, ENABLE_PASS)
    time.sleep(1)
    log(tn.read_very_eager().decode("ascii", errors="replace").strip(), YELLOW)

    send(tn, "development")
    out = read_until(tn, "Password:")
    log(out.strip(), YELLOW)
    send(tn, DEV_PASS)
    time.sleep(1)
    log(tn.read_very_eager().decode("ascii", errors="replace").strip(), YELLOW)

    send(tn, "sh", delay=2)
    log(tn.read_very_eager().decode("ascii", errors="replace").strip(), YELLOW)

    # Ping
    print(f"\n{'═'*58}")
    for host in hosts:
        cmd = f"ping -c {PING_COUNT} {host}"
        log(f"$ {cmd}", CYAN)
        send(tn, cmd, delay=0.5)

        output = ""
        deadline = time.time() + PING_TIMEOUT
        while time.time() < deadline:
            chunk = tn.read_very_eager().decode("ascii", errors="replace")
            output += chunk
            if "packet loss" in output.lower():
                break
            time.sleep(1)

        log(output.strip(), YELLOW)

        parsed = parse_ping(output)
        results[host] = parsed if parsed else {
            "sent": PING_COUNT, "received": 0,
            "lost": PING_COUNT, "loss_pct": 100, "parse_error": True
        }

    tn.close()

    # Save Results
    time_test=time.strftime("%Y%m%d-%H%M%S")
    # with open(f"ping_results_{router_ip.replace('.', '_')}_{time_test}.txt", "w") as f:
    #     f.write(f"{'HOST':<22} {'SENT':>5} {'RECV':>5} {'LOST':>5} {'LOSS%':>7}  STATUS\n")
    #     f.write(f"{'-'*58}\n")
    #     for host, r in results.items():
    #         loss = r["loss_pct"]
    #         status = "FAIL" if loss == 100 else "OK"
    #         note = "  (parse error)" if r.get("parse_error") else ""
    #         f.write(f"{host:<22} {r['sent']:>5} {r['received']:>5} {r['lost']:>5} {loss:>6}%  {status}{note}\n")
    print(f"\n{'═'*58}")
    print(f"{BOLD}{'PING RESULT':^58}{RESET}")
    print(f"{'═'*58}")
    print(f"{'HOST':<22} {'SENT':>5} {'RECV':>5} {'LOST':>5} {'LOSS%':>7}  STATUS")
    print(f"{'-'*58}")

    fails = []
    for host, r in results.items():
        loss = r["loss_pct"]
        status = f"{RED}FAIL{RESET}" if loss == 100 else f"{GREEN}OK{RESET}"
        if loss == 100:
            fails.append(host)
        note = "  (parse error)" if r.get("parse_error") else ""
        print(f"{host:<22} {r['sent']:>5} {r['received']:>5} {r['lost']:>5} {loss:>6}%  {status}{note}")

    print(f"{'═'*58}")
    if fails:
        print(f"{RED}{BOLD}FAIL: {', '.join(fails)}{RESET}")
    else:
        print(f"{GREEN}{BOLD}Tất cả host OK{RESET}")
    print(f"{'═'*58}\n")

    return results


if __name__ == "__main__":
    GPON_ONU_IP="192.168.10.1"
    XGS_ONU_IP="192.168.9.1"
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
    ping_znid_check(XGS_ONU_IP, HOST1)
    ping_znid_check(GPON_ONU_IP, HOST2)