#!/usr/bin/env python3

import telnetlib
import time
import re
import os
import subprocess
from datetime import datetime

LOG_DIR = "D:/aging_log"
os.makedirs(LOG_DIR, exist_ok=True)
PING_LOG_FILE = os.path.join(
    LOG_DIR,
    f"ping_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
)

TELNET_PORT  = 23
LOGIN_USER   = "admin"
LOGIN_PASS   = "dzsi"
ENABLE_PASS  = "development"
DEV_PASS     = "g4GwshWN"
PING_COUNT   = 5
TIMEOUT      = 10
PING_TIMEOUT = 30
VOIP_OK_STATES = {"up", "registered"}

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg, color=""):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{ts}] {msg}{RESET}")


def is_retryable_telnet_error(error):
    message = str(error).lower()
    return any(
        message_text in message
        for message_text in (
            "an existing connection was forcibly closed by the remote host",
            "an established connection was aborted by the software in your host machine",
        )
    )


def retry_telnet(operation, label, attempts=3):
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if not is_retryable_telnet_error(exc):
                raise
            if attempt == attempts:
                log(f"{label}: telnet connection closed after {attempts} attempts: {exc}", RED)
                raise
            log(
                f"{label}: telnet connection closed; reconnecting "
                f"({attempt + 1}/{attempts}) ...",
                YELLOW,
            )
            time.sleep(2)


def ping_host_icmp(device_ip: str, count: int = 5, timeout_ms: int = 2000) -> tuple[bool, str]:
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), device_ip]
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


def get_log_path(file_name: str) -> str:
    return os.path.join(LOG_DIR, file_name)


def set_ping_log_file(path: str) -> None:
    global PING_LOG_FILE
    PING_LOG_FILE = path


def write_ping_log(msg: str) -> None:
    with open(PING_LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"{msg.rstrip()}\n")


def write_voip_log(msg: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    write_ping_log(f"[{timestamp}] {msg}")


def send(tn, cmd, delay=1):
    tn.write(cmd.encode("ascii") + b"\n")
    time.sleep(delay)

def read_until(tn, expected, timeout=TIMEOUT):
    try:
        return tn.read_until(expected.encode(), timeout=timeout).decode("ascii", errors="replace")
    except Exception as e:
        if is_retryable_telnet_error(e):
            raise
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


def read_until_any(tn, patterns, timeout):
    """Đọc tới khi thấy 1 trong các pattern. Trả về (buffer, pattern khớp hoặc None)."""
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="replace")
        except EOFError:
            break
        if chunk:
            buf += chunk
            for p in patterns:
                if p in buf:
                    return buf, p
        time.sleep(0.2)
    return buf, None


def onu_login_enable(tn):
    read_until(tn, "login:", timeout=15)
    send(tn, LOGIN_USER, delay=0.5)
    read_until(tn, "Password:", timeout=10)
    send(tn, LOGIN_PASS, delay=0.5)
    read_until_any(tn, [">", "#"], timeout=10)

    send(tn, "enable", delay=0.5)
    _, hit = read_until_any(tn, ["Password:", "#"], timeout=5)
    if hit == "Password:":
        send(tn, ENABLE_PASS, delay=0.5)
        read_until_any(tn, ["#"], timeout=10)


def run_onu_cmd(tn, cmd, prompt="#", timeout=30, quiet=1.5):
    """Gửi lệnh và đọc tới khi prompt quay lại (thay vì 1 lần read_very_eager)."""
    send(tn, cmd, delay=0.3)
    out = ""
    last_data = time.time()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="replace")
        except EOFError:
            break
        if chunk:
            out += chunk
            last_data = time.time()
        elif out.rstrip().endswith(prompt) and (time.time() - last_data) > quiet:
            break
        time.sleep(0.2)
    return out


def parse_voip_status(output: str) -> dict:
    """Parse output của lệnh `show voice status`.

    Một thiết bị ONT/ONU có thể đồng thời là cùng một box vật lý. Đòi hỏi không phải
    tất cả các ONT/ONU đều có voice; vì vậy việc parse chỉ đánh dấu là OK khi tất cả
    các line đều ở trạng thái registered/up.
    """
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
        status = (line["registration_status"] or "").lower()
        line["ok"] = status in VOIP_OK_STATES

    return {
        "lines": lines,
        "ok": bool(lines) and all(line["ok"] for line in lines.values()),
    }


def _check_voip_status_once(device_ip: str) -> dict:
    """Kiểm tra trạng thái voice của ONT/ONU trên thiết bị đã được telnet tới.

    Tên hàm được giữ nguyên để tránh phá vỡ call site cũ, nhưng về mặt ý nghĩa thì
    `device_ip` là IP hoặc host của thiết bị ONT/ONU/ZNID đang kiểm tra voice.
    """
    reachable, ping_output = ping_host_icmp(device_ip, count=5, timeout_ms=2000)
    if reachable:
        log(f"PING before telnet to {device_ip}: OK (5 ICMP packets)", GREEN)
        write_voip_log(f"PING before telnet to {device_ip}: OK (5 ICMP packets)")
    else:
        log(f"PING before telnet to {device_ip}: FAIL | {ping_output[:300]}", RED)
        write_voip_log(f"PING before telnet to {device_ip}: FAIL | {ping_output[:300]}")

    log(f"Telnet {device_ip}:{TELNET_PORT} ...", CYAN)
    try:
        tn = telnetlib.Telnet(device_ip, TELNET_PORT, timeout=TIMEOUT)
    except Exception as e:
        if is_retryable_telnet_error(e):
            raise
        log(f"VOIP: cannot connect to {device_ip}: {e}", RED)
        write_voip_log(f"VOIP: cannot connect to {device_ip}: {e}")
        raise ConnectionError(f"Cannot telnet to ZNID {device_ip}: {e}") from e

    try:
        onu_login_enable(tn)

        output = run_onu_cmd(tn, "show voice status")
        result = parse_voip_status(output)
        result["output"] = output

        log(output.strip(), YELLOW)
        if not result["lines"]:
            log("VOIP: không parse được dòng 'Line N:' nào từ output trên", RED)
        status = f"{GREEN}OK{RESET}" if result["ok"] else f"{RED}FAIL{RESET}"
        log(f"VOIP registration: {status}", CYAN)
        write_voip_log(f"VOIP registration: {'OK' if result['ok'] else 'FAIL'}")
        for line_number, line_status in result["lines"].items():
            line_message = (
                f"Line {line_number}: Registration Status = "
                f"{line_status['registration_status'] or 'Unknown'}"
            )
            log(
                line_message,
                GREEN if line_status["ok"] else RED,
            )
            write_voip_log(line_message)

        return result
    finally:
        tn.close()


def check_voip_status(device_ip: str) -> dict:
    return retry_telnet(
        lambda: _check_voip_status_once(device_ip),
        f"VOIP {device_ip}",
    )


def _reboot_znid_once(device_ip: str) -> None:
    reachable, ping_output = ping_host_icmp(device_ip, count=5, timeout_ms=2000)
    if reachable:
        log(f"PING before telnet reboot {device_ip}: OK (5 ICMP packets)", GREEN)
    else:
        log(f"PING before telnet reboot {device_ip}: FAIL | {ping_output[:300]}", RED)

    log(f"Telnet {device_ip}:{TELNET_PORT} để reboot ...", CYAN)
    tn = telnetlib.Telnet(device_ip, TELNET_PORT, timeout=TIMEOUT)
    try:
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
        send(tn, "reboot")
        log(f"Sent Reboot to {device_ip}", CYAN)
    finally:
        tn.close()


def reboot_znid(device_ip: str) -> None:
    return retry_telnet(
        lambda: _reboot_znid_once(device_ip),
        f"Reboot ZNID {device_ip}",
    )


def _ping_znid_check_once(router_ip: str, hosts: list[str]) -> dict:
    results = {}

    reachable, ping_output = ping_host_icmp(router_ip, count=5, timeout_ms=2000)
    if reachable:
        log(f"PING before telnet to {router_ip}: OK (5 ICMP packets)", GREEN)
    else:
        log(f"PING before telnet to {router_ip}: FAIL | {ping_output[:300]}", RED)

    log(f"Telnet {router_ip}:{TELNET_PORT} ...", CYAN)
    try:
        tn = telnetlib.Telnet(router_ip, TELNET_PORT, timeout=TIMEOUT)
    except Exception as e:
        if is_retryable_telnet_error(e):
            raise
        log(f"Cannot telnet to ZNID {router_ip}: {e}", RED)
        raise ConnectionError(f"Cannot telnet to ZNID {router_ip}: {e}") from e

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

    print(f"\n{'═'*58}")
    print(f"{BOLD}{'PING RESULT':^58}{RESET}")
    print(f"{'═'*58}")
    print(f"{'HOST':<22} {'SENT':>5} {'RECV':>5} {'LOST':>5} {'LOSS%':>7}  STATUS")
    print(f"{'-'*58}")

    fails = []
    result_lines = [
        "═" * 58,
        f"{'PING RESULT':^58}",
        "═" * 58,
        f"{'HOST':<22} {'SENT':>5} {'RECV':>5} {'LOST':>5} {'LOSS%':>7}  STATUS",
        "-" * 58,
    ]
    for host, r in results.items():
        loss = r["loss_pct"]
        status = f"{RED}FAIL{RESET}" if loss == 100 else f"{GREEN}OK{RESET}"
        if loss == 100:
            fails.append(host)
        note = "  (parse error)" if r.get("parse_error") else ""
        print(f"{host:<22} {r['sent']:>5} {r['received']:>5} {r['lost']:>5} {loss:>6}%  {status}{note}")
        plain_status = "FAIL" if loss == 100 else "OK"
        result_lines.append(
            f"{host:<22} {r['sent']:>5} {r['received']:>5} {r['lost']:>5} "
            f"{loss:>6}%  {plain_status}{note}"
        )

    print(f"{'═'*58}")
    if fails:
        print(f"{RED}{BOLD}FAIL: {', '.join(fails)}{RESET}")
        result_lines.append(f"FAIL: {', '.join(fails)}")
    else:
        print(f"{GREEN}{BOLD}Tất cả host OK{RESET}")
        result_lines.append("Tất cả host OK")
    print(f"{'═'*58}\n")
    result_lines.append("═" * 58)
    write_ping_log(f"[PING] ZNID {router_ip}\n" + "\n".join(result_lines))

    return results


def ping_znid_check(router_ip: str, hosts: list[str]) -> dict:
    return retry_telnet(
        lambda: _ping_znid_check_once(router_ip, hosts),
        f"PING ZNID {router_ip}",
    )


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