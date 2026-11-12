# -*- coding: utf-8 -*-
"""
DHCP Client Emulator
Performs a full DORA sequence (Discover → Offer → Request → ACK)
on a selected network interface with a configurable MAC address.

Requires: scapy >= 2.4  +  Npcap (Windows) or libpcap (Linux/macOS)
Run as Administrator / root for raw socket access.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import threading
import random
import queue as _queue
import re
import socket

try:
    from GPON_NSO_Generator import GPONConfigGenerator as _GPONConfigGenerator
    _GPON_OK = True
except Exception:
    _GPON_OK = False

try:
    from GPON_NSO_XML_RPC_Generator import GPONRPCGenerator as _GPONRPCGenerator
    _GPON_RPC_OK = True
except Exception:
    _GPON_RPC_OK = False

try:
    from NETCONF_RPC_Sender_Tab import NETCONFRPCSender as _NETCONFRPCSender
    _RPC_SENDER_OK = True
except Exception:
    _RPC_SENDER_OK = False

try:
    from scapy.all import conf, sendp, AsyncSniffer
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import (
        IPv6, ICMPv6ND_RS, ICMPv6ND_RA,
        ICMPv6NDOptPrefixInfo, ICMPv6NDOptMTU,
    )
    from scapy.layers.l2 import Ether, Dot1Q
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

try:
    from scapy.layers.dhcp6 import (
        DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply, DHCP6_Renew,
        DHCP6OptClientId, DHCP6OptServerId,
        DHCP6OptIA_NA, DHCP6OptIAAddress,
        DHCP6OptElapsedTime, DHCP6OptOptReq, DHCP6OptDNSServers,
        DUID_LL,
    )
    _DHCPv6_OK = True
except ImportError:
    _DHCPv6_OK = False


try:
    # Try scapy.all first (works on Scapy 2.5+)
    from scapy.all import PPPoED, PPPoE  # noqa: F811
    _PPPOE_OK = True
except ImportError:
    try:
        from scapy.layers.l2 import PPPoED, PPPoE  # type: ignore
        _PPPOE_OK = True
    except ImportError:
        _PPPOE_OK = False


# ─── Ethernet helper ──────────────────────────────────────────────────────────

def build_eth(src: str, dst: str = "ff:ff:ff:ff:ff:ff",
              vlan_id=None, pcp: int = 0):
    """Build Ethernet frame with optional 802.1Q tag."""
    eth = Ether(src=src, dst=dst)
    if vlan_id:
        eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)
    return eth


# ─── Color helpers ────────────────────────────────────────────────────────────

def _mix(hex_color: str, factor: float, target: int = 255) -> str:
    """Lighten (target=255) or darken (target=0) a hex color by factor 0‒1."""
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    r = int(r + (target - r) * factor)
    g = int(g + (target - g) * factor)
    b = int(b + (target - b) * factor)
    return f"#{max(0,min(255,r)):02x}{max(0,min(255,g)):02x}{max(0,min(255,b)):02x}"


# ─── Rounded button (Canvas-based) ────────────────────────────────────────────

class RoundedButton(tk.Canvas):
    """A button drawn on a Canvas with rounded corners."""

    def __init__(self, parent, text, command=None,
                 bg="#2563eb", fg="white",
                 radius=8, font=("Segoe UI", 9, "bold"),
                 padx=14, pady=6, canvas_bg=None, **kw):
        import tkinter.font as _tkf
        f  = _tkf.Font(family=font[0], size=abs(font[1]),
                       weight=font[2] if len(font) > 2 else "normal")
        tw = f.measure(text)
        th = f.metrics("linespace")
        self._bw = tw + padx * 2
        self._bh = th + pady * 2

        cbg = canvas_bg or (parent.cget("bg") if hasattr(parent, "cget") else "#f4f7fb")
        super().__init__(parent, width=self._bw, height=self._bh,
                         bg=cbg, highlightthickness=0, cursor="hand2", **kw)

        self._bg   = bg
        self._hov  = _mix(bg, 0.15, 255)   # lighten on hover
        self._act  = _mix(bg, 0.15, 0)     # darken on press
        self._fg   = fg
        self._r    = radius
        self._font = font
        self._text = text
        self._cmd  = command

        self._draw(self._bg)
        self.bind("<Enter>",           lambda _: self._draw(self._hov))
        self.bind("<Leave>",           lambda _: self._draw(self._bg))
        self.bind("<ButtonPress-1>",   lambda _: self._draw(self._act))
        self.bind("<ButtonRelease-1>", self._release)

    def _draw(self, color):
        self.delete("all")
        w, h, r = self._bw, self._bh, self._r
        # Fill rounded rectangle using arcs + rectangles
        kw = dict(fill=color, outline=color)
        self.create_arc(    0,     0, r*2,   r*2, start= 90, extent=90, **kw)
        self.create_arc(w-r*2,     0,   w,   r*2, start=  0, extent=90, **kw)
        self.create_arc(w-r*2, h-r*2,   w,     h, start=270, extent=90, **kw)
        self.create_arc(    0, h-r*2, r*2,     h, start=180, extent=90, **kw)
        self.create_rectangle(  r, 0, w-r,   h, **kw)
        self.create_rectangle(  0, r,   w, h-r, **kw)
        self.create_text(w//2, h//2, text=self._text,
                         fill=self._fg, font=self._font)

    def _release(self, _):
        self._draw(self._bg)
        if self._cmd:
            self._cmd()

    def pack(self, **kw):
        super().pack(**kw)
        return self

    def grid(self, **kw):
        super().grid(**kw)
        return self


# ─── Helpers ──────────────────────────────────────────────────────────────────

def random_mac():
    mac = [random.randint(0, 255) for _ in range(6)]
    mac[0] = (mac[0] & 0xFE) | 0x02   # locally administered, unicast
    return ':'.join(f'{b:02x}' for b in mac)


def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', '').replace('-', ''))


def increment_mac(base_mac: str, n: int) -> str:
    """Return base_mac + n (wraps within 48-bit space, keeps locally-administered bit)."""
    val = int.from_bytes(mac_to_bytes(base_mac), 'big')
    val = (val + n) & 0xFFFFFFFFFFFF
    return ':'.join(f'{b:02x}' for b in val.to_bytes(6, 'big'))


def get_iface_list():
    """Return list of (display_label, scapy_name) tuples."""
    items = []
    if not _SCAPY_OK:
        return items
    try:
        for name, iface in conf.ifaces.items():
            desc = getattr(iface, 'description', '') or getattr(iface, 'name', name)
            ip   = getattr(iface, 'ip', '')
            label = f"{desc}  [{ip}]" if ip else desc
            items.append((label, name))
    except Exception:
        pass
    return items


def lease_fmt(seconds):
    if not isinstance(seconds, int):
        return str(seconds)
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    return f"{seconds}s  ({h}h {m}m {s}s)"


def mac_to_link_local(mac: str) -> str:
    """Convert MAC to IPv6 link-local address (EUI-64, fe80::/64)."""
    b = [int(x, 16) for x in mac.replace('-', ':').split(':')]
    b[0] ^= 0x02
    return "fe80::{:02x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}".format(
        b[0], b[1], b[2], b[3], b[4], b[5])


# ─── Main app ─────────────────────────────────────────────────────────────────

class DHCPClientEmulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Testing Tools Emulator (thao.do@zhone.com)")
        self.root.geometry("1200x820")
        self.root.minsize(900, 650)

        self._stop_event       = threading.Event()   # DHCP tab only
        self._thread           = None                 # DHCP worker thread
        self._pppoe_stop_event = threading.Event()    # PPPoE tab only (independent of DHCP)
        self._pppoe_thread     = None                 # PPPoE worker thread
        self._capture_target = "dhcp"   # tracks which tab started the current capture
        self._threads       = []
        self._log_queue     = _queue.Queue()
        self._iface_map     = {}
        self._mc_success    = 0
        self._mc_total      = 0
        # DHCP session state
        self._client_leases    = {}
        self._dhcp_client_rows = {}
        # PPPoE session state
        self._pppoe_leases      = {}
        self._pppoe_client_rows = {}
        # IGMP state
        self._igmp_leases        = {}   # client_idx → {ip, mac, iface, vlan_id, pcp, groups}
        self._igmp_client_rows   = {}   # client_idx → parent iid
        self._igmp_group_rows_dict = {} # (client_idx, "group:port") → child iid
        self.igmp_tree          = None
        self._igmp_stop_event     = threading.Event()
        self._igmp_current_iface  = ""   # interface selected when Start is clicked
        self._igmp_video_events     = {}   # "group_ip:port" → stop Event
        self._igmp_pause_events     = {}   # "group_ip:port" → pause Event
        self._igmp_responder_events = {}   # client_idx → stop Event
        self._igmp_stats_sniffer= None
        self._igmp_pkt_counts   = {}   # group_ip → [count, bytes, last_bytes, bitrate]
        self._igmp_video_nb     = None
        self.igmp_group_rows    = []   # list of (frame, ip_var, port_var,
                                       #          mode_var, src_var)
        # IGMPv3 (RFC 3376) per-group source filter:
        #   "group_ip:port" → {"mode": "include"|"exclude", "srcs": [ip, …]}
        self._igmp_group_filters = {}
        self._igmp_v3_widgets    = []  # widgets enabled only when IGMPv3 chosen
        # Packet capture state
        self._capture_sniffer  = None
        self._captured_packets = []
        self._capture_count    = 0
        # UI references set in _build_ui
        self._proto_nb     = None
        self._pane         = None
        self._sash_pos     = {}   # {"DHCP": px, "PPPoE": px} — per-tab sash
        self._prev_tab     = None
        self.igmp_log      = None  # Exchange Log widget inside IGMP tab
        self._dhcp_tbl_frm = None
        self._pppoe_tbl_frm= None
        self.dhcp_tree     = None
        self.pppoe_tree    = None

        self._apply_styles()
        self._build_ui()
        self._refresh_ifaces()
        self.root.after(50, self._on_proto_tab)  # set correct state for initial tab
        self._setup_scroll()                      # enable hover-scroll on all panes
        self.root.after(50, self._poll_log)

        if not _SCAPY_OK:
            self._log("[ERROR] scapy is not installed.\n"
                      "        Run:  pip install scapy\n"
                      "        Also install Npcap (Windows): https://npcap.com\n", "err")

    # ── Light "Sky" palette ────────────────────────────────────────────────────
    C_BASE   = "#f4f7fb"   # window & frame background
    C_SURF   = "#ffffff"   # card / LabelFrame surface
    C_INPUT  = "#edf1f7"   # input field background
    C_BORDER = "#c8d4e3"   # borders
    C_TEXT   = "#1a2d44"   # primary text
    C_SUB    = "#4a6278"   # secondary labels
    C_DIM    = "#8fa3b8"   # muted / hint text
    C_ACCENT = "#1a6fc4"   # blue accent (headings)
    C_GREEN  = "#1a7a3c"   # success
    C_RED    = "#c0392b"   # error
    C_ORANGE = "#c05a00"   # send / warning
    C_YELLOW = "#8a6a00"   # attention
    C_TEAL   = "#007a6a"   # recv
    C_MANTLE = "#1a1f2e"   # log terminal (keep dark)

    def _apply_styles(self):
        s = ttk.Style()
        s.theme_use("clam")

        BG, SURF   = self.C_BASE, self.C_SURF
        INPUT      = self.C_INPUT
        BORDER, FG = self.C_BORDER, self.C_TEXT
        DIM, ACC   = self.C_DIM, self.C_ACCENT

        self.root.configure(bg=BG)

        # ── Global defaults ───────────────────────────────────────────────────
        s.configure(".",
                    background=BG, foreground=FG,
                    troughcolor=BORDER, bordercolor=BORDER,
                    darkcolor=BG, lightcolor=BG,
                    selectbackground=ACC, selectforeground=SURF,
                    font=("Segoe UI", 9), relief="flat")

        # ── Structural ────────────────────────────────────────────────────────
        s.configure("TFrame",       background=BG)
        s.configure("TPanedwindow", background=BG, sashrelief="flat", sashwidth=5)

        s.configure("TLabelframe",
                    background=SURF, bordercolor=BORDER,
                    relief="solid", padding=(10, 6))
        s.configure("TLabelframe.Label",
                    background=SURF, foreground=ACC,
                    font=("Segoe UI", 9, "bold"), padding=(4, 0))

        s.configure("TSeparator", background=BORDER)

        # ── Input widgets ─────────────────────────────────────────────────────
        _inp = dict(fieldbackground=INPUT, foreground=FG, bordercolor=BORDER,
                    lightcolor=INPUT, darkcolor=INPUT, padding=(4, 3))

        s.configure("TEntry",   insertcolor=FG, **_inp)
        s.map("TEntry",   bordercolor=[("focus", ACC)])

        s.configure("TCombobox", arrowcolor=self.C_SUB,
                    selectbackground=INPUT, selectforeground=FG, **_inp)
        s.map("TCombobox",
              fieldbackground=[("readonly", INPUT)],
              foreground=[("readonly", FG)],
              bordercolor=[("focus", ACC)],
              arrowcolor=[("active", ACC)])

        s.configure("TSpinbox", arrowcolor=self.C_SUB, **_inp)
        s.map("TSpinbox", bordercolor=[("focus", ACC)])

        # ── Labels ────────────────────────────────────────────────────────────
        s.configure("TLabel",      background=BG,   foreground=FG)
        s.configure("Head.TLabel", background=BG,   foreground=FG,
                    font=("Segoe UI", 9, "bold"))
        s.configure("Val.TEntry",  font=("Consolas", 9))

        # ── Plain ttk buttons (Clear Log / Clear Table, etc.) ─────────────────
        _tbtn = dict(font=("Segoe UI", 9), padding=(9, 5), relief="flat",
                     bordercolor=BORDER, darkcolor=INPUT, lightcolor=INPUT)
        s.configure("TButton",        background=INPUT, foreground=FG, **_tbtn)
        s.map("TButton", background=[("active", BORDER), ("pressed", self.C_DIM)])
        s.configure("Action.TButton", background=INPUT, foreground=FG, **_tbtn)
        s.map("Action.TButton", background=[("active", BORDER)])

        # Unused named styles (kept so old references don't crash)
        for name, bg in (("Start.TButton",   "#27ae60"),
                         ("Stop.TButton",    "#e74c3c"),
                         ("Release.TButton", "#e67e22"),
                         ("Renew.TButton",   "#2980b9"),
                         ("Ping.TButton",    "#8e44ad")):
            s.configure(name, background=bg, foreground="white", **_tbtn)

        # ── Toggle / Check / Radio ────────────────────────────────────────────
        for w in ("TRadiobutton", "TCheckbutton"):
            s.configure(w, background=BG, foreground=FG,
                        indicatorcolor=INPUT, indicatorrelief="flat")
            s.map(w,
                  background=[("active", BG)],
                  foreground=[("active", ACC)],
                  indicatorcolor=[("selected", ACC), ("active", INPUT)])

        # ── Scrollbar ─────────────────────────────────────────────────────────
        s.configure("TScrollbar",
                    background=INPUT, troughcolor=BG,
                    arrowcolor=DIM,   bordercolor=BG,
                    darkcolor=BG,     lightcolor=BG,
                    arrowsize=10,     relief="flat")
        s.map("TScrollbar", background=[("active", BORDER), ("pressed", ACC)])

        # ── Treeview ──────────────────────────────────────────────────────────
        s.configure("Treeview",
                    background=SURF, foreground=FG,
                    fieldbackground=SURF, bordercolor=BORDER,
                    rowheight=24, font=("Consolas", 9))
        s.configure("Treeview.Heading",
                    background=INPUT, foreground=ACC,
                    font=("Segoe UI", 9, "bold"),
                    relief="flat", padding=(4, 5))
        s.map("Treeview",
              background=[("selected", "#d0e4f7")],
              foreground=[("selected", self.C_TEXT)])
        s.map("Treeview.Heading",
              background=[("active", BORDER)],
              foreground=[("active", self.C_ACCENT)])

    def _build_ui(self):
        _cbg = self.C_BASE

        # ── Main PanedWindow: notebook (top) ↕ DHCP/PPPoE area (bottom) ─────────
        self._main_pane = ttk.PanedWindow(self.root, orient="vertical")
        self._main_pane.pack(fill="both", expand=True, padx=8, pady=(8, 2))

        # ── Protocol Notebook (each tab is fully self-contained) ──────────────
        self._proto_nb = ttk.Notebook(self._main_pane)
        self._main_pane.add(self._proto_nb, weight=1)
        self._proto_nb.bind("<<NotebookTabChanged>>", self._on_proto_tab)

        def _common_rows(frm, iface_var, iface_cb_attr,
                         mac_var, vlan_var, pcp_var,
                         num_cli_var, interval_var, mac_mode_var,
                         ping_tgt_var, ping_cnt_var, ping_int_var):
            """Build Interface→Ping rows into frm, store widgets on self."""
            frm.columnconfigure(1, weight=1)
            ttk.Label(frm, text="Interface:", style="Head.TLabel").grid(
                row=0, column=0, sticky="w", padx=(0, 8), pady=3)
            cb = ttk.Combobox(frm, textvariable=iface_var, state="readonly", width=50)
            cb.grid(row=0, column=1, sticky="ew", pady=3)
            setattr(self, iface_cb_attr, cb)
            ttk.Button(frm, text="↻", command=self._refresh_ifaces, width=3).grid(
                row=0, column=2, padx=(6, 0))

            ttk.Label(frm, text="Client MAC:", style="Head.TLabel").grid(
                row=1, column=0, sticky="w", padx=(0, 8), pady=3)
            ttk.Entry(frm, textvariable=mac_var, width=20,
                      font=("Consolas", 9)).grid(row=1, column=1, sticky="w", pady=3)
            ttk.Button(frm, text="Random MAC",
                       command=lambda v=mac_var: v.set(random_mac()),
                       style="Action.TButton").grid(row=1, column=2, padx=(6, 0))

            ttk.Label(frm, text="VLAN ID (802.1Q):", style="Head.TLabel").grid(
                row=2, column=0, sticky="w", padx=(0, 8), pady=3)
            vr = ttk.Frame(frm)
            vr.grid(row=2, column=1, columnspan=2, sticky="w", pady=3)
            ttk.Entry(vr, textvariable=vlan_var, width=8,
                      font=("Consolas", 9)).pack(side="left")
            ttk.Label(vr, text="  (1–4094, blank=no tag)",
                      foreground=self.C_DIM).pack(side="left")
            ttk.Label(vr, text="   PCP:", style="Head.TLabel").pack(
                side="left", padx=(10, 4))
            ttk.Spinbox(vr, textvariable=pcp_var, from_=0, to=7, width=4).pack(side="left")

            ttk.Label(frm, text="Clients:", style="Head.TLabel").grid(
                row=3, column=0, sticky="w", padx=(0, 8), pady=3)
            cr = ttk.Frame(frm)
            cr.grid(row=3, column=1, columnspan=2, sticky="w", pady=3)
            ttk.Spinbox(cr, textvariable=num_cli_var,
                        from_=1, to=255, width=6).pack(side="left")
            ttk.Label(cr, text="   Interval (ms):", style="Head.TLabel").pack(
                side="left", padx=(12, 4))
            ttk.Entry(cr, textvariable=interval_var, width=6,
                      font=("Consolas", 9)).pack(side="left")
            ttk.Label(cr, text="between starts",
                      foreground=self.C_DIM).pack(side="left", padx=(4, 0))

            ttk.Label(frm, text="MAC mode:", style="Head.TLabel").grid(
                row=4, column=0, sticky="w", padx=(0, 8), pady=3)
            mr = ttk.Frame(frm)
            mr.grid(row=4, column=1, columnspan=2, sticky="w", pady=3)
            ttk.Radiobutton(mr, text="Sequential",
                            variable=mac_mode_var, value="sequential").pack(side="left")
            ttk.Radiobutton(mr, text="Random each client",
                            variable=mac_mode_var, value="random").pack(
                side="left", padx=(12, 0))

            ttk.Label(frm, text="Ping target:", style="Head.TLabel").grid(
                row=5, column=0, sticky="w", padx=(0, 8), pady=3)
            pr = ttk.Frame(frm)
            pr.grid(row=5, column=1, columnspan=2, sticky="w", pady=3)
            ttk.Entry(pr, textvariable=ping_tgt_var, width=18,
                      font=("Consolas", 9)).pack(side="left")
            ttk.Label(pr, text="  (blank=gateway)  Count:",
                      foreground=self.C_DIM).pack(side="left")
            ttk.Spinbox(pr, textvariable=ping_cnt_var,
                        from_=1, to=10, width=4).pack(side="left")
            ttk.Label(pr, text="  Interval (ms):",
                      foreground=self.C_DIM).pack(side="left", padx=(8, 4))
            ttk.Spinbox(pr, textvariable=ping_int_var,
                        from_=0, to=10000, increment=100, width=6).pack(side="left")

        # ──── GPON NSO Tab (embedded directly) ───────────────────────────────
        gpon_frm = ttk.Frame(self._proto_nb)
        self._proto_nb.add(gpon_frm, text="  GPON NSO ")

        if _GPON_OK:
            _GPONConfigGenerator(gpon_frm)
        else:
            ttk.Label(gpon_frm,
                      text="⚠  Không tìm thấy GPON_NSO_Generator.py\n"
                           "Đặt file đó cùng thư mục với tool này.",
                      style="Head.TLabel").pack(padx=24, pady=24, anchor="w")

        # ──── GPON RPC Tab (embedded directly) ───────────────────────────────
        gpon_rpc_frm = ttk.Frame(self._proto_nb)
        self._proto_nb.add(gpon_rpc_frm, text="  GPON RPC ")

        if _GPON_RPC_OK:
            _GPONRPCGenerator(gpon_rpc_frm)
        else:
            ttk.Label(gpon_rpc_frm,
                      text="⚠  Không tìm thấy GPON_NSO_XML_RPC_Generator.py\n"
                           "Đặt file đó cùng thư mục với tool này.",
                      style="Head.TLabel").pack(padx=24, pady=24, anchor="w")

        # ──── RPC Sender Tab (NETCONF, embedded directly) ────────────────────
        rpc_sender_frm = ttk.Frame(self._proto_nb)
        self._proto_nb.add(rpc_sender_frm, text="  RPC Sender ")

        if _RPC_SENDER_OK:
            _NETCONFRPCSender(rpc_sender_frm)
        else:
            ttk.Label(rpc_sender_frm,
                      text="⚠  Không tìm thấy NETCONF_RPC_Sender_Tab.py\n"
                           "Đặt file đó cùng thư mục với tool này.",
                      style="Head.TLabel").pack(padx=24, pady=24, anchor="w")

        # ──── DHCP Tab ────────────────────────────────────────────────────────
        _dhcp_tab = ttk.Frame(self._proto_nb)
        self._proto_nb.add(_dhcp_tab, text="  DHCP Client  ")
        dhcp_frm = self._scrollable_frame(_dhcp_tab)

        self.iface_var       = tk.StringVar()
        self.mac_var         = tk.StringVar(value=random_mac())
        self.vlan_var        = tk.StringVar(value="")
        self.pcp_var         = tk.StringVar(value="0")
        self.num_clients_var = tk.StringVar(value="1")
        self.interval_var    = tk.StringVar(value="200")
        self.mac_mode_var    = tk.StringVar(value="sequential")
        self.ping_target_var   = tk.StringVar(value="")
        self.ping_count_var    = tk.StringVar(value="3")
        self.ping_interval_var = tk.StringVar(value="1000")

        _common_rows(dhcp_frm, self.iface_var, "iface_cb",
                     self.mac_var, self.vlan_var, self.pcp_var,
                     self.num_clients_var, self.interval_var, self.mac_mode_var,
                     self.ping_target_var, self.ping_count_var, self.ping_interval_var)

        ttk.Label(dhcp_frm, text="IP Version:", style="Head.TLabel").grid(
            row=6, column=0, sticky="w", padx=(0, 8), pady=3)
        ver_row = ttk.Frame(dhcp_frm)
        ver_row.grid(row=6, column=1, columnspan=2, sticky="w", pady=3)
        self.dhcp_version_var = tk.StringVar(value="v4")
        ttk.Radiobutton(ver_row, text="DHCPv4  (IPv4)", variable=self.dhcp_version_var,
                        value="v4").pack(side="left", padx=(0, 16))
        ttk.Radiobutton(ver_row, text="DHCPv6  (IPv6)", variable=self.dhcp_version_var,
                        value="v6").pack(side="left")

        ttk.Label(dhcp_frm, text="Hostname:", style="Head.TLabel").grid(
            row=7, column=0, sticky="w", padx=(0, 8), pady=3)
        self.hostname_var = tk.StringVar(value="MikroTik")
        ttk.Entry(dhcp_frm, textvariable=self.hostname_var, width=20,
                  font=("Consolas", 9)).grid(row=7, column=1, sticky="w", pady=3)

        ttk.Label(dhcp_frm, text="Padding:", style="Head.TLabel").grid(
            row=8, column=0, sticky="w", padx=(0, 8), pady=3)
        pad_row = ttk.Frame(dhcp_frm)
        pad_row.grid(row=8, column=1, columnspan=2, sticky="w", pady=3)
        self.pad_var  = tk.StringVar(value="auto")
        self.pad_mode = tk.StringVar(value="auto")
        ttk.Radiobutton(pad_row, text="Auto (300 B)", variable=self.pad_mode,
                        value="auto", command=self._on_pad_mode).pack(side="left")
        ttk.Radiobutton(pad_row, text="Manual:", variable=self.pad_mode,
                        value="manual", command=self._on_pad_mode).pack(
            side="left", padx=(12, 4))
        self.pad_entry = ttk.Entry(pad_row, textvariable=self.pad_var, width=6,
                                   font=("Consolas", 9), state="disabled")
        self.pad_entry.pack(side="left")
        ttk.Label(pad_row, text="bytes",
                  foreground=self.C_DIM).pack(side="left", padx=(4, 0))

        ttk.Label(dhcp_frm, text="Timeout / Retry:", style="Head.TLabel").grid(
            row=9, column=0, sticky="w", padx=(0, 8), pady=3)
        tr = ttk.Frame(dhcp_frm)
        tr.grid(row=9, column=1, columnspan=2, sticky="w", pady=3)
        self.timeout_var = tk.StringVar(value="5")
        ttk.Entry(tr, textvariable=self.timeout_var, width=5).pack(side="left")
        ttk.Label(tr, text="s   Retry:", style="Head.TLabel").pack(
            side="left", padx=(4, 4))
        self.retry_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tr, text="Enable", variable=self.retry_var).pack(side="left")
        ttk.Label(tr, text="  Max:", style="Head.TLabel").pack(side="left", padx=(8, 4))
        self.max_retry_var = tk.StringVar(value="4")
        ttk.Spinbox(tr, textvariable=self.max_retry_var,
                    from_=1, to=8, width=4).pack(side="left")
        ttk.Label(tr, text="  (4→8→64s ±1s)",
                  foreground=self.C_DIM).pack(side="left", padx=(6, 0))

        dhcp_btn = tk.Frame(dhcp_frm, bg=_cbg)
        dhcp_btn.grid(row=10, column=0, columnspan=3, sticky="w", pady=(8, 4))
        RoundedButton(dhcp_btn, "▶  Start Binding", command=self._start_dora,
                      bg="#27ae60", canvas_bg=_cbg).pack(side="left", padx=(0, 4))
        RoundedButton(dhcp_btn, "■  Stop", command=self._stop_dora,
                      bg="#e74c3c", canvas_bg=_cbg).pack(side="left", padx=(0, 8))
        tk.Frame(dhcp_btn, bg=self.C_BORDER, width=1).pack(
            side="left", fill="y", padx=(0, 8), pady=3)
        RoundedButton(dhcp_btn, "↩ Release", command=self._release_selected,
                      bg="#e67e22", canvas_bg=_cbg).pack(side="left", padx=(0, 4))
        RoundedButton(dhcp_btn, "↻ Renew", command=self._renew_selected,
                      bg="#2980b9", canvas_bg=_cbg).pack(side="left")

        # ──── PPPoE Tab ───────────────────────────────────────────────────────
        _pppoe_tab = ttk.Frame(self._proto_nb)
        self._proto_nb.add(_pppoe_tab, text="  PPPoE Client  ")
        pppoe_frm = self._scrollable_frame(_pppoe_tab)

        self.pppoe_iface_var       = tk.StringVar()
        self.pppoe_mac_var         = tk.StringVar(value=random_mac())
        self.pppoe_vlan_var        = tk.StringVar(value="")
        self.pppoe_pcp_var         = tk.StringVar(value="0")
        self.pppoe_num_clients_var = tk.StringVar(value="1")
        self.pppoe_interval_var    = tk.StringVar(value="200")
        self.pppoe_mac_mode_var    = tk.StringVar(value="sequential")
        self.pppoe_ping_target_var   = tk.StringVar(value="")
        self.pppoe_ping_count_var    = tk.StringVar(value="3")
        self.pppoe_ping_interval_var = tk.StringVar(value="1000")

        _common_rows(pppoe_frm, self.pppoe_iface_var, "pppoe_iface_cb",
                     self.pppoe_mac_var, self.pppoe_vlan_var, self.pppoe_pcp_var,
                     self.pppoe_num_clients_var, self.pppoe_interval_var,
                     self.pppoe_mac_mode_var,
                     self.pppoe_ping_target_var, self.pppoe_ping_count_var,
                     self.pppoe_ping_interval_var)

        ttk.Label(pppoe_frm, text="Service Name:", style="Head.TLabel").grid(
            row=6, column=0, sticky="w", padx=(0, 8), pady=3)
        svc_row = ttk.Frame(pppoe_frm)
        svc_row.grid(row=6, column=1, columnspan=2, sticky="w", pady=3)
        self.pppoe_svc_var = tk.StringVar(value="")
        ttk.Entry(svc_row, textvariable=self.pppoe_svc_var, width=24,
                  font=("Consolas", 9)).pack(side="left")
        ttk.Label(svc_row, text="  (blank = accept any)",
                  foreground=self.C_DIM).pack(side="left")

        ttk.Label(pppoe_frm, text="Username:", style="Head.TLabel").grid(
            row=7, column=0, sticky="w", padx=(0, 8), pady=3)
        self.pppoe_user_var = tk.StringVar(value="")
        ttk.Entry(pppoe_frm, textvariable=self.pppoe_user_var, width=24,
                  font=("Consolas", 9)).grid(row=7, column=1, sticky="w", pady=3)

        ttk.Label(pppoe_frm, text="Password:", style="Head.TLabel").grid(
            row=8, column=0, sticky="w", padx=(0, 8), pady=3)
        self.pppoe_pass_var = tk.StringVar(value="")
        ttk.Entry(pppoe_frm, textvariable=self.pppoe_pass_var, width=24,
                  font=("Consolas", 9), show="●").grid(
            row=8, column=1, sticky="w", pady=3)

        ttk.Label(pppoe_frm, text="Auth method:", style="Head.TLabel").grid(
            row=9, column=0, sticky="w", padx=(0, 8), pady=3)
        auth_row = ttk.Frame(pppoe_frm)
        auth_row.grid(row=9, column=1, columnspan=2, sticky="w", pady=3)
        self.pppoe_auth_var = tk.StringVar(value="auto")
        for val, lbl in (("auto", "Auto"), ("pap", "PAP"),
                         ("chap", "CHAP"), ("none", "None")):
            ttk.Radiobutton(auth_row, text=lbl,
                            variable=self.pppoe_auth_var, value=val).pack(
                side="left", padx=(0, 12))

        ttk.Label(pppoe_frm, text="MRU / Timeout:", style="Head.TLabel").grid(
            row=10, column=0, sticky="w", padx=(0, 8), pady=3)
        mru_row = ttk.Frame(pppoe_frm)
        mru_row.grid(row=10, column=1, columnspan=2, sticky="w", pady=3)
        self.pppoe_mru_var = tk.StringVar(value="1492")
        ttk.Entry(mru_row, textvariable=self.pppoe_mru_var, width=7,
                  font=("Consolas", 9)).pack(side="left")
        ttk.Label(mru_row, text="   Timeout (s):",
                  style="Head.TLabel").pack(side="left", padx=(14, 4))
        self.pppoe_timeout_var = tk.StringVar(value="10")
        ttk.Entry(mru_row, textvariable=self.pppoe_timeout_var,
                  width=6, font=("Consolas", 9)).pack(side="left")

        pppoe_btn = tk.Frame(pppoe_frm, bg=_cbg)
        pppoe_btn.grid(row=11, column=0, columnspan=3, sticky="w", pady=(8, 4))
        RoundedButton(pppoe_btn, "▶  Connect", command=self._start_pppoe,
                      bg="#16a085", canvas_bg=_cbg).pack(side="left", padx=(0, 4))
        RoundedButton(pppoe_btn, "■  Stop", command=self._stop_pppoe,
                      bg="#e74c3c", canvas_bg=_cbg).pack(side="left", padx=(0, 8))
        tk.Frame(pppoe_btn, bg=self.C_BORDER, width=1).pack(
            side="left", fill="y", padx=(0, 8), pady=3)
        RoundedButton(pppoe_btn, "✕ Disconnect (PADT)",
                      command=self._pppoe_disconnect_selected,
                      bg="#c0392b", canvas_bg=_cbg).pack(side="left")

        # ──── IGMP Multicast Tab ─────────────────────────────────────────────
        igmp_frm = ttk.Frame(self._proto_nb)
        self._proto_nb.add(igmp_frm, text="  IGMP Multicast  ")

        # Variables declared here, widgets built into igmp_frm's PanedWindow below
        self.igmp_iface_var        = tk.StringVar()
        self.igmp_mac_var          = tk.StringVar(value=random_mac())
        self.igmp_vlan_var         = tk.StringVar(value="")
        self.igmp_pcp_var          = tk.StringVar(value="0")
        self.igmp_num_cli_var      = tk.StringVar(value="1")
        self.igmp_interval_var     = tk.StringVar(value="200")
        self.igmp_mac_mode_var     = tk.StringVar(value="sequential")
        self.igmp_dhcp_timeout_var = tk.StringVar(value="5")
        self.igmp_version_var      = tk.StringVar(value="v2")
        self.igmp_retry_var        = tk.BooleanVar(value=True)
        self.igmp_max_retry_var    = tk.StringVar(value="4")

        # ── DHCP/PPPoE area — bottom pane of _main_pane (added dynamically) ─────
        self._dhcp_area = tk.Frame(self._main_pane, bg=_cbg)

        # ── Shared bottom bar ─────────────────────────────────────────────────
        bot = tk.Frame(self._dhcp_area, bg=_cbg)
        bot.pack(fill="x", padx=8, pady=(2, 4))
        RoundedButton(bot, "Clear Log",   command=self._clear_log,
                      bg="#5d6d7e", canvas_bg=_cbg).pack(side="left", padx=(0, 4))
        RoundedButton(bot, "Clear Table", command=self._reset_table,
                      bg="#5d6d7e", canvas_bg=_cbg).pack(side="left", padx=(0, 8))
        tk.Frame(bot, bg=self.C_BORDER, width=1).pack(
            side="left", fill="y", padx=(0, 8), pady=3)
        RoundedButton(bot, "⊙ Ping Selected", command=self._ping_selected,
                      bg="#8e44ad", canvas_bg=_cbg).pack(side="left")
        self._summary_var = tk.StringVar(value="")
        tk.Label(bot, textvariable=self._summary_var,
                 font=("Segoe UI", 9, "bold"),
                 fg=self.C_GREEN, bg=_cbg).pack(side="right", padx=(0, 4))

        # ── Capture bar ──────────────────────────────────────────────────────
        cap_bar = tk.Frame(self._dhcp_area, bg=_cbg)
        cap_bar.pack(fill="x", padx=8, pady=(0, 4))

        self.capture_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(cap_bar, text="Auto-capture",
                        variable=self.capture_var).pack(side="left")
        ttk.Label(cap_bar, text="  BPF Filter:",
                  style="Head.TLabel").pack(side="left", padx=(12, 4))
        self.capture_filter_var = tk.StringVar(value="")
        ttk.Entry(cap_bar, textvariable=self.capture_filter_var,
                  width=30, font=("Consolas", 9)).pack(side="left")
        ttk.Label(cap_bar, text="  (blank = all)",
                  foreground=self.C_DIM).pack(side="left")

        self.capture_status_var = tk.StringVar(value="○ Not started")
        tk.Label(cap_bar, textvariable=self.capture_status_var,
                 font=("Segoe UI", 9, "bold"),
                 fg=self.C_ACCENT, bg=_cbg).pack(side="left", padx=(16, 0))

        RoundedButton(cap_bar, "💾 Save PCAP", command=self._save_pcap,
                      bg="#2c7a7b", canvas_bg=_cbg).pack(side="right")

        # ── PanedWindow ───────────────────────────────────────────────────────
        self._pane = ttk.PanedWindow(self._dhcp_area, orient="vertical")
        self._pane.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # DHCP table
        self._dhcp_tbl_frm = ttk.LabelFrame(self._pane, text=" DHCP Client List ", padding=4)
        self._build_dhcp_table(self._dhcp_tbl_frm)
        self._pane.add(self._dhcp_tbl_frm, weight=1)

        # PPPoE table (not in pane yet, swapped in on tab change)
        self._pppoe_tbl_frm = ttk.LabelFrame(self._pane, text=" PPPoE Client List ", padding=4)
        self._build_pppoe_table(self._pppoe_tbl_frm)

        # DHCP Exchange Log (initially in pane)
        self._dhcp_log_frm = ttk.LabelFrame(self._pane, text=" Exchange Log — DHCP Client ", padding=4)
        self._build_log(self._dhcp_log_frm, "dhcp")
        self._pane.add(self._dhcp_log_frm, weight=2)

        # PPPoE Exchange Log (not in pane yet, swapped in on tab change)
        self._pppoe_log_frm = ttk.LabelFrame(self._pane, text=" Exchange Log — PPPoE Client ", padding=4)
        self._build_log(self._pppoe_log_frm, "pppoe")

        # Active tree pointers (start with DHCP)
        self.client_tree  = self.dhcp_tree
        self._client_rows = self._dhcp_client_rows

        # ── IGMP area (hidden when DHCP/PPPoE/GPON tab active) ───────────────
        # 3-pane PanedWindow lives INSIDE the IGMP notebook tab frame
        # → no separate area, no empty space
        self._igmp_pane = ttk.PanedWindow(igmp_frm, orient="vertical")
        _igmp_pane = self._igmp_pane
        _igmp_pane.pack(fill="both", expand=True, padx=4, pady=(2, 4))

        # ── Config pane (draggable) ───────────────────────────────────────
        _igmp_cfg_outer = ttk.LabelFrame(_igmp_pane,
                                         text=" IGMP Configuration ")
        _igmp_cfg = self._scrollable_frame(_igmp_cfg_outer)
        _igmp_cfg.columnconfigure(1, weight=1)
        _igmp_ping_tgt = tk.StringVar(value="")
        _igmp_ping_cnt = tk.StringVar(value="3")
        _igmp_ping_int = tk.StringVar(value="1000")
        _common_rows(_igmp_cfg, self.igmp_iface_var, "igmp_iface_cb",
                     self.igmp_mac_var, self.igmp_vlan_var, self.igmp_pcp_var,
                     self.igmp_num_cli_var, self.igmp_interval_var,
                     self.igmp_mac_mode_var, _igmp_ping_tgt, _igmp_ping_cnt,
                     _igmp_ping_int)

        ttk.Label(_igmp_cfg, text="DHCP Timeout:", style="Head.TLabel").grid(
            row=6, column=0, sticky="w", padx=(0, 8), pady=3)
        _igmp_to_row = ttk.Frame(_igmp_cfg)
        _igmp_to_row.grid(row=6, column=1, columnspan=2, sticky="w", pady=3)
        ttk.Entry(_igmp_to_row, textvariable=self.igmp_dhcp_timeout_var,
                  width=5, font=("Consolas", 9)).pack(side="left")
        ttk.Label(_igmp_to_row, text="s   IGMP version:",
                  style="Head.TLabel").pack(side="left", padx=(10, 6))
        for v, l in (("v2", "IGMPv2"), ("v3", "IGMPv3")):
            ttk.Radiobutton(_igmp_to_row, text=l,
                            variable=self.igmp_version_var, value=v,
                            command=self._igmp_on_version_change).pack(
                side="left", padx=(0, 10))

        ttk.Label(_igmp_cfg, text="DHCP Retry:", style="Head.TLabel").grid(
            row=7, column=0, sticky="w", padx=(0, 8), pady=3)
        _igmp_retry_row = ttk.Frame(_igmp_cfg)
        _igmp_retry_row.grid(row=7, column=1, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(_igmp_retry_row, text="Enable",
                        variable=self.igmp_retry_var).pack(side="left")
        ttk.Label(_igmp_retry_row, text="   Max:", style="Head.TLabel").pack(
            side="left", padx=(12, 4))
        ttk.Spinbox(_igmp_retry_row, textvariable=self.igmp_max_retry_var,
                    from_=1, to=8, width=4).pack(side="left")
        ttk.Label(_igmp_retry_row, text="  (4→8→16→32→64s ±1s)",
                  foreground=self.C_DIM).pack(side="left", padx=(6, 0))

        ttk.Label(_igmp_cfg, text="Multicast Groups:",
                  style="Head.TLabel").grid(
            row=8, column=0, sticky="nw", padx=(0, 8), pady=6)
        self.igmp_groups_frame = ttk.Frame(_igmp_cfg)
        self.igmp_groups_frame.grid(row=8, column=1, columnspan=2,
                                    sticky="w", pady=3)
        self._igmp_add_group_row()
        self._igmp_on_version_change()   # grey out v3 source filter for IGMPv2

        ttk.Button(_igmp_cfg, text="+ Add Group", style="Action.TButton",
                   command=self._igmp_add_group_row).grid(
            row=9, column=1, sticky="w", pady=(2, 4))

        _igmp_btn = tk.Frame(_igmp_cfg, bg=_cbg)
        _igmp_btn.grid(row=10, column=0, columnspan=3, sticky="w", pady=(4, 2))
        RoundedButton(_igmp_btn, "▶  Start", command=self._start_igmp,
                      bg="#0288d1", canvas_bg=_cbg).pack(side="left", padx=(0, 4))
        RoundedButton(_igmp_btn, "■  Stop", command=self._stop_igmp,
                      bg="#e74c3c", canvas_bg=_cbg).pack(side="left")

        _igmp_pane.add(_igmp_cfg_outer, weight=1)

        # ── Client table pane ─────────────────────────────────────────────
        _igmp_tbl = ttk.LabelFrame(_igmp_pane,
                                   text=" IGMP Client List ", padding=4)
        # Hierarchical tree: parent=client, child=group
        _igmp_cols = ("label", "ip", "status", "pkts", "pps", "bitrate")
        self.igmp_tree = ttk.Treeview(_igmp_tbl, columns=_igmp_cols,
                                      show="tree headings", selectmode="extended")
        self.igmp_tree.heading("#0",      text="#")
        self.igmp_tree.column( "#0",      width=45,  anchor="w", stretch=False)
        self.igmp_tree.heading("label",   text="MAC / Group")
        self.igmp_tree.column( "label",   width=155, anchor="w", stretch=False)
        self.igmp_tree.heading("ip",      text="DHCP IP")
        self.igmp_tree.column( "ip",      width=110, anchor="w", stretch=False)
        self.igmp_tree.heading("status",  text="Status")
        self.igmp_tree.column( "status",  width=95,  anchor="w", stretch=False)
        self.igmp_tree.heading("pkts",    text="Rx Pkts")
        self.igmp_tree.column( "pkts",    width=70,  anchor="e", stretch=False)
        self.igmp_tree.heading("pps",     text="PPS")
        self.igmp_tree.column( "pps",     width=62,  anchor="e", stretch=False)
        self.igmp_tree.heading("bitrate", text="Bitrate")
        self.igmp_tree.column( "bitrate", width=90,  anchor="e", stretch=False)
        _igmp_vsb = ttk.Scrollbar(_igmp_tbl, orient="vertical",
                                   command=self.igmp_tree.yview)
        self.igmp_tree.configure(yscrollcommand=_igmp_vsb.set)
        _igmp_vsb.pack(side="right", fill="y")
        self.igmp_tree.pack(fill="both", expand=True)
        self._configure_tree_tags(self.igmp_tree)
        _igmp_pane.add(_igmp_tbl, weight=1)

        # ── Video Monitor pane ────────────────────────────────────────────
        vid_frm = ttk.LabelFrame(_igmp_pane,
                                  text=" Video Monitor ", padding=4)
        self._igmp_video_nb = ttk.Notebook(vid_frm)
        self._igmp_video_nb.pack(fill="both", expand=True)
        # Placeholder shown before any group is monitored
        _ph = ttk.Frame(self._igmp_video_nb)
        self._igmp_video_nb.add(_ph, text="  No groups  ")
        ttk.Label(_ph, text="Nhấn ▶ Start để join group và hiển thị video.",
                  foreground=self.C_DIM).pack(expand=True)
        _igmp_pane.add(vid_frm, weight=3)

        # ── Exchange Log pane ─────────────────────────────────────────────────
        igmp_log_frm = ttk.LabelFrame(_igmp_pane, text=" Exchange Log — IGMP Multicast ", padding=4)
        self._build_log(igmp_log_frm, "igmp")
        _igmp_pane.add(igmp_log_frm, weight=1)

    # ── Protocol tab helpers ──────────────────────────────────────────────────

    def _setup_scroll(self):
        """Global mouse-wheel handler: scroll the widget under the cursor,
        not just the focused one.  Works for Treeview, Text, and PanedWindow."""

        def _on_wheel(event):
            # Find the widget the cursor is hovering over
            try:
                wx = self.root.winfo_pointerx()
                wy = self.root.winfo_pointery()
                target = self.root.winfo_containing(wx, wy)
            except Exception:
                return

            steps = -1 * (event.delta // 120)   # +1 = down, -1 = up

            # Walk up until we hit a scrollable widget or a PanedWindow sash
            w = target
            while w:
                cls = type(w).__name__
                if cls in ("Text", "Treeview", "Listbox"):
                    w.yview_scroll(steps, "units")
                    return "break"
                if cls == "Canvas" and str(w) in getattr(self, "_scroll_canvases", set()):
                    w.yview_scroll(steps, "units")
                    return "break"
                if cls == "PanedWindow":
                    # Scroll the nearest sash when hovering in a PanedWindow
                    try:
                        orient = w.cget("orient")
                        n = len(w.panes()) - 1
                        if n <= 0:
                            break
                        cursor = wy - w.winfo_rooty() if orient == "vertical" \
                                 else wx - w.winfo_rootx()
                        best_i = min(range(n),
                                     key=lambda i: abs(w.sashpos(i) - cursor))
                        w.sashpos(best_i, max(0, w.sashpos(best_i) + steps * 20))
                    except Exception:
                        pass
                    return "break"
                try:
                    w = w.master
                except Exception:
                    break

        self.root.bind_all("<MouseWheel>", _on_wheel, add="+")

    def _scrollable_frame(self, parent):
        """Wrap a vertical-scroll canvas inside parent. Returns inner ttk.Frame.
        Mouse wheel scrolling is bound directly to canvas + all child widgets."""
        canvas = tk.Canvas(parent, bg=self.C_BASE, highlightthickness=0)
        vsb    = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner  = ttk.Frame(canvas)

        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        canvas.configure(yscrollcommand=vsb.set)
        canvas.bind("<Configure>",
                    lambda e, wi=win_id: canvas.itemconfig(wi, width=e.width))

        def _scroll(e, c=canvas):
            c.yview_scroll(-1 * (e.delta // 120), "units")
            return "break"

        def _bind_all_children(w):
            """Bind <MouseWheel> to w and every descendant."""
            try:
                w.bind("<MouseWheel>", _scroll, add="+")
            except Exception:
                pass
            for child in w.winfo_children():
                _bind_all_children(child)

        def _on_inner_configure(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Re-bind every time new widgets are added to inner frame
            _bind_all_children(inner)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<MouseWheel>", _scroll, add="+")

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        return inner

    def _build_dhcp_table(self, parent):
        cols = ("#", "MAC", "Status", "Assigned IP", "Subnet Mask",
                "Gateway", "DNS Server", "IPv6 Address", "IPv6 DNS", "Lease", "Ping")
        tree = ttk.Treeview(parent, columns=cols, show="headings",
                             selectmode="extended")
        col_w = {"#": 38, "MAC": 122, "Status": 88, "Assigned IP": 100,
                 "Subnet Mask": 100, "Gateway": 100, "DNS Server": 110,
                 "IPv6 Address": 200, "IPv6 DNS": 160, "Lease": 82, "Ping": 80}
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=col_w[c], anchor="w", stretch=False)
        vsb = ttk.Scrollbar(parent, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        self._configure_tree_tags(tree)
        self.dhcp_tree = tree

    def _build_pppoe_table(self, parent):
        cols = ("#", "MAC", "Status", "Session ID", "AC Name",
                "IPv4", "IPv6", "Auth", "Ping")
        tree = ttk.Treeview(parent, columns=cols, show="headings",
                             selectmode="extended")
        col_w = {"#": 38, "MAC": 122, "Status": 100, "Session ID": 80,
                 "AC Name": 100, "IPv4": 110, "IPv6": 200, "Auth": 60, "Ping": 80}
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=col_w[c], anchor="w", stretch=False)
        vsb = ttk.Scrollbar(parent, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        self._configure_tree_tags(tree)
        self.pppoe_tree = tree

    def _configure_tree_tags(self, tree):
        tree.tag_configure("success",  foreground="#0f6e30", font=("Consolas", 9, "bold"))
        tree.tag_configure("fail",     foreground="#b02020", font=("Consolas", 9, "bold"))
        tree.tag_configure("running",  foreground="#8a4f00")
        tree.tag_configure("released", foreground=self.C_DIM)
        tree.tag_configure("odd",      background="#ffffff")
        tree.tag_configure("even",     background="#f0f5fc")

    def _build_log(self, parent, name="dhcp"):
        """Build Exchange Log area: Save button bar + Text widget. Stores as self.<name>_log."""
        save_bar = tk.Frame(parent, bg=self.C_BASE)
        save_bar.pack(fill="x", side="top")
        RoundedButton(save_bar, "💾 Save Log",
                      command=lambda n=name: self._save_log(n),
                      bg="#2c7a7b", canvas_bg=self.C_BASE,
                      font=("Segoe UI", 8, "bold"), padx=8, pady=3,
                      ).pack(side="right", padx=4, pady=3)
        log = tk.Text(
            parent, font=("Consolas", 9), bg=self.C_MANTLE, fg="#d0d8e8",
            insertbackground="#d0d8e8", selectbackground="#2d4060",
            relief="flat", state="disabled", wrap="word", padx=8, pady=6,
        )
        setattr(self, f"{name}_log", log)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=log.yview)
        log.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        log.pack(fill="both", expand=True)
        _b = ("Consolas", 9, "bold")
        _n = ("Consolas", 9)
        log.tag_configure("send",    foreground="#7cb8ff", font=_b)
        log.tag_configure("recv",    foreground="#6ddba8", font=_b)
        log.tag_configure("err",     foreground="#ff8080", font=_n)
        log.tag_configure("sys",     foreground="#ffb86c", font=_b)
        log.tag_configure("success", foreground="#6ddba8", font=_b)
        log.tag_configure("detail",  foreground="#788899", font=_n)

    def _on_proto_tab(self, _event=None):
        tab     = self._proto_nb.tab(self._proto_nb.select(), "text").strip()
        tab_key = "DHCP" if "DHCP" in tab else ("PPPoE" if "PPPoE" in tab else None)

        # ── Save sash of the tab we're leaving ────────────────────────────────
        if self._prev_tab and str(self._dhcp_area) in self._main_pane.panes():
            prev_key = ("DHCP" if "DHCP" in self._prev_tab
                        else ("PPPoE" if "PPPoE" in self._prev_tab else None))
            if prev_key:
                try:
                    self._sash_pos[prev_key] = self._main_pane.sashpos(0)
                except Exception:
                    pass
        self._prev_tab = tab

        if "IGMP" in tab:
            try:
                self._main_pane.forget(self._dhcp_area)
            except Exception:
                pass
            # Set initial IGMP pane sash positions on first visit so Video Monitor
            # is clearly visible (not collapsed to zero)
            if not self._sash_pos.get("IGMP_init"):
                self._sash_pos["IGMP_init"] = True
                def _set_igmp_sashes():
                    try:
                        h = self._igmp_pane.winfo_height()
                        if h < 100:
                            return
                        # Config ~30%, Client List ~15%, Video ~40%, Log ~15%
                        s0 = int(h * 0.30)
                        s1 = int(h * 0.45)
                        s2 = int(h * 0.85)
                        self._igmp_pane.sashpos(0, s0)
                        self._igmp_pane.sashpos(1, s1)
                        self._igmp_pane.sashpos(2, s2)
                    except Exception:
                        pass
                self.root.after(80, _set_igmp_sashes)
            return

        if "GPON" in tab:
            try:
                self._main_pane.forget(self._dhcp_area)
            except Exception:
                pass
            return

        # Any non-DHCP/PPPoE tab (e.g. RPC Sender) has no bottom table/log area
        if tab_key is None:
            try:
                self._main_pane.forget(self._dhcp_area)
            except Exception:
                pass
            return

        # ── DHCP or PPPoE ─────────────────────────────────────────────────────
        first_time = str(self._dhcp_area) not in self._main_pane.panes()
        if first_time:
            self._main_pane.add(self._dhcp_area, weight=2)
            self.root.update_idletasks()

        # Restore saved sash or set initial position for this specific tab
        saved = self._sash_pos.get(tab_key)
        if saved is not None:
            self._main_pane.sashpos(0, saved)
        elif first_time or tab_key not in self._sash_pos:
            nb_h = self._proto_nb.winfo_reqheight()
            self._main_pane.sashpos(0, max(380, nb_h + 20))

        is_dhcp = "DHCP" in tab

        # Swap table frame — always update client_tree even if pane ops fail
        swap_in  = self._dhcp_tbl_frm  if is_dhcp else self._pppoe_tbl_frm
        swap_out = self._pppoe_tbl_frm if is_dhcp else self._dhcp_tbl_frm
        try:
            self._pane.forget(swap_out)
        except Exception:
            pass
        try:
            self._pane.insert(0, swap_in, weight=1)
        except Exception:
            pass

        # Swap log frame
        log_in  = self._dhcp_log_frm  if is_dhcp else self._pppoe_log_frm
        log_out = self._pppoe_log_frm if is_dhcp else self._dhcp_log_frm
        try:
            self._pane.forget(log_out)
        except Exception:
            pass
        try:
            self._pane.add(log_in, weight=2)
        except Exception:
            try:
                self._pane.insert("end", log_in, weight=2)
            except Exception:
                pass

        # MUST always run so DORA/PPPoE worker targets the correct tree
        self.client_tree  = self.dhcp_tree         if is_dhcp else self.pppoe_tree
        self._client_rows = self._dhcp_client_rows if is_dhcp else self._pppoe_client_rows


    # ── Table helpers ─────────────────────────────────────────────────────────

    # ── IGMP group row management ─────────────────────────────────────────────

    def _igmp_add_group_row(self):
        outer = ttk.Frame(self.igmp_groups_frame)
        outer.pack(anchor="w", pady=(2, 6))
        row_frm  = ttk.Frame(outer)
        row_frm.pack(anchor="w")
        ip_var   = tk.StringVar(value="237.0.0.10")
        port_var = tk.StringVar(value="5000")
        mode_var = tk.StringVar(value=self.IGMP_MODE_LABELS["exclude"])
        src_var  = tk.StringVar(value="")
        ttk.Label(row_frm, text="Group IP:", style="Head.TLabel").pack(
            side="left", padx=(0, 4))
        ttk.Entry(row_frm, textvariable=ip_var, width=14,
                  font=("Consolas", 9)).pack(side="left")
        ttk.Label(row_frm, text="  Port:", style="Head.TLabel").pack(
            side="left", padx=(8, 4))
        ttk.Entry(row_frm, textvariable=port_var, width=6,
                  font=("Consolas", 9)).pack(side="left")
        _cbg2 = self.C_BASE
        # ▶ Join — joins selected clients (or all if none selected)
        RoundedButton(row_frm, "▶ Join",
                      command=lambda iv=ip_var, pv=port_var, mv=mode_var,
                      sv=src_var:
                      self._igmp_join_single_group(iv.get().strip(),
                                                   int(pv.get() or 1234),
                                                   mv.get(), sv.get()),
                      bg="#0288d1", canvas_bg=_cbg2,
                      font=("Segoe UI", 8, "bold"),
                      padx=8, pady=3).pack(side="left", padx=(8, 0))
        # Leave — leaves selected clients (or all) from this group
        RoundedButton(row_frm, "Leave",
                      command=lambda iv=ip_var, pv=port_var:
                      self._igmp_leave_group(iv.get().strip(),
                                             int(pv.get() or 1234)),
                      bg="#e67e22", canvas_bg=_cbg2,
                      font=("Segoe UI", 8, "bold"),
                      padx=8, pady=3).pack(side="left", padx=(4, 0))
        ttk.Button(row_frm, text="−",
                   command=lambda f=outer, iv=ip_var, pv=port_var:
                   self._igmp_remove_group_row(f, iv, pv),
                   width=2).pack(side="left", padx=(4, 0))

        # ── IGMPv3 (RFC 3376) source filter — INCLUDE / EXCLUDE ──────────────
        v3_frm = ttk.Frame(outer)
        v3_frm.pack(anchor="w", padx=(12, 0), pady=(2, 0))
        lbl_mode = ttk.Label(v3_frm, text="IGMPv3 Filter:", style="Head.TLabel")
        lbl_mode.pack(side="left", padx=(0, 4))
        cb_mode = ttk.Combobox(v3_frm, textvariable=mode_var, width=20,
                               state="readonly",
                               values=[self.IGMP_MODE_LABELS["exclude"],
                                       self.IGMP_MODE_LABELS["include"]])
        cb_mode.pack(side="left")
        lbl_src = ttk.Label(v3_frm, text="  Sources:", style="Head.TLabel")
        lbl_src.pack(side="left", padx=(8, 4))
        ent_src = ttk.Entry(v3_frm, textvariable=src_var, width=34,
                            font=("Consolas", 9))
        ent_src.pack(side="left")
        lbl_hint = ttk.Label(
            v3_frm,
            text=" (cách nhau bởi dấu phẩy — EXCLUDE rỗng = mọi source)",
            foreground=self.C_DIM)
        lbl_hint.pack(side="left", padx=(4, 0))
        # ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES — incremental source updates
        btn_allow = ttk.Button(
            v3_frm, text="Allow", width=6,
            command=lambda iv=ip_var, pv=port_var, sv=src_var:
            self._igmp_source_change(iv.get().strip(), int(pv.get() or 1234),
                                     sv.get(), 5))
        btn_allow.pack(side="left", padx=(8, 0))
        btn_block = ttk.Button(
            v3_frm, text="Block", width=6,
            command=lambda iv=ip_var, pv=port_var, sv=src_var:
            self._igmp_source_change(iv.get().strip(), int(pv.get() or 1234),
                                     sv.get(), 6))
        btn_block.pack(side="left", padx=(4, 0))

        self._igmp_v3_widgets.extend(
            [cb_mode, ent_src, btn_allow, btn_block])
        self.igmp_group_rows.append((outer, ip_var, port_var,
                                     mode_var, src_var))
        self._igmp_on_version_change()

    def _igmp_remove_group_row(self, frm, ip_var, port_var):
        if len(self.igmp_group_rows) <= 1:
            return
        # Drop this row's v3 widgets from the enable/disable list
        _prefix = str(frm) + "."
        self._igmp_v3_widgets = [w for w in self._igmp_v3_widgets
                                 if not str(w).startswith(_prefix)]
        self.igmp_group_rows = [r for r in self.igmp_group_rows
                                if r[1] is not ip_var]
        frm.destroy()

    def _igmp_on_version_change(self):
        """Enable the IGMPv3 source-filter widgets only for IGMPv3."""
        v3 = self.igmp_version_var.get() == "v3"
        for w in list(self._igmp_v3_widgets):
            try:
                if isinstance(w, ttk.Combobox):
                    w.configure(state="readonly" if v3 else "disabled")
                else:
                    w.configure(state="normal" if v3 else "disabled")
            except Exception:
                self._igmp_v3_widgets.remove(w)

    # ── IGMPv3 source-filter helpers (RFC 3376) ───────────────────────────────

    IGMP_MODE_LABELS = {"exclude": "EXCLUDE (ASM)",
                        "include": "INCLUDE (SSM)"}

    @staticmethod
    def _igmp_mode_key(label: str) -> str:
        """Combobox label → "include" / "exclude"."""
        return "include" if "INCLUDE" in (label or "").upper() else "exclude"

    @staticmethod
    def _igmp_parse_sources(src_str: str):
        """Parse a comma/space separated source list → (sources, bad_entries)."""
        srcs, bad = [], []
        for tok in re.split(r"[,\s;]+", (src_str or "").strip()):
            if not tok:
                continue
            try:
                socket.inet_aton(tok)
                if tok.count(".") != 3:
                    raise ValueError
                if tok not in srcs:
                    srcs.append(tok)
            except Exception:
                bad.append(tok)
        return srcs, bad

    def _igmp_filter_of(self, group_key: str):
        """Return (mode, sources) for a group key — defaults to EXCLUDE {}."""
        f = self._igmp_group_filters.get(group_key) or {}
        return f.get("mode", "exclude"), list(f.get("srcs", []))

    def _igmp_filter_text(self, group_key: str) -> str:
        """Short "[IN: a, b]" / "[EX: a]" suffix for the tree label."""
        if self.igmp_version_var.get() != "v3":
            return ""
        mode, srcs = self._igmp_filter_of(group_key)
        if not srcs:
            return "" if mode == "exclude" else "  [IN: ∅]"
        tag = "IN" if mode == "include" else "EX"
        shown = ", ".join(srcs[:2]) + ("…" if len(srcs) > 2 else "")
        return f"  [{tag}: {shown}]"

    def _igmp_v3_report(self, mac, ip, vlan_id, pcp, rtype, group_ip, srcs):
        """Build an IGMPv3 Membership Report (one group record, RFC 3376)."""
        from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr
        from scapy.layers.inet import IPOption_Router_Alert
        gr = IGMPv3gr(rtype=rtype, maddr=group_ip, srcaddrs=list(srcs or []))
        return (build_eth(mac, "01:00:5e:00:00:16", vlan_id, pcp) /
                IP(src=ip, dst="224.0.0.22", ttl=1,
                   options=IPOption_Router_Alert()) /
                IGMPv3(type=0x22) /
                IGMPv3mr(records=[gr]))

    # Record types used below (RFC 3376 §4.2.12)
    _IGMP_RT_NAME = {1: "IS_IN", 2: "IS_EX", 3: "TO_IN", 4: "TO_EX",
                     5: "ALLOW", 6: "BLOCK"}

    def _igmp_source_change(self, group_ip: str, port: int,
                            src_str: str, rtype: int):
        """Send ALLOW_NEW_SOURCES (5) / BLOCK_OLD_SOURCES (6) for a group."""
        if self.igmp_version_var.get() != "v3":
            messagebox.showinfo("IGMP", "Chỉ IGMPv3 hỗ trợ Allow/Block source.")
            return
        if not self._igmp_leases:
            messagebox.showinfo("IGMP", "Không có client active.")
            return
        srcs, bad = self._igmp_parse_sources(src_str)
        if bad:
            messagebox.showerror("IGMP", f"Source IP không hợp lệ: {', '.join(bad)}")
            return
        if not srcs:
            messagebox.showerror("IGMP",
                                 "Allow/Block cần ít nhất một source IP.")
            return
        key   = f"{group_ip}:{port}"
        rname = self._IGMP_RT_NAME.get(rtype, str(rtype))

        # Keep the stored filter in sync with the incremental change
        mode, cur = self._igmp_filter_of(key)
        if mode == "include":
            new = ([s for s in cur if s not in srcs] if rtype == 6
                   else cur + [s for s in srcs if s not in cur])
        else:
            new = (cur + [s for s in srcs if s not in cur] if rtype == 6
                   else [s for s in cur if s not in srcs])
        self._igmp_group_filters[key] = {"mode": mode, "srcs": new}

        for idx in self._igmp_target_clients():
            lease = self._igmp_leases.get(idx)
            if not lease:
                continue
            threading.Thread(
                target=self._igmp_send_record,
                args=(idx, lease, group_ip, rtype, srcs, key, rname),
                daemon=True).start()

    def _igmp_send_record(self, client_idx, lease, group_ip, rtype,
                          srcs, group_key, rname):
        """Send a single IGMPv3 group record for one client."""
        try:
            pkt = self._igmp_v3_report(lease["mac"], lease["ip"],
                                       lease.get("vlan_id"),
                                       lease.get("pcp", 0),
                                       rtype, group_ip, srcs)
            sendp(pkt, iface=lease["iface"], verbose=False)
            self._log(f"  >>> IGMPv3 {rname} {group_key} "
                      f"src=[{', '.join(srcs) or '∅'}] "
                      f"(C{client_idx+1:02d})\n", "send", target="igmp")
        except Exception as e:
            self._log(f"  [ERROR] IGMPv3 {rname}: {e}\n", "err", target="igmp")

    def _igmp_target_clients(self):
        """Clients selected in the tree, or all active clients if none."""
        sel = self.igmp_tree.selection()
        iid_to_idx = {v: k for k, v in self._igmp_client_rows.items()}
        if not sel:
            return set(self._igmp_leases.keys())
        targets = set()
        for iid in sel:
            parent = self.igmp_tree.parent(iid)
            idx = iid_to_idx.get(iid if parent == "" else parent)
            if idx is not None:
                targets.add(idx)
        return targets

    # ── IGMP table helpers ────────────────────────────────────────────────────

    def _igmp_table_add_row(self, idx: int, mac: str):
        """Add parent (client) row to the IGMP tree."""
        row_tag = "even" if idx % 2 == 0 else "odd"
        iid = self.igmp_tree.insert(
            "", "end", text=f"C{idx+1:02d}", open=True,
            tags=(row_tag,),
            values=(mac, "-", "Waiting", "0", "0", "-")
        )
        self._igmp_client_rows[idx] = iid

    def _igmp_table_add_group_row(self, client_idx: int, group_key: str):
        """Add child (group) row under a client parent row."""
        key = (client_idx, group_key)
        if key in self._igmp_group_rows_dict:
            # Already there — only refresh the label (source filter may
            # have changed since the first join)
            def _relabel():
                iid = self._igmp_group_rows_dict.get(key)
                if not iid:
                    return
                try:
                    vals = list(self.igmp_tree.item(iid, "values"))
                    vals[0] = group_key + self._igmp_filter_text(group_key)
                    self.igmp_tree.item(iid, values=vals)
                except Exception:
                    self._igmp_group_rows_dict.pop(key, None)

            self.root.after(0, _relabel)
            return
        parent_iid = self._igmp_client_rows.get(client_idx)
        if not parent_iid:
            return

        def _do():
            iid = self.igmp_tree.insert(
                parent_iid, "end", text="", tags=("running",),
                values=(group_key + self._igmp_filter_text(group_key),
                        "", "Joining…", "0", "0", "-")
            )
            self._igmp_group_rows_dict[key] = iid

        self.root.after(0, _do)

    def _igmp_table_update(self, idx: int, **kwargs):
        """Thread-safe update of a client (parent) row.
        Keys: label(=MAC), ip, status, pkts, pps, bitrate"""
        _ci = {"label": 0, "ip": 1, "status": 2, "pkts": 3, "pps": 4, "bitrate": 5}

        def _do():
            iid = self._igmp_client_rows.get(idx)
            if not iid:
                return
            vals = list(self.igmp_tree.item(iid, "values"))
            for k, v in kwargs.items():
                if k in _ci:
                    vals[_ci[k]] = v
            self.igmp_tree.item(iid, values=vals)
            status = vals[2]
            row_tag = "even" if idx % 2 == 0 else "odd"
            if "✔" in status or "Watching" in status:
                tags = ("success", row_tag)
            elif "✗" in status:
                tags = ("fail", row_tag)
            elif any(s in status for s in ("DHCP", "Joining", "retry")):
                tags = ("running", row_tag)
            else:
                tags = (row_tag,)
            self.igmp_tree.item(iid, tags=tags)

        self.root.after(0, _do)

    def _igmp_group_row_update(self, client_idx: int, group_key: str, **kwargs):
        """Thread-safe update of a group (child) row.
        Keys: status, pkts, pps, bitrate"""
        _ci = {"status": 2, "pkts": 3, "pps": 4, "bitrate": 5}

        def _do():
            iid = self._igmp_group_rows_dict.get((client_idx, group_key))
            if not iid:
                return
            try:
                vals = list(self.igmp_tree.item(iid, "values"))
            except Exception:
                # Item no longer exists (tree was cleared) — remove stale entry
                self._igmp_group_rows_dict.pop((client_idx, group_key), None)
                return
            for k, v in kwargs.items():
                if k in _ci:
                    vals[_ci[k]] = v
            self.igmp_tree.item(iid, values=vals)
            status = vals[2]
            if status == "Left":
                self.igmp_tree.item(iid, tags=("released",))
            elif "Watching" in status or "✔" in status:
                self.igmp_tree.item(iid, tags=("success",))
            elif "✗" in status:
                self.igmp_tree.item(iid, tags=("fail",))
            else:
                self.igmp_tree.item(iid, tags=("running",))

        self.root.after(0, _do)

    # ── IGMP start / stop / leave ─────────────────────────────────────────────

    def _start_igmp(self):
        if not _SCAPY_OK:
            messagebox.showerror("Error", "scapy không có sẵn.")
            return

        label = self.igmp_iface_var.get().strip()
        if not label:
            messagebox.showerror("Error", "Chọn network interface trước.")
            return
        iface = self._iface_map.get(label, label)

        mac = self.igmp_mac_var.get().strip().lower()
        if len(mac.replace(":", "").replace("-", "")) != 12:
            messagebox.showerror("Error", "Invalid MAC address.")
            return

        vlan_id = None
        if self.igmp_vlan_var.get().strip():
            try:
                vlan_id = int(self.igmp_vlan_var.get())
            except ValueError:
                pass
        pcp = int(self.igmp_pcp_var.get() or 0)

        try:
            num_clients = max(1, int(self.igmp_num_cli_var.get()))
        except ValueError:
            num_clients = 1
        try:
            interval_ms = max(0, int(self.igmp_interval_var.get()))
        except ValueError:
            interval_ms = 200
        try:
            timeout = max(1, int(self.igmp_dhcp_timeout_var.get()))
        except ValueError:
            timeout = 5

        retry_enabled = self.igmp_retry_var.get()
        try:
            max_retries = max(1, int(self.igmp_max_retry_var.get()))
        except ValueError:
            max_retries = 3

        mac_mode    = self.igmp_mac_mode_var.get()
        igmp_ver    = self.igmp_version_var.get()
        group_list  = [(r[1].get().strip(), int(r[2].get() or 1234))
                       for r in self.igmp_group_rows
                       if r[1].get().strip()]

        if not group_list:
            messagebox.showerror("Error", "Nhập ít nhất một multicast group.")
            return

        # ── IGMPv3 source filters (RFC 3376) from the group rows ─────────────
        self._igmp_group_filters.clear()
        for r in self.igmp_group_rows:
            g_ip = r[1].get().strip()
            if not g_ip:
                continue
            key       = f"{g_ip}:{int(r[2].get() or 1234)}"
            f_mode    = self._igmp_mode_key(r[3].get())
            srcs, bad = self._igmp_parse_sources(r[4].get())
            if igmp_ver == "v3":
                if bad:
                    messagebox.showerror(
                        "Error", f"{key}: source IP không hợp lệ: "
                                 f"{', '.join(bad)}")
                    return
                if f_mode == "include" and not srcs:
                    messagebox.showerror(
                        "Error", f"{key}: INCLUDE mode cần ít nhất một "
                                 f"source IP (RFC 3376).")
                    return
            self._igmp_group_filters[key] = {"mode": f_mode, "srcs": srcs}

        macs = [increment_mac(mac, i) if mac_mode == "sequential"
                else random_mac() for i in range(num_clients)]

        self._igmp_stop_event.clear()
        self._igmp_current_iface = iface   # needed by video relay workers

        # Reset IGMP table — clear ALL row dicts to avoid stale iids
        self.igmp_tree.delete(*self.igmp_tree.get_children())
        self._igmp_client_rows.clear()
        self._igmp_group_rows_dict.clear()
        self._igmp_leases.clear()
        self._summary_var.set("")

        for idx, m in enumerate(macs):
            self._igmp_table_add_row(idx, m)

        # Video tabs are created only AFTER IGMP join is sent (in _igmp_send_join_one)
        # — not here, to avoid showing video before the client actually joins

        # Start stats sniffer
        self._igmp_start_stats(iface, [g for g, _ in group_list])

        # Start workers
        for idx, m in enumerate(macs):
            threading.Thread(
                target=self._igmp_worker,
                args=(iface, m, timeout, vlan_id, pcp,
                      igmp_ver, idx, num_clients, interval_ms,
                      retry_enabled, max_retries),
                daemon=True
            ).start()

    def _stop_igmp(self):
        self._igmp_stop_event.set()
        # Stop query responder threads
        for ev in self._igmp_responder_events.values():
            ev.set()
        self._igmp_responder_events.clear()
        # Stop video threads
        for ev in self._igmp_video_events.values():
            ev.set()
        self._igmp_video_events.clear()
        # Stop stats sniffer
        if self._igmp_stats_sniffer:
            try:
                self._igmp_stats_sniffer.stop()
            except Exception:
                pass
            self._igmp_stats_sniffer = None
        # Tear down each client: leave all joined groups, then release its DORA (DHCP) lease
        clients = list(self._igmp_leases.items())
        if clients:
            self._log(f"[Stop] Tearing down {len(clients)} IGMP client(s) "
                      f"(Leave + DHCP Release)…\n", "sys", target="igmp")
            for idx, lease in clients:
                threading.Thread(target=self._igmp_teardown_worker,
                                 args=(idx, lease), daemon=True).start()
        self._log("[IGMP] Stopped\n", "sys", target="igmp")

    def _igmp_teardown_worker(self, client_idx: int, lease: dict):
        """Stop one IGMP client: send Leave for its groups, then RELEASE its lease."""
        if lease.get("groups"):
            self._igmp_send_leave(client_idx)
        self._igmp_release_worker(client_idx, lease)

    def _igmp_release_worker(self, client_idx: int, lease: dict):
        """Release the DHCP (DORA) lease held by an IGMP client (IGMP-tab scoped)."""
        mac      = lease["mac"]
        assigned = lease.get("ip")
        server   = lease.get("server")
        iface    = lease["iface"]
        vlan_id  = lease.get("vlan_id")
        pcp      = lease.get("pcp", 0)
        if not server or not assigned:
            self._igmp_leases.pop(client_idx, None)
            return
        try:
            mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
            client_id = b'\x01' + mac_to_bytes(mac)
            xid       = random.randint(1, 0xFFFFFFFF)
            eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
            if vlan_id:
                eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)
            pkt = (eth /
                   IP(src=assigned, dst=server) /
                   UDP(sport=68, dport=67) /
                   BOOTP(op=1, htype=1, hlen=6, ciaddr=assigned,
                         chaddr=mac_bytes, xid=xid) /
                   DHCP(options=[("message-type", "release"),
                                 ("server_id",    server),
                                 ("client_id",    client_id), "end"]))
            sendp(pkt, iface=iface, verbose=False)
            self._log(f"  >>> DHCP RELEASE {assigned} → server {server} "
                      f"(C{client_idx+1:02d})\n", "send", target="igmp")
        except Exception as exc:
            self._log(f"  [ERROR] IGMP Release: {exc}\n", "err", target="igmp")
        finally:
            self._igmp_leases.pop(client_idx, None)
            self._igmp_table_update(client_idx, status="Released", ip="-")

    def _igmp_leave_selected(self):
        sel = self.igmp_tree.selection()
        if not sel:
            messagebox.showinfo("IGMP", "Chọn ít nhất một client hoặc group.")
            return
        iid_to_idx = {v: k for k, v in self._igmp_client_rows.items()}
        # Reverse map for group rows
        iid_to_group = {v: k for k, v in self._igmp_group_rows_dict.items()}

        for iid in sel:
            parent_iid = self.igmp_tree.parent(iid)
            if parent_iid == "":
                # Parent row selected → leave ALL groups for this client
                idx = iid_to_idx.get(iid)
                if idx is not None and idx in self._igmp_leases:
                    threading.Thread(target=self._igmp_send_leave,
                                     args=(idx,), daemon=True).start()
            else:
                # Child row selected → leave THIS group only
                row_key = iid_to_group.get(iid)   # (client_idx, "group:port")
                if row_key:
                    client_idx, group_key = row_key
                    if client_idx in self._igmp_leases:
                        g_ip, port_str = group_key.rsplit(":", 1)
                        threading.Thread(
                            target=self._igmp_send_leave_one,
                            args=(client_idx, g_ip, int(port_str), group_key),
                            daemon=True
                        ).start()

    def _igmp_send_leave_one(self, client_idx: int, group_ip: str,
                              port: int, group_key: str):
        """Send IGMP Leave for a single group of a single client."""
        from scapy.contrib.igmp import IGMP
        from scapy.layers.inet import IPOption_Router_Alert
        lease = self._igmp_leases.get(client_idx)
        if not lease:
            return
        mac      = lease["mac"]
        ip       = lease["ip"]
        iface    = lease["iface"]
        vlan_id  = lease.get("vlan_id")
        pcp      = lease.get("pcp", 0)
        igmp_ver = lease.get("igmp_ver", "v2")

        eth = build_eth(mac, "01:00:5e:00:00:02", vlan_id, pcp)
        if igmp_ver == "v2":
            pkt = (eth /
                   IP(src=ip, dst="224.0.0.2", ttl=1,
                      options=IPOption_Router_Alert()) /
                   IGMP(type=0x17, gaddr=group_ip))
        else:
            # Full leave = CHANGE_TO_INCLUDE_MODE with an empty source list
            pkt = self._igmp_v3_report(mac, ip, vlan_id, pcp,
                                       3, group_ip, [])
        try:
            sendp(pkt, iface=iface, verbose=False)
            self._log(f"  >>> IGMP Leave {group_ip}:{port} (C{client_idx+1:02d})\n",
                      "send", target="igmp")
        except Exception as e:
            self._log(f"  [ERROR] Leave one: {e}\n", "err", target="igmp")

        self._igmp_group_row_update(client_idx, group_key, status="Left")
        # Remove from lease groups so query responder stops reporting it
        lease["groups"] = [(g, p) for g, p in lease.get("groups", [])
                           if not (g == group_ip and p == port)]

    def _igmp_send_leave(self, client_idx: int):
        """Send IGMP Leave for ALL groups of a client."""
        from scapy.contrib.igmp import IGMP
        from scapy.layers.inet import IPOption_Router_Alert
        lease = self._igmp_leases.get(client_idx)
        if not lease:
            return
        mac, ip    = lease["mac"], lease["ip"]
        iface      = lease["iface"]
        vlan_id    = lease.get("vlan_id")
        pcp        = lease.get("pcp", 0)
        igmp_ver   = lease.get("igmp_ver", "v2")
        group_list = list(lease.get("groups", []))

        for group_ip, port in group_list:
            key = f"{group_ip}:{port}"
            eth = build_eth(mac, "01:00:5e:00:00:02", vlan_id, pcp)
            if igmp_ver == "v2":
                pkt = (eth /
                       IP(src=ip, dst="224.0.0.2", ttl=1,
                          options=IPOption_Router_Alert()) /
                       IGMP(type=0x17, gaddr=group_ip))
            else:
                # Full leave = CHANGE_TO_INCLUDE_MODE with an empty source list
                pkt = self._igmp_v3_report(mac, ip, vlan_id, pcp,
                                           3, group_ip, [])
            try:
                sendp(pkt, iface=iface, verbose=False)
                self._log(f"  >>> IGMP Leave {group_ip} (C{client_idx+1:02d})\n",
                          "send", target="igmp")
            except Exception as e:
                self._log(f"  [ERROR] Leave: {e}\n", "err", target="igmp")
            self._igmp_group_row_update(client_idx, key, status="Left")

        lease["groups"] = []
        self._igmp_table_update(client_idx, status="Left")

    # ── IGMP Join single group for existing clients ───────────────────────────

    def _igmp_join_single_group(self, group_ip: str, port: int,
                                 mode_label: str = None, src_str: str = None):
        """Join group for selected clients (or all if none selected).

        For IGMPv3 the join carries the group's source filter (RFC 3376):
        INCLUDE → CHANGE_TO_INCLUDE_MODE with the listed sources,
        EXCLUDE → CHANGE_TO_EXCLUDE_MODE (empty list = any source / ASM)."""
        if not self._igmp_leases:
            messagebox.showinfo("IGMP",
                                "Không có client active. Nhấn ▶ Start trước.")
            return
        import time as _t
        key      = f"{group_ip}:{port}"
        igmp_ver = self.igmp_version_var.get()

        # Refresh this group's source filter from its row widgets
        if mode_label is not None or src_str is not None:
            f_mode    = self._igmp_mode_key(mode_label)
            srcs, bad = self._igmp_parse_sources(src_str)
            if igmp_ver == "v3":
                if bad:
                    messagebox.showerror(
                        "IGMP", f"Source IP không hợp lệ: {', '.join(bad)}")
                    return
                if f_mode == "include" and not srcs:
                    messagebox.showerror(
                        "IGMP", "INCLUDE mode cần ít nhất một source IP "
                                "(RFC 3376) — INCLUDE {} nghĩa là Leave.")
                    return
            self._igmp_group_filters[key] = {"mode": f_mode, "srcs": srcs}

        targets = self._igmp_target_clients()

        if not targets:
            messagebox.showinfo("IGMP", "Chọn client trong bảng hoặc đảm bảo có client active.")
            return

        # Track stats for this new group
        if group_ip not in self._igmp_pkt_counts:
            self._igmp_pkt_counts[group_ip] = [0, 0]
            self._igmp_prev_pkts[group_ip]  = [0, _t.time()]

        # Video tab is created in _igmp_send_join_one AFTER join packet is sent

        for client_idx in targets:
            lease = self._igmp_leases.get(client_idx)
            if not lease:
                continue
            if (group_ip, port) in lease.get("groups", []):
                if igmp_ver != "v3":
                    self._log(f"  C{client_idx+1:02d} already joined {key}\n",
                              "detail", target="igmp")
                    continue
                # IGMPv3: re-send the state-change record so a changed
                # INCLUDE/EXCLUDE source list reaches the querier
                self._log(f"  C{client_idx+1:02d} {key} already joined — "
                          f"sending filter update\n", "detail", target="igmp")
            else:
                lease["groups"].append((group_ip, port))
            self._igmp_table_add_group_row(client_idx, key)
            threading.Thread(
                target=self._igmp_send_join_one,
                args=(client_idx, lease, group_ip, igmp_ver, key),
                daemon=True
            ).start()

    def _igmp_send_join_one(self, client_idx: int, lease: dict,
                             group_ip: str, igmp_ver: str, group_key: str):
        """Send IGMP join for one group, update child row status."""
        from scapy.contrib.igmp import IGMP
        from scapy.layers.inet import IPOption_Router_Alert
        mac     = lease["mac"]
        ip      = lease["ip"]
        iface   = lease["iface"]
        vlan_id = lease.get("vlan_id")
        pcp     = lease.get("pcp", 0)

        parts_g  = [int(x) for x in group_ip.split('.')]
        mcast_mac = (f"01:00:5e:{parts_g[1] & 0x7f:02x}"
                     f":{parts_g[2]:02x}:{parts_g[3]:02x}")
        f_desc = ""
        if igmp_ver == "v2":
            pkt = (build_eth(mac, mcast_mac, vlan_id, pcp) /
                   IP(src=ip, dst=group_ip, ttl=1,
                      options=IPOption_Router_Alert()) /
                   IGMP(type=0x16, gaddr=group_ip))
        else:
            # RFC 3376 §4.2.12: TO_IN (3) for INCLUDE, TO_EX (4) for EXCLUDE
            f_mode, srcs = self._igmp_filter_of(group_key)
            rtype  = 3 if f_mode == "include" else 4
            pkt    = self._igmp_v3_report(mac, ip, vlan_id, pcp,
                                          rtype, group_ip, srcs)
            f_desc = (f" {self._IGMP_RT_NAME[rtype]} "
                      f"src=[{', '.join(srcs) or '∅'}]")
        try:
            sendp(pkt, iface=iface, verbose=False)
            self._log(f"  >>> {igmp_ver} Join {group_key}{f_desc} "
                      f"(C{client_idx+1:02d})\n",
                      "send", target="igmp")
            self._igmp_group_row_update(client_idx, group_key, status="Watching")
            # Open video tab only AFTER join is sent — first client for this group
            g_ip, p_str = group_key.rsplit(":", 1)
            if group_key not in self._igmp_video_events:
                self.root.after(0, lambda g=g_ip, p=int(p_str):
                                self._igmp_add_single_video_tab(g, p))
        except Exception as e:
            self._log(f"  [ERROR] Join one: {e}\n", "err", target="igmp")
            self._igmp_group_row_update(client_idx, group_key, status="✗ Error")

    # ── IGMP DHCP + Join worker ───────────────────────────────────────────────

    def _igmp_worker(self, iface, mac, timeout, vlan_id, pcp,
                     igmp_ver, client_idx, total, interval_ms,
                     retry_enabled=True, max_retries=2):
        """DHCP only — no auto IGMP join. User clicks Join per group."""
        import time as _t
        from scapy.packet import Raw

        pfx = f"[C{client_idx+1:02d}] " if total > 1 else ""

        def log(msg, tag=None):
            if pfx:
                parts = msg.split('\n')
                msg2 = '\n'.join((pfx + p) if p.strip() else p for p in parts)
            else:
                msg2 = msg
            self._log(msg2, tag, target="igmp")

        if interval_ms > 0 and client_idx > 0:
            _t.sleep(client_idx * interval_ms / 1000)

        try:
            # ── Get IP (reuse or DORA) ────────────────────────────────────────
            existing_lease = next(
                (l for l in self._client_leases.values()
                 if l.get("mac", "").lower() == mac.lower()),
                None
            )

            if existing_lease:
                client_ip = existing_lease["ip"]
                log(f"<<< Using existing DHCP lease: {client_ip}\n", "recv")
            else:
                _RFC_INIT = 4.0
                _RFC_MAX  = 64.0
                t_retry   = _RFC_INIT if retry_enabled else float(timeout)
                n_retries = max_retries if retry_enabled else 0
                client_ip = None

                for attempt in range(n_retries + 1):
                    if self._igmp_stop_event.is_set():
                        return
                    if attempt == 0:
                        log(">>> DHCP DORA...\n", "send")
                        self._igmp_table_update(client_idx, status="DHCP...")
                    else:
                        log(f"  DHCP retry {attempt}/{n_retries}"
                            f"  timeout={t_retry:.1f}s\n", "sys")
                        self._igmp_table_update(
                            client_idx, status=f"DHCP retry {attempt}/{n_retries}")

                    client_ip, _lt, _t1, _srv = self._igmp_dhcp_get_ip(
                        iface, mac, t_retry, vlan_id, pcp)
                    if client_ip:
                        break
                    if attempt < n_retries:
                        log("    No OFFER — retrying\n", "err")
                        t_retry = max(1.0, min(t_retry * 2, _RFC_MAX)
                                      + random.uniform(-1.0, 1.0))

                if not client_ip:
                    log(f"[TIMEOUT] No DHCP IP after "
                        f"{n_retries + 1} attempt(s)\n", "err")
                    self._igmp_table_update(client_idx, status="✗ DHCP Fail")
                    return

                log(f"<<< DHCP IP: {client_ip}\n", "recv")

            # Store lease — groups list starts empty (user joins manually)
            self._igmp_leases[client_idx] = {
                "ip": client_ip, "mac": mac, "iface": iface,
                "vlan_id": vlan_id, "pcp": pcp,
                "groups": [], "igmp_ver": igmp_ver,
                "server": _srv or "",
            }
            self._igmp_table_update(client_idx,
                                     status="✔ IP Ready", ip=client_ip)
            log(f"✔ IP Ready: {client_ip} — click ▶ Join to join groups\n",
                "success")

            # Auto-renew
            if _lt and _srv and not self._igmp_stop_event.is_set():
                t1_val = int(_t1) if _t1 else _lt // 2
                log(f"  Auto-Renew   : will renew in {lease_fmt(t1_val)}\n", "detail")
                threading.Thread(
                    target=self._igmp_auto_renew_loop,
                    args=(client_idx, _lt, t1_val),
                    daemon=True,
                ).start()

            # Start query responder (handles RFC 3376 queries when groups joined)
            stop_ev = threading.Event()
            self._igmp_responder_events[client_idx] = stop_ev
            threading.Thread(
                target=self._igmp_query_responder,
                args=(client_idx, iface, mac, client_ip, vlan_id, pcp,
                      igmp_ver, stop_ev),
                daemon=True
            ).start()

        except Exception as e:
            log(f"[ERROR] {e}\n", "err")
            import traceback; log(traceback.format_exc(), "err")
            self._igmp_table_update(client_idx, status="✗ Error")

    def _igmp_query_responder(self, client_idx, iface, mac, ip,
                               vlan_id, pcp, igmp_ver, stop_ev):
        """RFC 3376 query responder — runs independently per client."""
        import time as _t
        from scapy.contrib.igmp import IGMP
        from scapy.layers.inet import IPOption_Router_Alert

        pfx = f"[C{client_idx+1:02d}] "

        def _send_report(group_ip, port=None):
            parts_g   = [int(x) for x in group_ip.split('.')]
            mcast_mac = (f"01:00:5e:{parts_g[1] & 0x7f:02x}"
                         f":{parts_g[2]:02x}:{parts_g[3]:02x}")
            if igmp_ver == "v2":
                pkt = (build_eth(mac, mcast_mac, vlan_id, pcp) /
                       IP(src=ip, dst=group_ip, ttl=1,
                          options=IPOption_Router_Alert()) /
                       IGMP(type=0x16, gaddr=group_ip))
            else:
                # Current-state record — RFC 3376 §4.2.12:
                # MODE_IS_INCLUDE (1) / MODE_IS_EXCLUDE (2) with the sources
                f_mode, srcs = self._igmp_filter_of(f"{group_ip}:{port}")
                rtype = 1 if f_mode == "include" else 2
                pkt   = self._igmp_v3_report(mac, ip, vlan_id, pcp,
                                             rtype, group_ip, srcs)
            try:
                sendp(pkt, iface=iface, verbose=False)
            except Exception:
                pass

        while not stop_ev.is_set() and not self._igmp_stop_event.is_set():
            live = self._igmp_leases.get(client_idx, {}).get("groups", [])
            if not live:
                _t.sleep(2.0)   # no groups joined yet — idle
                continue

            sniffer_q = AsyncSniffer(
                iface=iface,
                lfilter=lambda p: (
                    IP in p and IGMP in p and
                    p[IGMP].type == 0x11 and
                    p[IP].src != ip),
                count=1, timeout=130,
                stop_filter=lambda _: stop_ev.is_set()
                            or self._igmp_stop_event.is_set(),
            )
            sniffer_q.start()
            sniffer_q.join(timeout=131)

            if stop_ev.is_set() or self._igmp_stop_event.is_set():
                break

            live = self._igmp_leases.get(client_idx, {}).get("groups", [])
            if not live:
                continue

            if not sniffer_q.results:
                # 130 s no query → unsolicited keep-alive
                for g_ip, g_port in live:
                    _send_report(g_ip, g_port)
                self._log(f"{pfx}↔ Keep-alive report for "
                          f"{len(live)} group(s)\n", "detail", target="igmp")
                continue

            query    = sniffer_q.results[0]
            _raw_mrt = (getattr(query[IGMP], "mrtime",  None) or
                        getattr(query[IGMP], "maxresp", None) or
                        getattr(query[IGMP], "gstimer", None) or 100)
            mrtime   = float(_raw_mrt) / 10.0
            q_group  = str(query[IGMP].gaddr)

            _t.sleep(random.uniform(0, min(mrtime, 10.0)))
            if stop_ev.is_set() or self._igmp_stop_event.is_set():
                break

            live = self._igmp_leases.get(client_idx, {}).get("groups", [])
            if q_group == "0.0.0.0":
                to_report = list(live)
                q_type    = "General"
            else:
                to_report = [(g, p) for g, p in live if g == q_group]
                q_type    = f"Group-Specific ({q_group})"

            for g_ip, g_port in to_report:
                _send_report(g_ip, g_port)
            if to_report:
                self._log(f"{pfx}↔ {q_type} Query → Report: "
                          f"{', '.join(g for g, _ in to_report)}\n",
                          "detail", target="igmp")

    # ── IGMP Leave per group (called from Leave button in group row) ───────────

    def _igmp_leave_group(self, group_ip: str, port: int):
        """Leave this group for selected clients (or all if none selected)."""
        if not self._igmp_leases:
            messagebox.showinfo("IGMP", "Không có client active.")
            return
        key = f"{group_ip}:{port}"
        sel = self.igmp_tree.selection()
        iid_to_idx = {v: k for k, v in self._igmp_client_rows.items()}
        if sel:
            targets = set()
            for iid in sel:
                parent = self.igmp_tree.parent(iid)
                idx = iid_to_idx.get(iid if parent == "" else parent)
                if idx is not None:
                    targets.add(idx)
        else:
            targets = set(self._igmp_leases.keys())
        for idx in targets:
            if idx in self._igmp_leases:
                threading.Thread(
                    target=self._igmp_send_leave_one,
                    args=(idx, group_ip, port, key),
                    daemon=True
                ).start()

        # Stop video for this group so socket is released before any re-join
        if key in self._igmp_video_events:
            self._igmp_close_video_tab(key, send_leave=False)

    def _igmp_dhcp_get_ip(self, iface, mac, timeout, vlan_id, pcp):
        """Minimal DHCP DORA, returns (ip, lease_time, t1, server) or (None,…)."""
        from scapy.packet import Raw
        xid       = random.randint(1, 0xFFFFFFFF)
        mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
        client_id = b'\x01' + mac_to_bytes(mac)

        def _eth(dst="ff:ff:ff:ff:ff:ff"):
            return build_eth(mac, dst, vlan_id, pcp)

        def _make(msg_type, extra_opts=()):
            base = (_eth() / IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000, secs=0) /
                    DHCP(options=[("message-type", msg_type),
                                  ("client_id", client_id),
                                  *extra_opts, "end"]))
            needed = 300 - len(bytes(base[BOOTP]))
            return base / Raw(b'\x00' * max(0, needed))

        disc = _make("discover")
        sn1  = AsyncSniffer(
            iface=iface,
            lfilter=lambda p: (DHCP in p and p[BOOTP].xid == xid and
                               any(o[0] == 'message-type' and o[1] == 2
                                   for o in p[DHCP].options if isinstance(o, tuple))),
            count=1, timeout=timeout,
            stop_filter=lambda _: self._igmp_stop_event.is_set())
        sn1.start()
        sendp(disc, iface=iface, verbose=False)
        sn1.join(timeout=timeout + 1)
        offers = sn1.results or []
        if not offers:
            return None, None, None, None

        offer    = offers[0]
        offered  = offer[BOOTP].yiaddr
        opts_o   = {o[0]: o[1] for o in offer[DHCP].options if isinstance(o, tuple)}
        server   = opts_o.get("server_id", offer[IP].src)

        req = _make("request", [("requested_addr", offered), ("server_id", server)])
        sn2 = AsyncSniffer(
            iface=iface,
            lfilter=lambda p: (DHCP in p and p[BOOTP].xid == xid and
                               any(o[0] == 'message-type' and o[1] in (5, 6)
                                   for o in p[DHCP].options if isinstance(o, tuple))),
            count=1, timeout=timeout,
            stop_filter=lambda _: self._igmp_stop_event.is_set())
        sn2.start()
        sendp(req, iface=iface, verbose=False)
        sn2.join(timeout=timeout + 1)
        acks = sn2.results or []
        if not acks:
            return None, None, None, None

        ack        = acks[0]
        opts_a     = {o[0]: o[1] for o in ack[DHCP].options if isinstance(o, tuple)}
        if opts_a.get("message-type") == 6:
            return None, None, None, None
        lease_time = opts_a.get("lease_time", None)
        t1         = opts_a.get("renewal_time", lease_time // 2 if lease_time else None)
        return str(ack[BOOTP].yiaddr), lease_time, t1, str(server)

    # ── IGMP stats sniffer ────────────────────────────────────────────────────

    def _igmp_start_stats(self, iface, group_ips):
        import time as _t
        self._igmp_pkt_counts = {g: [0, 0] for g in group_ips}  # [pkts, bytes]
        # Snapshot for PPS: {group_ip: [prev_pkts, prev_time]}
        self._igmp_prev_pkts  = {g: [0, _t.time()] for g in group_ips}

        def _on_pkt(pkt):
            if IP in pkt and pkt[IP].dst in self._igmp_pkt_counts:
                c = self._igmp_pkt_counts[pkt[IP].dst]
                c[0] += 1
                c[1] += len(pkt)

        try:
            self._igmp_stats_sniffer = AsyncSniffer(
                iface=iface, filter="ip multicast",
                prn=_on_pkt, store=False,
                stop_filter=lambda _: self._igmp_stop_event.is_set())
            self._igmp_stats_sniffer.start()
        except Exception as e:
            self._log(f"[IGMP Stats] Sniffer error: {e}\n", "err", target="igmp")

        self.root.after(1000, self._igmp_update_stats)

    def _igmp_update_stats(self):
        import time as _t
        if self._igmp_stop_event.is_set():
            return

        now = _t.time()

        # ── Step 1: Pre-compute per-group stats ONCE (shared by all clients) ──
        # Updating _igmp_prev_pkts inside the client loop would cause the 2nd
        # client to always see delta=0 (PPS=0) for shared groups.
        group_stats = {}   # g_ip → (cur_pkts, g_pps, g_kb)
        for g_ip, (cur_pkts, cur_bytes) in self._igmp_pkt_counts.items():
            prev_pkts, prev_time = self._igmp_prev_pkts.get(g_ip, [0, now])
            elapsed = now - prev_time
            g_pps  = (cur_pkts - prev_pkts) / elapsed if elapsed > 0 else 0.0
            g_kb   = cur_bytes / 1024
            group_stats[g_ip] = (cur_pkts, g_pps, g_kb)
            self._igmp_prev_pkts[g_ip] = [cur_pkts, now]  # update snapshot ONCE

        # ── Step 2: Apply same stats to every client that joined each group ────
        for idx, lease in self._igmp_leases.items():
            total_pkts = 0
            total_pps  = 0.0
            total_kb   = 0.0

            for g_ip, port in lease.get("groups", []):
                cur_pkts, g_pps, g_kb = group_stats.get(g_ip, (0, 0.0, 0.0))
                total_pkts += cur_pkts
                total_pps  += g_pps
                total_kb   += g_kb

                key = f"{g_ip}:{port}"
                self._igmp_group_row_update(idx, key,
                                            pkts=str(cur_pkts),
                                            pps=f"{g_pps:.0f}",
                                            bitrate=f"{g_kb:.1f} KB")

            self._igmp_table_update(idx,
                                     pkts=str(total_pkts),
                                     pps=f"{total_pps:.0f}",
                                     bitrate=f"{total_kb:.1f} KB")

        self.root.after(1000, self._igmp_update_stats)

    # ── IGMP video display ────────────────────────────────────────────────────

    def _igmp_setup_video_tabs(self, group_list):
        """Create one video tab per group — called on Start (clears existing)."""
        for ev in self._igmp_video_events.values():
            ev.set()
        self._igmp_video_events.clear()
        self._igmp_pause_events.clear()
        for tab in self._igmp_video_nb.tabs():
            self._igmp_video_nb.forget(tab)

        for group_ip, port in group_list:
            self._igmp_add_single_video_tab(group_ip, port)

    def _igmp_add_single_video_tab(self, group_ip: str, port: int):
        """Add one video tab with Pause/Play, Fullscreen, Minimize, Close controls."""
        key = f"{group_ip}:{port}"
        if key in self._igmp_video_events:
            # Re-join: close old video first, wait for socket release, then reopen
            self._igmp_close_video_tab(key, send_leave=False)
            self.root.after(800, lambda: self._igmp_add_single_video_tab(group_ip, port))
            return

        tab_frm = ttk.Frame(self._igmp_video_nb)
        self._igmp_video_nb.add(tab_frm, text=f"  {key}  ")

        # Canvas
        canvas = tk.Canvas(tab_frm, bg="#0d0d0d", highlightthickness=0)
        canvas.pack(fill="both", expand=True)

        # Wait label overlay
        lbl = tk.Label(tab_frm, text=f"Waiting for stream {key}…",
                       bg="#0d0d0d", fg="#888888", font=("Segoe UI", 10))
        lbl.place(relx=0.5, rely=0.5, anchor="center")

        # Control bar (bottom)
        ctrl = tk.Frame(tab_frm, bg="#111122", height=28)
        ctrl.pack(side="bottom", fill="x")
        ctrl.pack_propagate(False)

        # Stream label
        tk.Label(ctrl, text=key, bg="#111122", fg="#6688aa",
                 font=("Consolas", 8)).pack(side="left", padx=8)

        # Events
        stop_ev  = threading.Event()
        pause_ev = threading.Event()   # set = paused
        self._igmp_video_events[key] = stop_ev
        self._igmp_pause_events[key] = pause_ev

        # ⏸/▶ Pause/Resume
        pause_txt = tk.StringVar(value="⏸")

        def _toggle_pause(pe=pause_ev, pt=pause_txt):
            if pe.is_set():
                pe.clear()
                pt.set("⏸")
            else:
                pe.set()
                pt.set("▶")

        tk.Button(ctrl, textvariable=pause_txt, command=_toggle_pause,
                  bg="#111122", fg="white", relief="flat",
                  font=("Segoe UI", 11), cursor="hand2",
                  padx=6).pack(side="left")

        # ⛶ Fullscreen
        def _fullscreen(k=key, g=group_ip, p=port):
            win = tk.Toplevel(self.root)
            win.title(f"Fullscreen — {k}")
            win.configure(bg="#000000")
            win.state("zoomed")
            c2    = tk.Canvas(win, bg="#000000", highlightthickness=0)
            c2.pack(fill="both", expand=True)
            lbl2  = tk.Label(win, text=f"Opening {k}…",
                             bg="#000", fg="#666", font=("Segoe UI", 10))
            lbl2.place(relx=0.5, rely=0.5, anchor="center")
            fs_stop = threading.Event()
            fs_pau  = threading.Event()
            win.protocol("WM_DELETE_WINDOW", lambda: (fs_stop.set(), win.destroy()))
            threading.Thread(target=self._igmp_video_worker,
                             args=(g, p, c2, lbl2, fs_stop, fs_pau),
                             daemon=True).start()

        tk.Button(ctrl, text="⛶", command=_fullscreen,
                  bg="#111122", fg="white", relief="flat",
                  font=("Segoe UI", 11), cursor="hand2",
                  padx=6).pack(side="left")

        # ⊟ Minimize/Restore canvas
        _canvas_visible = [True]

        def _toggle_minimize():
            if _canvas_visible[0]:
                canvas.pack_forget()
                lbl.place_forget()
                _canvas_visible[0] = False
                min_btn.config(text="□")
            else:
                canvas.pack(fill="both", expand=True)
                lbl.place(relx=0.5, rely=0.5, anchor="center")
                _canvas_visible[0] = True
                min_btn.config(text="⊟")

        min_btn = tk.Button(ctrl, text="⊟", command=_toggle_minimize,
                            bg="#111122", fg="white", relief="flat",
                            font=("Segoe UI", 11), cursor="hand2",
                            padx=6)
        min_btn.pack(side="left")

        # ✕ Close — next to ⊟
        tk.Button(ctrl, text="✕",
                  command=lambda k=key: self._igmp_close_video_tab(k),
                  bg="#111122", fg="#ff6666", relief="flat",
                  font=("Segoe UI", 11, "bold"), cursor="hand2",
                  padx=6).pack(side="left", padx=(2, 0))

        threading.Thread(
            target=self._igmp_video_worker,
            args=(group_ip, port, canvas, lbl, stop_ev, pause_ev),
            daemon=True
        ).start()

    def _igmp_close_video_tab(self, key: str, send_leave: bool = True):
        """Stop video thread, remove tab.
        send_leave=True → also send IGMP Leave for all clients joined this group.
        send_leave=False → called internally from _igmp_leave_group to avoid loop."""
        ev = self._igmp_video_events.pop(key, None)
        if ev:
            ev.set()
        self._igmp_pause_events.pop(key, None)
        for tab in self._igmp_video_nb.tabs():
            if self._igmp_video_nb.tab(tab, "text").strip() == key:
                self._igmp_video_nb.forget(tab)
                self._log(f"[Video] Closed {key}\n", "sys", target="igmp")
                break
        if send_leave:
            # Parse "group_ip:port" and send IGMP Leave for all clients
            try:
                g_ip, p_str = key.rsplit(":", 1)
                self._igmp_leave_group(g_ip, int(p_str))
            except Exception:
                pass

    def _igmp_video_worker(self, group_ip, port, canvas, lbl,
                            stop_event, pause_event=None):
        """Scapy-relay approach: capture multicast at L2 → forward to localhost
        → cv2 reads from 127.0.0.1. No dependency on OS multicast join / localaddr."""
        import cv2 as _cv2
        from PIL import Image, ImageTk as _itk
        import time as _t
        import socket as _sock

        def _set_lbl(txt):
            self.root.after(0, lambda: lbl.config(text=txt)
                            if lbl.winfo_exists() else None)

        # ── Allocate a free loopback port ─────────────────────────────────────
        _tmp = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        _tmp.bind(("127.0.0.1", 0))
        relay_port = _tmp.getsockname()[1]
        _tmp.close()

        relay_url = (f"udp://127.0.0.1:{relay_port}"
                     f"?fifo_size=5000000&overrun_nonfatal=1&timeout=15000000")
        self._log(f"[Video] Relay {group_ip}:{port} → 127.0.0.1:{relay_port}\n",
                  "detail", target="igmp")

        # ── Relay sender socket ────────────────────────────────────────────────
        relay_sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        relay_sock.setsockopt(_sock.SOL_SOCKET, _sock.SO_SNDBUF, 4 * 1024 * 1024)

        # ── Scapy sniffer: capture multicast, strip headers, relay to localhost ─
        iface = self._igmp_current_iface
        from scapy.layers.inet import IP, UDP as _UDP

        def _on_pkt(pkt):
            if stop_event.is_set():
                return
            if _UDP not in pkt or IP not in pkt:
                return
            if pkt[IP].dst != group_ip or pkt[_UDP].dport != port:
                return
            payload = bytes(pkt[_UDP].payload)
            if not payload:
                return
            # Strip RTP header if present (version=2 in top 2 bits)
            if len(payload) >= 12 and (payload[0] >> 6) == 2:
                cc       = payload[0] & 0x0F          # CSRC count
                has_ext  = bool(payload[0] & 0x10)
                hdr_len  = 12 + cc * 4
                if has_ext and len(payload) >= hdr_len + 4:
                    ext_words = int.from_bytes(payload[hdr_len+2:hdr_len+4], "big")
                    hdr_len  += 4 + ext_words * 4
                payload = payload[hdr_len:]
            try:
                relay_sock.sendto(payload, ("127.0.0.1", relay_port))
            except Exception:
                pass

        capture_sn = AsyncSniffer(
            iface=iface,
            prn=_on_pkt,   # called for every packet; filtering done inside _on_pkt
            store=False,
            stop_filter=lambda _: stop_event.is_set()
                                  or self._igmp_stop_event.is_set(),
        )
        capture_sn.start()
        self._log(f"[Video] Scapy relay started for {group_ip}:{port}\n", "detail", target="igmp")

        # ── Open cv2 on relay port ─────────────────────────────────────────────
        cap = None
        for _attempt in range(3):
            if stop_event.is_set() or self._igmp_stop_event.is_set():
                break
            cap = _cv2.VideoCapture(relay_url, _cv2.CAP_FFMPEG)
            cap.set(_cv2.CAP_PROP_BUFFERSIZE, 1)
            if cap.isOpened():
                break
            self._log(f"[Video] Retry {_attempt+1}/3 …\n", "detail", target="igmp")
            if cap:
                cap.release()
            _t.sleep(3)

        if not cap or not cap.isOpened():
            _set_lbl(f"No stream: {group_ip}:{port}")
            self._log(f"[Video] Cannot open relay for {group_ip}:{port}\n", "err", target="igmp")
            capture_sn.stop()
            relay_sock.close()
            return

        _set_lbl("")
        self._log(f"[Video] Stream OK {group_ip}:{port} via relay\n", "recv", target="igmp")

        while not stop_event.is_set() and not self._igmp_stop_event.is_set():
            if pause_event and pause_event.is_set():
                _t.sleep(0.1)
                continue
            ret, frame = cap.read()
            if not ret:
                _t.sleep(0.02)
                continue
            try:
                cw = max(canvas.winfo_width(),  320)
                ch = max(canvas.winfo_height(), 180)
                h, w = frame.shape[:2]
                scale = min(cw / w, ch / h)
                nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
                frame  = _cv2.resize(frame, (nw, nh))
                img    = Image.fromarray(_cv2.cvtColor(frame, _cv2.COLOR_BGR2RGB))
                photo  = _itk.PhotoImage(img)

                def _draw(c=canvas, p=photo):
                    if c.winfo_exists():
                        c.delete("all")
                        c.create_image(0, 0, anchor="nw", image=p)
                        c._photo = p

                canvas.after(0, _draw)
            except Exception:
                pass
            _t.sleep(1 / 30)

        cap.release()
        try:
            capture_sn.stop()
        except Exception:
            pass
        relay_sock.close()
        self._log(f"[Video] Stopped {group_ip}:{port}\n", "sys", target="igmp")

    def _reset_table(self):
        for tree in (self.dhcp_tree, self.pppoe_tree):
            if tree:
                tree.delete(*tree.get_children())
        self._dhcp_client_rows.clear()
        self._pppoe_client_rows.clear()
        self._client_leases.clear()
        self._pppoe_leases.clear()
        # keep self._client_rows / self.client_tree in sync with active tab
        self._client_rows = (self._dhcp_client_rows
                             if self.client_tree is self.dhcp_tree
                             else self._pppoe_client_rows)
        self._summary_var.set("")

    def _table_add_row(self, idx: int, mac: str):
        row_tag = "even" if idx % 2 == 0 else "odd"
        iid = self.client_tree.insert(
            "", "end", tags=(row_tag,),
            values=(f"C{idx + 1:02d}", mac, "Waiting",
                    "-", "-", "-", "-", "-", "-", "-", "-")
        )
        self._client_rows[idx] = iid

    def _table_update(self, idx: int, **kwargs):
        """Thread-safe update of a client row.
        Keys: status, ip, mask, gw, dns, ip6, dns6, lease, ping"""
        col_idx = {"status": 2, "ip": 3, "mask": 4, "gw": 5, "dns": 6,
                   "ip6": 7, "dns6": 8, "lease": 9, "ping": 10}

        def _do():
            iid = self._client_rows.get(idx)
            if iid is None:
                return
            vals = list(self.client_tree.item(iid, "values"))
            for k, v in kwargs.items():
                if k in col_idx:
                    vals[col_idx[k]] = v
            self.client_tree.item(iid, values=vals)
            # Determine status tag, keep alternating-row tag as base
            row_tag = "even" if idx % 2 == 0 else "odd"
            status = vals[2]
            if "✔" in status or "Renewed" in status:
                tags = ("success", row_tag)
            elif "✗" in status or "Error" in status:
                tags = ("fail", row_tag)
            elif status in ("Running", "Renewing…", "Pinging…") or "Retry" in status:
                tags = ("running", row_tag)
            elif status in ("Released",):
                tags = ("released", row_tag)
            else:
                tags = (row_tag,)
            self.client_tree.item(iid, tags=tags)
            self.client_tree.see(iid)

        self.root.after(0, _do)

    def _update_summary(self, success: int, total: int):
        def _do():
            self._summary_var.set(f"{success} / {total} succeeded")
        self.root.after(0, _do)

    # ── UI callbacks ──────────────────────────────────────────────────────────

    # ── PPPoE table helpers ───────────────────────────────────────────────────

    def _pppoe_table_add_row(self, idx: int, mac: str):
        row_tag = "even" if idx % 2 == 0 else "odd"
        iid = self.pppoe_tree.insert(
            "", "end", tags=(row_tag,),
            values=(f"C{idx+1:02d}", mac, "Waiting", "-", "-", "-", "-", "-", "-")
        )
        self._pppoe_client_rows[idx] = iid

    def _pppoe_table_update(self, idx: int, **kwargs):
        _ci = {"status": 2, "session_id": 3, "ac_name": 4,
               "ip4": 5, "ip6": 6, "auth": 7, "ping": 8}

        def _do():
            iid = self._pppoe_client_rows.get(idx)
            if iid is None:
                return
            vals = list(self.pppoe_tree.item(iid, "values"))
            for k, v in kwargs.items():
                if k in _ci:
                    vals[_ci[k]] = v
            self.pppoe_tree.item(iid, values=vals)
            status  = vals[2]
            row_tag = "even" if idx % 2 == 0 else "odd"
            if "✔" in status:
                tags = ("success", row_tag)
            elif "✗" in status:
                tags = ("fail", row_tag)
            elif any(s in status for s in
                     ("Running", "PADI", "PADR", "LCP",
                      "PAP", "CHAP", "IPCP", "IPv6CP", "Disc.")):
                tags = ("running", row_tag)
            elif "Disconn" in status:
                tags = ("released", row_tag)
            else:
                tags = (row_tag,)
            self.pppoe_tree.item(iid, tags=tags)
            self.pppoe_tree.see(iid)

        self.root.after(0, _do)

    # ── PPPoE start ───────────────────────────────────────────────────────────

    def _start_pppoe(self):
        if not _SCAPY_OK:
            messagebox.showerror("Error", "scapy is not installed.\nRun: pip install scapy")
            return
        if not _PPPOE_OK:
            messagebox.showerror("Error",
                                 "PPPoE layer không khả dụng trong bản scapy này.\n"
                                 "Thử: pip install --upgrade scapy")
            return
        if self._pppoe_thread and self._pppoe_thread.is_alive():
            messagebox.showinfo("Busy", "PPPoE connect already running.")
            return

        label = self.pppoe_iface_var.get().strip()
        if not label:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        iface = self._iface_map.get(label, label)

        mac   = self.pppoe_mac_var.get().strip().lower()
        parts = mac.replace("-", ":").split(":")
        if len(parts) != 6 or not all(len(p) == 2 for p in parts):
            messagebox.showerror("Error", "Invalid MAC address.")
            return

        try:
            timeout = max(3, int(self.pppoe_timeout_var.get()))
        except ValueError:
            timeout = 10

        vlan_id = None
        vlan_str = self.pppoe_vlan_var.get().strip()
        if vlan_str:
            try:
                vlan_id = int(vlan_str)
                if not (1 <= vlan_id <= 4094):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "VLAN ID must be 1–4094 or blank.")
                return
        pcp = 0
        try:
            pcp = max(0, min(7, int(self.pppoe_pcp_var.get())))
        except ValueError:
            pcp = 0

        service_name = self.pppoe_svc_var.get().strip()
        username     = self.pppoe_user_var.get().strip()
        password     = self.pppoe_pass_var.get()
        auth_mode    = self.pppoe_auth_var.get()
        try:
            mru = max(576, min(1500, int(self.pppoe_mru_var.get())))
        except ValueError:
            mru = 1492

        try:
            num_clients = max(1, int(self.pppoe_num_clients_var.get()))
        except ValueError:
            num_clients = 1
        try:
            interval_ms = max(0, int(self.pppoe_interval_var.get()))
        except ValueError:
            interval_ms = 200

        mac_mode = self.pppoe_mac_mode_var.get()
        macs = [increment_mac(mac, i) if mac_mode == "sequential"
                else random_mac() for i in range(num_clients)]

        self._pppoe_stop_event.clear()
        self.pppoe_tree.delete(*self.pppoe_tree.get_children())
        self._pppoe_client_rows.clear()
        self._pppoe_leases.clear()
        self._summary_var.set("")

        for idx, m in enumerate(macs):
            self._pppoe_table_add_row(idx, m)

        args_common = (iface, timeout, vlan_id, pcp,
                       service_name, username, password, auth_mode, mru)

        if num_clients == 1:
            self._pppoe_thread = threading.Thread(
                target=self._pppoe_worker,
                args=(iface, macs[0], timeout, vlan_id, pcp,
                      service_name, username, password, auth_mode, mru,
                      0, 1, None),
                daemon=True
            )
        else:
            self._pppoe_thread = threading.Thread(
                target=self._pppoe_coordinator,
                args=(macs, interval_ms) + args_common,
                daemon=True
            )
        # Track ping completion for auto-stop capture
        ping_target = self.pppoe_ping_target_var.get().strip()
        self._pppoe_ping_lock      = threading.Lock()
        self._pppoe_ping_remaining = num_clients if ping_target else 0

        self._capture_target = "pppoe"
        self._start_capture(iface)
        self._pppoe_thread.start()

    def _pppoe_coordinator(self, macs, interval_ms, iface, timeout, vlan_id, pcp,
                           service_name, username, password, auth_mode, mru,
):
        import time as _t
        num   = len(macs)
        lock  = threading.Lock()
        ok    = [0]

        self._log(f"\n{'='*60}\n  PPPoE Multi-Client — {num} clients\n{'='*60}\n\n", "sys", target="pppoe")

        def _done(success):
            with lock:
                if success:
                    ok[0] += 1
            self._update_summary(ok[0], num)

        workers = []
        for idx, m in enumerate(macs):
            if self._pppoe_stop_event.is_set():
                break
            t = threading.Thread(
                target=self._pppoe_worker,
                args=(iface, m, timeout, vlan_id, pcp,
                      service_name, username, password, auth_mode, mru,
                      idx, num, _done),
                daemon=True
            )
            workers.append(t)
            t.start()
            if idx < num - 1 and interval_ms > 0:
                _t.sleep(interval_ms / 1000)

        for t in workers:
            t.join()

        s = ok[0]
        self._log(f"\n{'─'*60}\n  PPPoE done: {s}/{num} connected\n{'─'*60}\n",
                  "success" if s == num else "err", target="pppoe")
        self._update_summary(s, num)

    # ── PPPoE disconnect (PADT) ───────────────────────────────────────────────

    def _pppoe_disconnect_selected(self):
        sel = self.pppoe_tree.selection()
        if not sel:
            messagebox.showinfo("PPPoE", "Chọn ít nhất một client trong bảng.")
            return
        iid_to_idx = {v: k for k, v in self._pppoe_client_rows.items()}
        for iid in sel:
            idx = iid_to_idx.get(iid)
            if idx is not None and idx in self._pppoe_leases:
                lease = self._pppoe_leases[idx]
                threading.Thread(target=self._pppoe_padt_worker,
                                 args=(idx, lease), daemon=True).start()

    def _pppoe_padt_worker(self, client_idx: int, lease: dict):
        mac        = lease["mac"]
        ac_mac     = lease["ac_mac"]
        session_id = lease["session_id"]
        iface      = lease["iface"]
        vlan_id    = lease.get("vlan_id")
        pcp        = lease.get("pcp", 0)
        pfx        = f"[C{client_idx+1:02d}] "

        try:
            eth = Ether(src=mac, dst=ac_mac)
            if vlan_id:
                eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)
            padt = eth / PPPoED(version=1, type=1, code=0xa7, sessionid=session_id)
            sendp(padt, iface=iface, verbose=False)
            self._log(f"{pfx}>>> PADT sent (session 0x{session_id:04x} terminated)\n", "send", target="pppoe")
        except Exception as e:
            self._log(f"{pfx}[ERROR] PADT: {e}\n", "err", target="pppoe")
        finally:
            self._pppoe_leases.pop(client_idx, None)
            self._pppoe_table_update(client_idx, status="Disconnected")

    # ── PPPoE worker (full session state machine) ─────────────────────────────

    def _pppoe_worker(self, iface, mac, timeout, vlan_id, pcp,
                      service_name, username, password, auth_mode, mru,
                      client_idx, total_clients, on_done):
        import struct, time as _t, hashlib, queue as _q
        from scapy.packet import Raw

        pfx     = f"[C{client_idx+1:02d}] " if total_clients > 1 else ""
        success = False

        def log(msg, tag=None):
            if pfx:
                parts = msg.split("\n")
                msg   = "\n".join((pfx + p) if p.strip() else p for p in parts)
            self._log(msg, tag, target="pppoe")

        try:
            # ── Packet builders ───────────────────────────────────────────────
            def _eth(dst="ff:ff:ff:ff:ff:ff"):
                e = Ether(src=mac, dst=dst)
                if vlan_id:
                    e = e / Dot1Q(vlan=vlan_id, prio=pcp)
                return e

            def _tag(t, v=b""):
                if isinstance(v, str):
                    v = v.encode()
                return struct.pack("!HH", t, len(v)) + v

            def _parse_tags(raw):
                tags, i = {}, 0
                while i + 4 <= len(raw):
                    t, l = struct.unpack_from("!HH", raw, i)
                    if t == 0:
                        break
                    tags[t] = raw[i+4: i+4+l]
                    i += 4 + l
                return tags

            svc_b     = service_name.encode() if service_name else b""
            host_uniq = struct.pack("!I", random.randint(0, 0xFFFFFFFF))

            log("=" * 58 + "\n", "sys")
            log("  PPPoE Session\n", "sys")
            log(f"  Interface : {iface}\n", "sys")
            log(f"  Client MAC: {mac}\n", "sys")
            log(f"  Auth      : {auth_mode.upper()}\n", "sys")
            log("=" * 58 + "\n\n", "sys")

            # ── PADI ──────────────────────────────────────────────────────────
            self._pppoe_table_update(client_idx, status="Disc.")
            tags_padi = _tag(0x0101, svc_b) + _tag(0x0103, host_uniq)
            padi = (_eth() /
                    PPPoED(version=1, type=1, code=0x09, sessionid=0) /
                    Raw(tags_padi))

            pado_pkt = None
            t_retry  = float(timeout)
            for attempt in range(4):
                if self._pppoe_stop_event.is_set():
                    return
                sniffer = AsyncSniffer(
                    iface=iface,
                    lfilter=lambda p: (
                        PPPoED in p and p[PPPoED].code == 0x07 and
                        _parse_tags(bytes(p[PPPoED].payload)).get(0x0103) == host_uniq
                    ),
                    count=1, timeout=t_retry,
                    stop_filter=lambda _: self._pppoe_stop_event.is_set(),
                )
                sniffer.start()
                log(f">>> PADI (attempt {attempt+1})\n", "send")
                sendp(padi, iface=iface, verbose=False)
                sniffer.join(timeout=t_retry + 1)
                if sniffer.results:
                    pado_pkt = sniffer.results[0]
                    break
                log("    No PADO — retrying\n", "err")
                t_retry = max(1.0, min(t_retry * 2, 64) + random.uniform(-1, 1))

            if not pado_pkt:
                log("[TIMEOUT] No PADO\n", "err")
                self._pppoe_table_update(client_idx, status="✗ No PADO")
                return

            ac_mac    = pado_pkt[Ether].src
            pado_tags = _parse_tags(bytes(pado_pkt[PPPoED].payload))
            ac_name   = pado_tags.get(0x0102, b"").decode(errors="replace")
            ac_cookie = pado_tags.get(0x0104)
            log(f"<<< PADO  AC='{ac_name}'  {ac_mac}\n", "recv")
            self._pppoe_table_update(client_idx, status="PADR…", ac_name=ac_name)

            # ── PADR → PADS ───────────────────────────────────────────────────
            tags_padr = _tag(0x0101, svc_b) + _tag(0x0103, host_uniq)
            if ac_cookie:
                tags_padr += _tag(0x0104, ac_cookie)
            padr = (_eth(ac_mac) /
                    PPPoED(version=1, type=1, code=0x19, sessionid=0) /
                    Raw(tags_padr))

            sniffer = AsyncSniffer(
                iface=iface,
                lfilter=lambda p: (
                    PPPoED in p and p[PPPoED].code in (0x65, 0xa7) and
                    _parse_tags(bytes(p[PPPoED].payload)).get(0x0103) == host_uniq
                ),
                count=1, timeout=timeout,
                stop_filter=lambda _: self._pppoe_stop_event.is_set(),
            )
            sniffer.start()
            log(">>> PADR\n", "send")
            sendp(padr, iface=iface, verbose=False)
            log("<<< Waiting for PADS…\n", "sys")
            sniffer.join(timeout=timeout + 1)

            if not sniffer.results:
                log("[TIMEOUT] No PADS\n", "err")
                self._pppoe_table_update(client_idx, status="✗ No PADS")
                return

            pads = sniffer.results[0]
            if pads[PPPoED].code == 0xa7:
                log("[REJECTED] PADT received\n", "err")
                self._pppoe_table_update(client_idx, status="✗ Rejected")
                return

            session_id = pads[PPPoED].sessionid
            log(f"<<< PADS  session=0x{session_id:04x}\n", "recv")
            self._pppoe_table_update(client_idx, status="LCP…",
                                     session_id=f"0x{session_id:04x}")

            # Store for disconnect
            self._pppoe_leases[client_idx] = dict(
                session_id=session_id, ac_mac=ac_mac, mac=mac,
                iface=iface, vlan_id=vlan_id, pcp=pcp, ip4=None, ip6=None
            )

            # ── PPP session queue ─────────────────────────────────────────────
            ppp_q = _q.Queue()

            def _ppp_filter(p):
                _dst = p.dst.lower() if hasattr(p, 'dst') else ''
                return (PPPoE in p and
                        p[PPPoE].sessionid == session_id and
                        p[PPPoE].code == 0 and
                        (_dst == mac.lower() or _dst.startswith("33:33:")))

            session_sn = AsyncSniffer(
                iface=iface,
                lfilter=_ppp_filter,
                prn=lambda p: ppp_q.put(bytes(p[PPPoE].payload)),
                store=False,
                stop_filter=lambda _: self._pppoe_stop_event.is_set(),
            )
            session_sn.start()

            def _send_ppp(proto, payload):
                pkt = (_eth(ac_mac) /
                       PPPoE(version=1, type=1, code=0, sessionid=session_id) /
                       Raw(struct.pack("!H", proto) + payload))
                sendp(pkt, iface=iface, verbose=False)

            def _recv_ppp(proto_want=None, codes=None, t=float(timeout)):
                deadline = _t.time() + t
                while _t.time() < deadline:
                    try:
                        raw = ppp_q.get(timeout=min(0.3, deadline - _t.time()))
                    except _q.Empty:
                        if self._pppoe_stop_event.is_set():
                            return None, None
                        continue
                    if len(raw) < 4:
                        continue
                    proto   = struct.unpack_from("!H", raw)[0]
                    payload = raw[2:]
                    # Respond to LCP echo silently
                    if proto == 0xc021 and payload and payload[0] == 9:
                        _send_ppp(0xc021, struct.pack("!BBH", 10, payload[1],
                                                      len(payload)) + payload[4:])
                        continue
                    # Auto-ack BRAS IPv6CP Config-Req during any non-IPv6CP phase
                    # (during IPv6CP phase, proto_want==0x8057 so we return it to caller)
                    if (proto == 0x8057 and proto_want != 0x8057 and
                            payload and len(payload) >= 4 and payload[0] == 1):
                        _v6p = payload[1]; _v6ln = struct.unpack_from("!H", payload, 2)[0]
                        if 4 <= _v6ln <= len(payload) + 4:
                            _send_ppp(0x8057,
                                      struct.pack("!BBH", 2, _v6p, _v6ln) +
                                      payload[4:_v6ln])
                        continue  # consume — do NOT re-queue
                    if proto_want is not None and proto != proto_want:
                        ppp_q.put(raw); _t.sleep(0.01); continue
                    if codes is not None and (not payload or payload[0] not in codes):
                        ppp_q.put(raw); _t.sleep(0.01); continue
                    return proto, payload
                return None, None

            # ── LCP ───────────────────────────────────────────────────────────
            magic    = random.randint(1, 0xFFFFFFFF)
            lcp_id   = random.randint(1, 255)
            our_opts = (struct.pack("!BBH", 1, 4, mru) +
                        struct.pack("!BBI", 5, 6, magic))
            peer_auth_proto = None
            lcp_ok  = False

            for _ in range(6):
                if self._pppoe_stop_event.is_set():
                    return
                req = struct.pack("!BBH", 1, lcp_id, 4 + len(our_opts)) + our_opts
                _send_ppp(0xc021, req)
                log(f">>> LCP Config-Req (id={lcp_id})\n", "send")

                deadline = _t.time() + float(timeout)
                while _t.time() < deadline and not lcp_ok:
                    try:
                        raw = ppp_q.get(timeout=min(0.4, deadline - _t.time()))
                    except _q.Empty:
                        continue
                    if len(raw) < 6:
                        continue
                    proto = struct.unpack_from("!H", raw)[0]
                    if proto != 0xc021:
                        # Auto-ack BRAS IPv6CP Config-Req during LCP phase
                        if proto == 0x8057 and len(raw) > 6 and raw[2] == 1:
                            _v6p = raw[3]; _v6ln = struct.unpack_from("!H", raw, 4)[0]
                            if 4 <= _v6ln <= len(raw) - 2:
                                _send_ppp(0x8057,
                                          struct.pack("!BBH", 2, _v6p, _v6ln) +
                                          raw[6:2 + _v6ln])
                        else:
                            ppp_q.put(raw)
                        continue
                    pl = raw[2:]
                    code, pid, ln = struct.unpack_from("!BBH", pl)
                    data = pl[4:ln]
                    if code == 2:   # Ack
                        log("<<< LCP Config-Ack\n", "recv")
                        lcp_ok = True
                    elif code == 3: # Nak — adopt suggestions
                        log("<<< LCP Config-Nak\n", "sys")
                        i2 = 0
                        while i2 + 2 <= len(data):
                            ot, ol = data[i2], data[i2+1]
                            ov = data[i2+2:i2+ol]
                            if ot == 1 and len(ov) >= 2:
                                mru = struct.unpack_from("!H", ov)[0]
                            i2 += max(ol, 2)
                        our_opts = (struct.pack("!BBH", 1, 4, mru) +
                                    struct.pack("!BBI", 5, 6, magic))
                        lcp_id = lcp_id % 255 + 1
                    elif code == 4: # Reject — strip rejected opts
                        log("<<< LCP Config-Reject\n", "sys")
                        our_opts = struct.pack("!BBH", 1, 4, mru)
                        lcp_id = lcp_id % 255 + 1
                    elif code == 1: # Peer Config-Req
                        i2 = 0
                        while i2 + 2 <= len(data):
                            ot, ol = data[i2], data[i2+1]
                            ov = data[i2+2:i2+ol]
                            if ot == 3 and len(ov) >= 2:
                                peer_auth_proto = struct.unpack_from("!H", ov)[0]
                            i2 += max(ol, 2)
                        ack = struct.pack("!BBH", 2, pid, ln) + data
                        _send_ppp(0xc021, ack)
                        log(">>> LCP Config-Ack (peer)\n", "send")
                    elif code == 9: # Echo-Req
                        _send_ppp(0xc021, struct.pack("!BBHI", 10, pid, 8, magic))
                if lcp_ok:
                    break

            if not lcp_ok:
                log("[ERROR] LCP failed\n", "err")
                self._pppoe_table_update(client_idx, status="✗ LCP Fail")
                session_sn.stop(); return

            # ── Auth ──────────────────────────────────────────────────────────
            eff_auth = auth_mode
            if auth_mode == "auto":
                eff_auth = ({0xc023: "pap", 0xc223: "chap"}
                            .get(peer_auth_proto, "none"))

            self._pppoe_table_update(client_idx,
                                     status=eff_auth.upper() + "…" if eff_auth != "none" else "IPCP…",
                                     auth=eff_auth.upper())

            if eff_auth == "pap":
                log(f">>> PAP Auth-Request (user='{username}')\n", "send")
                ub = username.encode(); pb = password.encode()
                pd = struct.pack("!B", len(ub)) + ub + struct.pack("!B", len(pb)) + pb
                pap_req = struct.pack("!BBH", 1, random.randint(1, 255), 4 + len(pd)) + pd
                _send_ppp(0xc023, pap_req)
                _, pr = _recv_ppp(0xc023, {2, 3})
                if pr is None:
                    log("[TIMEOUT] PAP no response\n", "err")
                    self._pppoe_table_update(client_idx, status="✗ PAP Timeout")
                    session_sn.stop(); return
                if pr[0] == 2:
                    log("<<< PAP Auth-Ack\n", "recv")
                else:
                    log("[FAIL] PAP Auth-Nak\n", "err")
                    self._pppoe_table_update(client_idx, status="✗ PAP Fail")
                    session_sn.stop(); return

            elif eff_auth == "chap":
                log("<<< Waiting for CHAP Challenge…\n", "sys")
                _, chal = _recv_ppp(0xc223, {1})
                if chal is None:
                    log("[TIMEOUT] CHAP no challenge\n", "err")
                    self._pppoe_table_update(client_idx, status="✗ CHAP Timeout")
                    session_sn.stop(); return
                cid = chal[1]
                vlen = chal[4] if len(chal) > 4 else 0
                cv   = chal[5: 5 + vlen]
                resp_val = hashlib.md5(bytes([cid]) + password.encode() + cv).digest()
                ub = username.encode()
                cr = struct.pack("!BBH", 2, cid,
                                 4 + 1 + len(resp_val) + len(ub))
                cr += struct.pack("!B", len(resp_val)) + resp_val + ub
                log(f">>> CHAP Response (user='{username}')\n", "send")
                _send_ppp(0xc223, cr)
                _, res = _recv_ppp(0xc223, {3, 4})
                if res is None or res[0] != 3:
                    log("[FAIL] CHAP Failure\n", "err")
                    self._pppoe_table_update(client_idx, status="✗ CHAP Fail")
                    session_sn.stop(); return
                log("<<< CHAP Success\n", "recv")

            # ── IPCP ──────────────────────────────────────────────────────────
            self._pppoe_table_update(client_idx, status="IPCP…")
            our_ip = b"\x00\x00\x00\x00"
            ipcp_id = random.randint(1, 255)
            ip4_addr = None

            for _ in range(6):
                if self._pppoe_stop_event.is_set(): break
                opts = struct.pack("!BB", 3, 6) + our_ip
                _send_ppp(0x8021, struct.pack("!BBH", 1, ipcp_id, 4 + len(opts)) + opts)
                log(f">>> IPCP Config-Req ({'.'.join(str(b) for b in our_ip)})\n", "send")
                _, ir = _recv_ppp(0x8021, {1, 2, 3, 4})
                if ir is None: break
                if ir[0] == 2:
                    ip4_addr = ".".join(str(b) for b in our_ip)
                    log(f"<<< IPCP Config-Ack  IP={ip4_addr}\n", "recv")
                    # Ack peer's IPCP if queued
                    _, pi = _recv_ppp(0x8021, {1}, t=1.0)
                    if pi:
                        pid2 = pi[1]; ln2 = struct.unpack_from("!H", pi, 2)[0]
                        _send_ppp(0x8021, struct.pack("!BBH", 2, pid2, ln2) + pi[4:ln2])
                    break
                elif ir[0] == 3:
                    i2 = 4
                    while i2 + 2 <= len(ir):
                        ot, ol = ir[i2], ir[i2+1]
                        if ot == 3 and ol == 6:
                            our_ip = ir[i2+2: i2+6]
                            log(f"<<< IPCP Nak → {'.'.join(str(b) for b in our_ip)}\n", "sys")
                        i2 += max(ol, 2)
                    ipcp_id = ipcp_id % 255 + 1
                elif ir[0] == 1:  # peer req
                    pid2 = ir[1]; ln2 = struct.unpack_from("!H", ir, 2)[0]
                    _send_ppp(0x8021, struct.pack("!BBH", 2, pid2, ln2) + ir[4:ln2])
                else:
                    log("<<< IPCP Config-Reject\n", "err"); break

            if ip4_addr:
                self._pppoe_leases[client_idx]["ip4"] = ip4_addr
                self._pppoe_table_update(client_idx, ip4=ip4_addr)

            # ── IPv6CP ────────────────────────────────────────────────────────
            self._pppoe_table_update(client_idx, status="IPv6CP…")
            # Build EUI-64 interface identifier from MAC (most BRASes accept this)
            _mb = [int(x, 16) for x in mac.replace('-', ':').split(':')]
            _mb[0] ^= 0x02  # flip U/L bit
            iface_id = bytes([_mb[0], _mb[1], _mb[2], 0xFF, 0xFE,
                               _mb[3], _mb[4], _mb[5]])
            ip6_addr        = None
            iv6_id          = random.randint(1, 255)
            _peer_req_acked = False
            _v6_fatal       = False

            # One long deadline shared across all retransmissions
            _v6dl = _t.time() + float(timeout) * 2  # allow up to 2× timeout

            def _v6cp_send_req():
                nonlocal iv6_id
                _o = struct.pack("!BB", 1, 10) + iface_id
                _send_ppp(0x8057,
                          struct.pack("!BBH", 1, iv6_id, 4 + len(_o)) + _o)
                iv6_id = iv6_id % 255 + 1

            _v6cp_send_req()
            log(">>> IPv6CP Config-Req\n", "send")

            while not self._pppoe_stop_event.is_set() and _t.time() < _v6dl:
                _t_left = _v6dl - _t.time()
                if _t_left <= 0:
                    break
                _, v6r = _recv_ppp(0x8057, {1, 2, 3, 4},
                                   t=min(3.0, _t_left))

                if v6r is None:
                    # No response within 3 s → resend Config-Req and keep waiting
                    if _t.time() < _v6dl:
                        _v6cp_send_req()
                        log(">>> IPv6CP Config-Req (resend)\n", "send")
                    continue

                _v6code = v6r[0]

                if _v6code == 1:
                    # Peer's Config-Req → ack it, keep waiting for our Ack
                    _pid = v6r[1]; _ln = struct.unpack_from("!H", v6r, 2)[0]
                    _send_ppp(0x8057,
                              struct.pack("!BBH", 2, _pid, _ln) + v6r[4:_ln])
                    log(f">>> IPv6CP Config-Ack (peer id={_pid})\n", "send")
                    _peer_req_acked = True

                elif _v6code == 2:
                    # Config-Ack for our request → success
                    b = iface_id
                    ip6_addr = (f"fe80::"
                                f"{b[0]:02x}{b[1]:02x}:{b[2]:02x}{b[3]:02x}:"
                                f"{b[4]:02x}{b[5]:02x}:{b[6]:02x}{b[7]:02x}")
                    log(f"<<< IPv6CP Ack  {ip6_addr}\n", "recv")
                    break

                elif _v6code == 3:
                    # Config-Nak → update interface-ID and resend
                    # Option layout: type(1B)+len(1B)+IID(8B), starts at v6r[4]
                    if len(v6r) >= 14 and v6r[4] == 1:
                        iface_id = v6r[6:14]  # skip type(1) + length(1) bytes
                    log("    IPv6CP Nak → resend with new IID\n", "detail")
                    _v6cp_send_req()
                    log(">>> IPv6CP Config-Req (new IID)\n", "send")

                elif _v6code == 4:
                    # Config-Reject → permanent failure
                    log(f"    IPv6CP: Config-Reject\n", "detail")
                    _v6_fatal = True
                    break

                else:
                    # Unexpected code — log and ignore, keep waiting
                    log(f"    IPv6CP: unexpected code {v6r[0]}, ignoring\n", "detail")

            if not ip6_addr and not _v6_fatal:
                log("    IPv6CP: timed out\n", "detail")

            # Peer may send its Config-Req AFTER sending Ack for ours
            if ip6_addr and not _peer_req_acked:
                _, pi = _recv_ppp(0x8057, {1}, t=2.0)
                if pi:
                    _pid = pi[1]; _ln = struct.unpack_from("!H", pi, 2)[0]
                    _send_ppp(0x8057,
                              struct.pack("!BBH", 2, _pid, _ln) + pi[4:_ln])
                    log(f">>> IPv6CP Config-Ack (peer id={_pid})\n", "send")

            if ip6_addr:
                self._pppoe_leases[client_idx]["ip6"] = ip6_addr
                self._pppoe_table_update(client_idx, ip6=ip6_addr)

            # ── IPv6 Global Address: RS/RA (SLAAC) then DHCPv6 fallback ─────────
            ip6_gua = None
            if ip6_addr and not self._pppoe_stop_event.is_set():
                import ipaddress as _ipaddr

                # Helper: recv one IPv6 PPP packet within deadline
                def _recv_ipv6_ppp(deadline):
                    if _t.time() >= deadline:
                        return None
                    _, _r6 = _recv_ppp(0x0057, None,
                                       t=min(2.0, deadline - _t.time()))
                    if not _r6:
                        return None
                    try:
                        return IPv6(_r6)
                    except Exception:
                        return None

                # ── Step 1: Router Solicitation → Router Advertisement (SLAAC) ──
                self._pppoe_table_update(client_idx, status="RS/RA…")
                _ra_m_flag = 0  # init before loop so check below is safe
                _last_rs   = _t.time() - 99  # force immediate first RS

                _ra_dl = _t.time() + float(timeout)
                while _t.time() < _ra_dl and not self._pppoe_stop_event.is_set():
                    # (Re)send RS every ~4 s until RA arrives
                    if _t.time() - _last_rs >= 4.0:
                        try:
                            _rs = IPv6(src=ip6_addr, dst="ff02::2") / ICMPv6ND_RS()
                            _send_ppp(0x0057, bytes(_rs))
                            log(">>> Router Solicitation (RS)\n", "send")
                            _last_rs = _t.time()
                        except Exception as _e:
                            log(f"    RS build error: {_e}\n", "detail")
                            break

                    _p6 = _recv_ipv6_ppp(_ra_dl)
                    if _p6 is None:
                        continue   # timeout slice expired, loop back to check deadline
                    if _p6.haslayer(ICMPv6ND_RA):
                        log("<<< Router Advertisement (RA) received\n", "recv")
                        _ra = _p6[ICMPv6ND_RA]
                        log(f"    M={_ra.M}  O={_ra.O}  "
                            f"RouterLifetime={_ra.routerlifetime}s\n", "detail")
                        # Walk RA options for prefix
                        _opt = _ra.payload
                        while _opt and not ip6_gua:
                            if isinstance(_opt, ICMPv6NDOptPrefixInfo):
                                _pfx = _opt
                                log(f"    Prefix: {_pfx.prefix}/{_pfx.prefixlen}  "
                                    f"A={_pfx.A}  L={_pfx.L}  "
                                    f"valid={_pfx.validlifetime}s\n", "detail")
                                if _pfx.A == 1 and _pfx.prefixlen == 64:
                                    # SLAAC: prefix[:8] + iface_id (8 bytes)
                                    _pfx_bytes = _ipaddr.IPv6Address(
                                        _pfx.prefix).packed[:8]
                                    ip6_gua = str(_ipaddr.IPv6Address(
                                        _pfx_bytes + iface_id))
                                    log(f"    SLAAC GUA  : {ip6_gua}\n", "recv")
                            _opt = _opt.payload if hasattr(_opt, 'payload') else None
                        _ra_m_flag = _ra.M
                        break
                    else:
                        log(f"    [IPv6 rx] {_p6.summary()}\n", "detail")

                # ── Step 2: DHCPv6 over PPP (if no SLAAC address or M flag set) ─
                _need_dhcpv6 = (ip6_gua is None) or bool(_ra_m_flag)

                if _need_dhcpv6 and _DHCPv6_OK and not self._pppoe_stop_event.is_set():
                    self._pppoe_table_update(client_idx, status="DHCPv6…")
                    log(">>> DHCPv6 over PPP\n", "send")

                    def _ppp_dhcpv6(ll_src):
                        """DHCPv6 SARR over PPP. Returns GUA string or None."""
                        _duid  = DUID_LL(lladdr=mac)
                        _cid   = DHCP6OptClientId(duid=_duid)
                        _iaid  = random.randint(1, 0xFFFFFFFF)
                        _trid  = random.randint(1, 0xFFFFFF)

                        sol = (IPv6(src=ll_src, dst="ff02::1:2") /
                               UDP(sport=546, dport=547) /
                               DHCP6_Solicit(trid=_trid) / _cid /
                               DHCP6OptIA_NA(iaid=_iaid, T1=0, T2=0) /
                               DHCP6OptElapsedTime(elapsedtime=0) /
                               DHCP6OptOptReq(reqopts=[23, 24]))
                        adv_p = None
                        for _att in range(3):
                            if self._pppoe_stop_event.is_set(): return None
                            _send_ppp(0x0057, bytes(sol))
                            log(f">>> DHCPv6 SOLICIT (attempt {_att + 1})\n", "send")
                            _dl = _t.time() + float(timeout)
                            while _t.time() < _dl and not self._pppoe_stop_event.is_set():
                                _p6 = _recv_ipv6_ppp(_dl)
                                if _p6 is None: continue
                                if (_p6.haslayer(DHCP6_Advertise) and
                                        _p6[DHCP6_Advertise].trid == _trid):
                                    adv_p = _p6; break
                                log(f"    [IPv6 rx] {_p6.summary()}\n", "detail")
                            if adv_p: break
                            log("    DHCPv6: no ADVERTISE\n", "detail")
                        if not adv_p: return None

                        adv_m = adv_p[DHCP6_Advertise]
                        if not (adv_m.haslayer(DHCP6OptServerId) and
                                adv_m.haslayer(DHCP6OptIA_NA)):
                            log("    DHCPv6: ADVERTISE missing SID/IA_NA\n", "detail")
                            return None

                        _sid = adv_m[DHCP6OptServerId]
                        _ia  = adv_m[DHCP6OptIA_NA]
                        _ofa = next((s for s in (_ia.ianaopts or [])
                                     if isinstance(s, DHCP6OptIAAddress)), None)
                        if not _ofa:
                            log("    DHCPv6: no IAADDR in ADVERTISE\n", "detail")
                            return None
                        log(f"<<< DHCPv6 ADVERTISE  offer={_ofa.addr}\n", "recv")

                        _trid2 = random.randint(1, 0xFFFFFF)
                        req = (IPv6(src=ll_src, dst="ff02::1:2") /
                               UDP(sport=546, dport=547) /
                               DHCP6_Request(trid=_trid2) / _cid / _sid /
                               DHCP6OptIA_NA(iaid=_iaid, T1=0, T2=0,
                                             ianaopts=[DHCP6OptIAAddress(
                                                 addr=_ofa.addr,
                                                 preflft=_ofa.preflft,
                                                 validlft=_ofa.validlft)]) /
                               DHCP6OptElapsedTime(elapsedtime=0))
                        rep_p = None
                        for _att in range(3):
                            if self._pppoe_stop_event.is_set(): return None
                            _send_ppp(0x0057, bytes(req))
                            log(f">>> DHCPv6 REQUEST (attempt {_att + 1})\n", "send")
                            _dl = _t.time() + float(timeout)
                            while _t.time() < _dl and not self._pppoe_stop_event.is_set():
                                _p6 = _recv_ipv6_ppp(_dl)
                                if _p6 is None: continue
                                if (_p6.haslayer(DHCP6_Reply) and
                                        _p6[DHCP6_Reply].trid == _trid2):
                                    rep_p = _p6; break
                                log(f"    [IPv6 rx] {_p6.summary()}\n", "detail")
                            if rep_p: break
                            log("    DHCPv6: no REPLY\n", "detail")
                        if not rep_p: return None

                        rep_m = rep_p[DHCP6_Reply]
                        if not rep_m.haslayer(DHCP6OptIA_NA): return None
                        _ia_r = rep_m[DHCP6OptIA_NA]
                        for _s in (_ia_r.ianaopts or []):
                            if isinstance(_s, DHCP6OptIAAddress):
                                log(f"<<< DHCPv6 REPLY  gua={_s.addr}\n", "recv")
                                return _s.addr
                        return None

                    _dhcp_gua = _ppp_dhcpv6(ip6_addr)
                    if _dhcp_gua:
                        ip6_gua = _dhcp_gua
                    else:
                        log("    DHCPv6: no global address obtained\n", "detail")

                if ip6_gua:
                    self._pppoe_leases[client_idx]["ip6_gua"] = ip6_gua
                    self._pppoe_table_update(client_idx, ip6=ip6_gua)
                elif ip6_addr:
                    log("    No GUA obtained — showing link-local only\n", "detail")

            # ── Connected ──────────────────────────────────────────────────────
            log("\n", None)
            log("✔ PPPoE Session Connected!\n", "success")
            log(f"  Session ID : 0x{session_id:04x}\n",   "recv")
            log(f"  AC Name    : {ac_name}\n",            "recv")
            log(f"  IPv4       : {ip4_addr or '-'}\n",    "recv")
            log(f"  IPv6 LL    : {ip6_addr or '-'}\n",    "recv")
            log(f"  IPv6 GUA   : {ip6_gua or '-'}\n",     "recv")
            log(f"  Auth       : {eff_auth.upper()}\n",   "recv")
            success = True
            self._pppoe_table_update(
                client_idx, status="✔ Connected",
                session_id=f"0x{session_id:04x}", ac_name=ac_name,
                ip4=ip4_addr or "-", ip6=ip6_gua or ip6_addr or "-",
                auth=eff_auth.upper()
            )

            # ── Auto-ping after connect ────────────────────────────────────
            ping_target = self.pppoe_ping_target_var.get().strip()
            if ping_target and ip4_addr:
                try:
                    ping_count = max(1, int(self.pppoe_ping_count_var.get()))
                except ValueError:
                    ping_count = 3
                try:
                    ping_interval_s = max(0.0, int(self.pppoe_ping_interval_var.get())) / 1000.0
                except ValueError:
                    ping_interval_s = 1.0
                threading.Thread(
                    target=self._pppoe_ping_worker,
                    args=(client_idx, self._pppoe_leases[client_idx],
                          ping_target, ping_count, ping_interval_s),
                    daemon=True
                ).start()

            # ── LCP Keep-alive loop ────────────────────────────────────────
            # Stay in loop: reply Echo-Request → keep session alive.
            # Exit when stop_event is set, or AC sends Terminate-Request.
            log("    [LCP keep-alive active — waiting for Echo-Request…]\n", "detail")
            while not self._pppoe_stop_event.is_set():
                try:
                    raw = ppp_q.get(timeout=1.0)
                except _q.Empty:
                    continue
                if len(raw) < 4:
                    continue
                proto   = struct.unpack_from("!H", raw)[0]
                payload = raw[2:]
                if not payload:
                    continue

                if proto == 0xc021:           # LCP
                    code = payload[0]
                    pid  = payload[1] if len(payload) > 1 else 0

                    if code == 9:             # Echo-Request → reply
                        echo_rep = struct.pack("!BBHI", 10, pid, 8, magic)
                        _send_ppp(0xc021, echo_rep)
                        log(f"    ↔ LCP Echo-Reply (id={pid})\n", "detail")

                    elif code == 5:           # Terminate-Request → ack + exit
                        log("[INFO] LCP Terminate-Request from AC — session ended\n", "sys")
                        term_ack = struct.pack("!BBH", 6, pid, 4)
                        _send_ppp(0xc021, term_ack)
                        self._pppoe_leases.pop(client_idx, None)
                        self._pppoe_table_update(client_idx, status="Terminated")
                        break

        except Exception as exc:
            log(f"\n[ERROR] {exc}\n", "err")
            import traceback
            log(traceback.format_exc(), "err")
            self._pppoe_table_update(client_idx, status="✗ Error")
        finally:
            try:
                if "session_sn" in dir() and getattr(session_sn, "running", False):
                    session_sn.stop()
            except Exception:
                pass
            if on_done:
                on_done(success)

    def _on_pad_mode(self):
        if self.pad_mode.get() == "manual":
            self.pad_entry.configure(state="normal")
            self.pad_var.set("0")
        else:
            self.pad_entry.configure(state="disabled")
            self.pad_var.set("auto")

    # ── Interface helpers ──────────────────────────────────────────────────────

    def _refresh_ifaces(self):
        if not _SCAPY_OK:
            return
        self._iface_map.clear()
        labels = []
        for label, name in get_iface_list():
            self._iface_map[label] = name
            labels.append(label)
        for cb, var in ((self.iface_cb,       self.iface_var),
                        (self.pppoe_iface_cb, self.pppoe_iface_var),
                        (self.igmp_iface_cb,  self.igmp_iface_var)):
            cb['values'] = labels
            if labels and not var.get():
                var.set(labels[0])

    # ── Logging ────────────────────────────────────────────────────────────────

    def _log(self, text, tag=None, target="dhcp"):
        self._log_queue.put((text, tag, target))

    def _poll_log(self):
        import time as _ts_time
        _log_map = {
            "dhcp":  getattr(self, "dhcp_log",  None),
            "pppoe": getattr(self, "pppoe_log", None),
            "igmp":  getattr(self, "igmp_log",  None),
        }
        changed = set()
        while not self._log_queue.empty():
            try:
                item = self._log_queue.get_nowait()
            except _queue.Empty:
                break
            # Support both old 2-tuple (legacy) and new 3-tuple format
            if len(item) == 3:
                text, tag, target = item
            else:
                text, tag = item
                target = "dhcp"
            _t = tag or ""
            widget = _log_map.get(target)
            if widget:
                ts = _ts_time.strftime("%H:%M:%S")
                stripped = text.lstrip('\n')
                lead = text[:len(text) - len(stripped)]
                text = f"{lead}[{ts}] {stripped}"
                widget.configure(state="normal")
                widget.insert(tk.END, text, _t)
                widget.configure(state="disabled")
                changed.add(target)
        for t in changed:
            w = _log_map.get(t)
            if w:
                w.see(tk.END)
        self.root.after(50, self._poll_log)

    def _clear_log(self):
        tab = self._proto_nb.tab(self._proto_nb.select(), "text").strip()
        if "DHCP" in tab:
            w = getattr(self, "dhcp_log", None)
        elif "PPPoE" in tab:
            w = getattr(self, "pppoe_log", None)
        elif "IGMP" in tab:
            w = getattr(self, "igmp_log", None)
        else:
            return
        if w:
            w.configure(state="normal")
            w.delete("1.0", tk.END)
            w.configure(state="disabled")

    def _save_log(self, name: str):
        from tkinter import filedialog
        _log_map = {
            "dhcp":  getattr(self, "dhcp_log",  None),
            "pppoe": getattr(self, "pppoe_log", None),
            "igmp":  getattr(self, "igmp_log",  None),
        }
        widget = _log_map.get(name)
        if not widget:
            return
        text = widget.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Save Log", "Log trống, không có gì để lưu.")
            return
        path = filedialog.asksaveasfilename(
            title=f"Lưu {name.upper()} Exchange Log",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"),
                       ("Log files", "*.log"),
                       ("All files", "*.*")],
            initialfile=f"{name}_exchange_log.txt",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            lines = len(text.splitlines())
            messagebox.showinfo("Save Log", f"Đã lưu {lines} dòng → {path}")
            self._log(f"[Log] Saved {lines} lines → {path}\n", "success", target=name)
        except Exception as exc:
            messagebox.showerror("Save Log Error", str(exc))

    def _ping_host(self, host, count=1, timeout_ms=1000):
        if not host or host == "-":
            return False
        cmd = []
        plat = platform.system().lower()
        if plat.startswith("win"):
            cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
        else:
            timeout_s = max(1, int(timeout_ms / 1000))
            cmd = ["ping", "-c", str(count), "-W", str(timeout_s), host]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

    # ── DORA logic ─────────────────────────────────────────────────────────────

    def _start_dora(self):
        if not _SCAPY_OK:
            messagebox.showerror("Error", "scapy is not installed.\nRun:  pip install scapy")
            return
        if self._thread and self._thread.is_alive():
            messagebox.showinfo("Busy", "DHCP DORA is already running.")
            return

        label = self.iface_var.get().strip()
        if not label:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        iface = self._iface_map.get(label, label)

        mac = self.mac_var.get().strip().lower()
        parts = mac.replace('-', ':').split(':')
        if len(parts) != 6 or not all(len(p) == 2 for p in parts):
            messagebox.showerror("Error",
                                 "Invalid MAC address.\nFormat: aa:bb:cc:dd:ee:ff")
            return

        try:
            timeout = max(1, int(self.timeout_var.get()))
        except ValueError:
            timeout = 5

        vlan_str = self.vlan_var.get().strip()
        vlan_id  = None
        if vlan_str:
            try:
                vlan_id = int(vlan_str)
                if not (1 <= vlan_id <= 4094):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "VLAN ID must be 1–4094 or blank.")
                return

        pcp = 0
        try:
            pcp = max(0, min(7, int(self.pcp_var.get())))
        except ValueError:
            pcp = 0

        hostname = self.hostname_var.get().strip()

        pad_mode = self.pad_mode.get()
        pad_bytes = None  # None = auto
        if pad_mode == "manual":
            try:
                pad_bytes = max(0, int(self.pad_var.get()))
            except ValueError:
                pad_bytes = 0

        try:
            num_clients = max(1, int(self.num_clients_var.get()))
        except ValueError:
            num_clients = 1

        try:
            interval_ms = max(0, int(self.interval_var.get()))
        except ValueError:
            interval_ms = 200

        mac_mode = self.mac_mode_var.get()

        # Generate all MACs up-front so the table can be populated immediately
        macs = []
        for idx in range(num_clients):
            if mac_mode == "random":
                macs.append(random_mac())
            else:
                macs.append(increment_mac(mac, idx))

        self._stop_event.clear()
        self._reset_table()
        self._threads.clear()
        for idx, m in enumerate(macs):
            self._table_add_row(idx, m)

        ping_custom = self.ping_target_var.get().strip() or None
        retry_enabled = self.retry_var.get()
        try:
            max_retries = max(1, int(self.max_retry_var.get()))
        except ValueError:
            max_retries = 4

        if self.dhcp_version_var.get() == "v6":
            if not _DHCPv6_OK:
                messagebox.showerror(
                    "Error",
                    "scapy DHCPv6 module not available.\n"
                    "Run:  pip install scapy  (version ≥ 2.4)")
                return
            if num_clients == 1:
                self._thread = threading.Thread(
                    target=self._dhcpv6_worker,
                    args=(iface, macs[0], timeout, vlan_id, pcp,
                          0, 1, None, retry_enabled, max_retries),
                    daemon=True
                )
            else:
                self._thread = threading.Thread(
                    target=self._dhcpv6_multi_coordinator,
                    args=(iface, macs, timeout, vlan_id, pcp,
                          interval_ms, retry_enabled, max_retries),
                    daemon=True
                )
        elif num_clients == 1:
            self._thread = threading.Thread(
                target=self._dora_worker,
                args=(iface, macs[0], timeout, vlan_id, pcp, hostname,
                      pad_bytes, 0, 1, None, ping_custom,
                      retry_enabled, max_retries),
                daemon=True
            )
        else:
            self._thread = threading.Thread(
                target=self._multi_coordinator,
                args=(iface, macs, timeout, vlan_id, pcp,
                      hostname, pad_bytes, interval_ms, ping_custom,
                      retry_enabled, max_retries),
                daemon=True
            )
        self._capture_target = "dhcp"
        self._start_capture(iface)
        self._thread.start()
        # Auto-stop capture when all DHCP workers finish (DORA + ping are done)
        _t = self._thread
        threading.Thread(target=lambda: (_t.join(), self._stop_capture()),
                         daemon=True).start()

    # ── DHCPv6 SARR worker ────────────────────────────────────────────────────

    def _dhcpv6_worker(self, iface, mac, timeout, vlan_id=None, pcp=0,
                       client_idx=0, total_clients=1, on_done=None,
                       retry_enabled=True, max_retries=4):
        import time as _time
        pfx     = f"[C{client_idx + 1:02d}] " if total_clients > 1 else ""
        success = False

        def log(msg, tag=None):
            if pfx:
                parts = msg.split('\n')
                msg2  = '\n'.join((pfx + p) if p.strip() else p for p in parts)
            else:
                msg2 = msg
            self._log(msg2, tag)

        try:
            ll_addr = mac_to_link_local(mac)
            duid    = DUID_LL(lladdr=mac)
            cid_opt = DHCP6OptClientId(duid=duid)
            trid    = random.randint(1, 0xFFFFFF)
            iaid    = random.randint(1, 0xFFFFFFFF)

            def _l2(dst="33:33:00:01:00:02"):
                eth = Ether(dst=dst, src=mac)
                if vlan_id:
                    return eth / Dot1Q(vlan=vlan_id, prio=pcp)
                return eth

            _RFC_INIT = 1.0
            _RFC_MAX  = 120.0

            def _next_t(t):
                return min(t * 2 + random.uniform(-0.1 * t, 0.1 * t), _RFC_MAX)

            self._table_update(client_idx, status="Running")
            vlan_info = f"VLAN {vlan_id}  PCP {pcp}" if vlan_id else "untagged"

            log("=" * 60 + "\n", "sys")
            log("  DHCPv6 Client — SARR Sequence\n", "sys")
            log(f"  Interface : {iface}\n", "sys")
            log(f"  Client MAC: {mac}\n", "sys")
            log(f"  Link-Local: {ll_addr}\n", "sys")
            log(f"  VLAN      : {vlan_info}\n", "sys")
            log("=" * 60 + "\n\n", "sys")

            t0      = _time.time()
            t_retry = _RFC_INIT if retry_enabled else float(timeout)
            n_tries = max_retries if retry_enabled else 0
            adv_pkts = []

            # ── 1+2: SOLICIT → ADVERTISE ─────────────────────────────────────
            log(">>> [1/4] DHCPv6 SOLICIT\n", "send")

            for attempt in range(n_tries + 1):
                if self._stop_event.is_set():
                    log("\n[Stopped]\n", "sys"); return

                elapsed_cs = min(int((_time.time() - t0) * 100), 65535)
                solicit = (
                    _l2() /
                    IPv6(src=ll_addr, dst="ff02::1:2") /
                    UDP(sport=546, dport=547) /
                    DHCP6_Solicit(trid=trid) /
                    cid_opt /
                    DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0) /
                    DHCP6OptElapsedTime(elapsedtime=elapsed_cs) /
                    DHCP6OptOptReq(reqopts=[23, 24])
                )

                label = (f"  attempt 1/{n_tries + 1}  timeout={t_retry:.1f}s"
                         if attempt == 0 else
                         f"  retry {attempt}/{n_tries}  timeout={t_retry:.1f}s")
                log(f"    SOLICIT {label}\n", "send" if attempt == 0 else "sys")

                adv_sn = AsyncSniffer(
                    iface=iface,
                    filter="udp and src port 547 and dst port 546",
                    lfilter=lambda p, _t=trid: (
                        IPv6 in p and DHCP6_Advertise in p and
                        p[DHCP6_Advertise].trid == _t
                    ),
                    count=1, timeout=t_retry,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
                adv_sn.start()
                sendp(solicit, iface=iface, verbose=False)
                log(f"<<< [2/4] Waiting for ADVERTISE  ({t_retry:.1f}s) ...\n", "sys")
                adv_sn.join(timeout=t_retry + 1)
                adv_pkts = adv_sn.results or []

                if adv_pkts:
                    break
                if attempt < n_tries:
                    log("    No ADVERTISE — will retry.\n", "err")
                    self._table_update(client_idx, status=f"Retry {attempt + 1}/{n_tries}")
                    t_retry = _next_t(t_retry)

            if not adv_pkts:
                log(f"[TIMEOUT] No DHCPv6 ADVERTISE after {n_tries + 1} attempt(s).\n", "err")
                self._table_update(client_idx, status="✗ No ADVERTISE")
                return

            adv = adv_pkts[0]
            if not adv.haslayer(DHCP6OptServerId):
                log("[ERROR] ADVERTISE has no Server ID option.\n", "err")
                self._table_update(client_idx, status="✗ No Server ID")
                return

            srv_id_opt  = adv[DHCP6OptServerId]
            offered_ia  = adv[DHCP6OptIA_NA] if adv.haslayer(DHCP6OptIA_NA) else None
            offered_opt = None
            if offered_ia:
                for sub in (offered_ia.ianaopts or []):
                    if isinstance(sub, DHCP6OptIAAddress):
                        offered_opt = sub; break

            if not offered_opt:
                log("[ERROR] ADVERTISE has no IA_NA address.\n", "err")
                self._table_update(client_idx, status="✗ No Addr Offer")
                return

            log(f"<<< [ADVERTISE] offered={offered_opt.addr}\n", "recv")
            self._table_update(client_idx, ip6=offered_opt.addr)

            # ── 3+4: REQUEST → REPLY ─────────────────────────────────────────
            log(">>> [3/4] DHCPv6 REQUEST\n", "send")
            trid2   = random.randint(1, 0xFFFFFF)
            t_retry = _RFC_INIT if retry_enabled else float(timeout)
            rep_pkts = []

            for attempt in range(n_tries + 1):
                if self._stop_event.is_set():
                    log("\n[Stopped]\n", "sys"); return

                elapsed_cs = min(int((_time.time() - t0) * 100), 65535)
                request = (
                    _l2() /
                    IPv6(src=ll_addr, dst="ff02::1:2") /
                    UDP(sport=546, dport=547) /
                    DHCP6_Request(trid=trid2) /
                    cid_opt / srv_id_opt /
                    DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0,
                                  ianaopts=[DHCP6OptIAAddress(
                                      addr=offered_opt.addr,
                                      preflft=offered_opt.preflft,
                                      validlft=offered_opt.validlft)]) /
                    DHCP6OptElapsedTime(elapsedtime=elapsed_cs) /
                    DHCP6OptOptReq(reqopts=[23, 24])
                )

                if attempt > 0:
                    log(f"    retry {attempt}/{n_tries}  timeout={t_retry:.1f}s\n", "sys")

                rep_sn = AsyncSniffer(
                    iface=iface,
                    filter="udp and src port 547 and dst port 546",
                    lfilter=lambda p, _t=trid2: (
                        IPv6 in p and DHCP6_Reply in p and
                        p[DHCP6_Reply].trid == _t
                    ),
                    count=1, timeout=t_retry,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
                rep_sn.start()
                sendp(request, iface=iface, verbose=False)
                log(f"<<< [4/4] Waiting for REPLY  ({t_retry:.1f}s) ...\n", "sys")
                rep_sn.join(timeout=t_retry + 1)
                rep_pkts = rep_sn.results or []

                if rep_pkts:
                    break
                if attempt < n_tries:
                    log("    No REPLY — will retry.\n", "err")
                    t_retry = _next_t(t_retry)

            if not rep_pkts:
                log(f"[TIMEOUT] No DHCPv6 REPLY after {n_tries + 1} attempt(s).\n", "err")
                self._table_update(client_idx, status="✗ No REPLY")
                return

            rep     = rep_pkts[0]
            rep_msg = rep[DHCP6_Reply]
            ia_na_r = rep_msg[DHCP6OptIA_NA] if rep_msg.haslayer(DHCP6OptIA_NA) else None
            assigned_opt = None
            if ia_na_r:
                for sub in (ia_na_r.ianaopts or []):
                    if isinstance(sub, DHCP6OptIAAddress):
                        assigned_opt = sub; break

            if not assigned_opt:
                log("[ERROR] No address in REPLY IA_NA.\n", "err")
                self._table_update(client_idx, status="✗ No Addr Reply")
                return

            dns_list = []
            if rep_msg.haslayer(DHCP6OptDNSServers):
                dns_list = [str(a) for a in rep_msg[DHCP6OptDNSServers].dnsservers]

            t1_val  = ia_na_r.T1 if ia_na_r else 0
            t2_val  = ia_na_r.T2 if ia_na_r else 0
            vl      = assigned_opt.validlft
            pl      = assigned_opt.preflft
            ip6_str = assigned_opt.addr
            dns_str = ", ".join(dns_list) if dns_list else "-"
            vl_str  = lease_fmt(vl) if vl else "-"

            log("\n", None)
            log("✔ DHCPv6 SARR completed!\n", "success")
            log("-" * 60 + "\n", "detail")
            log(f"  IPv6 Address : {ip6_str}\n",             "recv")
            log(f"  Preferred    : {lease_fmt(pl) if pl else '-'}\n", "recv")
            log(f"  Valid Lft    : {vl_str}\n",               "recv")
            log(f"  T1 (Renew)   : {lease_fmt(t1_val) if t1_val else '-'}\n", "detail")
            log(f"  T2 (Rebind)  : {lease_fmt(t2_val) if t2_val else '-'}\n", "detail")
            log(f"  DNS Servers  : {dns_str}\n",              "recv")
            log("-" * 60 + "\n", "detail")

            success = True
            self._client_leases[client_idx] = {
                "version": "v6",
                "ip6":      ip6_str,
                "vl":       vl,
                "t1":       t1_val,
                "mac":      mac,
                "iface":    iface,
                "vlan_id":  vlan_id,
                "pcp":      pcp,
                "srv_id":   srv_id_opt,
                "iaid":     iaid,
                "cid":      cid_opt,
                "ll_addr":  ll_addr,
            }
            self._table_update(client_idx, status="✔ REPLY",
                               ip6=ip6_str, dns6=dns_str, lease=vl_str, ping="-")

            if vl and t1_val and not self._stop_event.is_set():
                log(f"  Auto-Renew   : will renew in {lease_fmt(t1_val)}\n", "detail")
                threading.Thread(
                    target=self._dhcpv6_renew_loop,
                    args=(client_idx, iface, mac, ll_addr, vlan_id, pcp,
                          cid_opt, srv_id_opt, iaid, ip6_str, pl, vl, t1_val),
                    daemon=True,
                ).start()

        except PermissionError:
            log("\n[PERMISSION ERROR] Run this tool as Administrator.\n", "err")
            self._table_update(client_idx, status="✗ No Permission")
        except Exception as exc:
            log(f"\n[ERROR] {exc}\n", "err")
            import traceback
            log(traceback.format_exc(), "err")
            self._table_update(client_idx, status="✗ Error")
        finally:
            if on_done is not None:
                on_done(success)

    # ── DHCPv6 multi-client coordinator ──────────────────────────────────────

    def _dhcpv6_multi_coordinator(self, iface, macs, timeout, vlan_id, pcp,
                                   interval_ms, retry_enabled=True, max_retries=4):
        import time as _time
        num_clients      = len(macs)
        self._mc_success = 0
        self._mc_total   = num_clients
        lock = threading.Lock()

        self._log(f"\n{'='*60}\n", "sys")
        self._log(f"  Multi-Client DHCPv6 — {num_clients} clients  "
                  f"interval={interval_ms} ms\n", "sys")
        self._log(f"{'='*60}\n\n", "sys")

        def _on_done(ok: bool):
            with lock:
                if ok:
                    self._mc_success += 1
                done = self._mc_success
            self._update_summary(done, num_clients)

        workers = []
        for idx, client_mac in enumerate(macs):
            if self._stop_event.is_set():
                break
            t = threading.Thread(
                target=self._dhcpv6_worker,
                args=(iface, client_mac, timeout, vlan_id, pcp,
                      idx, num_clients, _on_done, retry_enabled, max_retries),
                daemon=True,
            )
            workers.append(t)
            t.start()
            if idx < num_clients - 1 and interval_ms > 0:
                _time.sleep(interval_ms / 1000.0)

        for t in workers:
            t.join()

        success = self._mc_success
        self._log(f"\n{'─'*60}\n", "detail")
        self._log(f"  Multi-Client DHCPv6 done: {success}/{num_clients} succeeded\n",
                  "success" if success == num_clients else "err")
        self._log(f"{'─'*60}\n", "detail")
        self._update_summary(success, num_clients)

    # ── DHCPv6 auto-renew loop ────────────────────────────────────────────────

    def _dhcpv6_renew_loop(self, client_idx, iface, mac, ll_addr, vlan_id, pcp,
                            cid_opt, srv_id_opt, iaid,
                            ip6_addr, preflft, validlft, t1):
        import time as _time
        pfx        = f"[C{client_idx + 1:02d}] "
        current_t1 = t1

        def _l2(dst="33:33:00:01:00:02"):
            eth = Ether(dst=dst, src=mac)
            if vlan_id:
                return eth / Dot1Q(vlan=vlan_id, prio=pcp)
            return eth

        while not self._stop_event.is_set():
            deadline = _time.monotonic() + current_t1
            while not self._stop_event.is_set():
                rem = int(deadline - _time.monotonic())
                if rem <= 0:
                    break
                h, r = divmod(rem, 3600)
                m, s = divmod(r, 60)
                label = (f"T1 {h}h{m:02d}m" if h else
                         f"T1 {m}m{s:02d}s" if m else f"T1 {s}s")
                self._table_update(client_idx, lease=label)
                _time.sleep(1)

            if self._stop_event.is_set():
                break

            lease = self._client_leases.get(client_idx)
            if not lease or lease.get("version") != "v6":
                break

            self._log(f"{pfx}[DHCPv6 Renew] Renewing {ip6_addr}\n", "send")
            self._table_update(client_idx, status="Renewing…")

            try:
                trid      = random.randint(1, 0xFFFFFF)
                elapsed_s = 0
                renew_pkt = (
                    _l2() /
                    IPv6(src=ll_addr, dst="ff02::1:2") /
                    UDP(sport=546, dport=547) /
                    DHCP6_Renew(trid=trid) /
                    cid_opt / srv_id_opt /
                    DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0,
                                  ianaopts=[DHCP6OptIAAddress(
                                      addr=ip6_addr,
                                      preflft=preflft,
                                      validlft=validlft)]) /
                    DHCP6OptElapsedTime(elapsedtime=elapsed_s)
                )

                sn = AsyncSniffer(
                    iface=iface,
                    filter="udp and src port 547 and dst port 546",
                    lfilter=lambda p, _t=trid: (
                        IPv6 in p and DHCP6_Reply in p and
                        p[DHCP6_Reply].trid == _t
                    ),
                    count=1, timeout=10,
                )
                sn.start()
                sendp(renew_pkt, iface=iface, verbose=False)
                sn.join(timeout=11)
                rep_pkts = sn.results or []

                if not rep_pkts:
                    self._log(f"{pfx}[DHCPv6 Renew] TIMEOUT\n", "err")
                    self._table_update(client_idx, status="✗ Renew Timeout", lease="-")
                    break

                rep      = rep_pkts[0][DHCP6_Reply]
                ia_na_r  = rep[DHCP6OptIA_NA] if rep.haslayer(DHCP6OptIA_NA) else None
                new_addr = ip6_addr
                new_vl   = validlft
                new_pl   = preflft
                new_t1   = current_t1

                if ia_na_r:
                    new_t1 = ia_na_r.T1 or current_t1
                    for sub in (ia_na_r.ianaopts or []):
                        if isinstance(sub, DHCP6OptIAAddress):
                            new_addr = sub.addr
                            new_vl   = sub.validlft
                            new_pl   = sub.preflft
                            break

                vl_str   = lease_fmt(new_vl) if new_vl else "-"
                self._log(f"{pfx}[DHCPv6 Renew] OK  addr={new_addr}  valid={vl_str}\n",
                          "recv")
                ip6_addr  = new_addr
                preflft   = new_pl
                validlft  = new_vl
                current_t1 = new_t1
                lease["ip6"] = new_addr
                lease["vl"]  = new_vl
                lease["t1"]  = new_t1
                self._client_leases[client_idx] = lease
                self._table_update(client_idx, status="✔ REPLY",
                                   ip6=new_addr, lease=vl_str)

            except Exception as exc:
                self._log(f"{pfx}[DHCPv6 Renew] Error: {exc}\n", "err")
                break

        self._log(f"{pfx}[DHCPv6 Renew] Stopped.\n", "sys")

    def _stop_dora(self):
        self._stop_event.set()
        if self._capture_target == "dhcp":
            self._stop_capture()
        # Tear down all active DHCP sessions (send RELEASE for each lease)
        leases = list(self._client_leases.items())
        if leases:
            self._log(f"[Stop] Releasing {len(leases)} active DHCP lease(s)…\n", "sys")
            for idx, lease in leases:
                threading.Thread(target=self._release_worker,
                                 args=(idx, lease), daemon=True).start()

    def _stop_pppoe(self):
        self._pppoe_stop_event.set()
        if self._capture_target == "pppoe":
            self._stop_capture()
        # Tear down all active PPPoE sessions (send PADT for each)
        leases = list(self._pppoe_leases.items())
        if leases:
            self._log(f"[Stop] Terminating {len(leases)} active PPPoE session(s)…\n",
                      "sys", target="pppoe")
            for idx, lease in leases:
                threading.Thread(target=self._pppoe_padt_worker,
                                 args=(idx, lease), daemon=True).start()

    # ── Packet capture ────────────────────────────────────────────────────────

    def _start_capture(self, iface: str):
        if not self.capture_var.get():
            return
        # Stop any previous capture first
        self._stop_capture(silent=True)

        self._captured_packets = []
        self._capture_count    = 0
        bpf = self.capture_filter_var.get().strip() or None

        def _on_pkt(pkt):
            self._captured_packets.append(pkt)
            self._capture_count += 1
            if self._capture_count % 20 == 0:   # update label every 20 packets
                self._update_capture_status(running=True)

        try:
            self._capture_sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf,
                prn=_on_pkt,
                store=False,
            )
            self._capture_sniffer.start()
            desc = f" (filter: {bpf})" if bpf else ""
            _ct = getattr(self, "_capture_target", "dhcp")
            self._log(f"[Capture] Started on {iface}{desc}\n", "sys", target=_ct)
            self._update_capture_status(running=True)
        except Exception as e:
            _ct = getattr(self, "_capture_target", "dhcp")
            self._log(f"[Capture] Failed to start: {e}\n", "err", target=_ct)

    def _stop_capture(self, silent=False):
        sn = self._capture_sniffer
        if sn is None:
            return
        try:
            sn.stop()
        except Exception:
            pass
        self._capture_sniffer = None
        n = self._capture_count
        if not silent:
            _ct = getattr(self, "_capture_target", "dhcp")
            self._log(f"[Capture] Stopped — {n} packets captured\n", "sys", target=_ct)
        self._update_capture_status(running=False)

    def _update_capture_status(self, running: bool):
        n = self._capture_count
        icon   = "● " if running else "○ "
        status = f"Capturing ({n} pkts)" if running else f"Stopped ({n} pkts)"
        def _do():
            self.capture_status_var.set(icon + status)
        self.root.after(0, _do)

    def _save_pcap(self):
        from tkinter import filedialog
        if not self._captured_packets:
            messagebox.showinfo("Capture", "Không có packet nào được capture.")
            return
        path = filedialog.asksaveasfilename(
            title="Lưu file PCAP",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            from scapy.utils import wrpcap
            wrpcap(path, self._captured_packets)
            n = len(self._captured_packets)
            messagebox.showinfo("Capture", f"Đã lưu {n} packets\n{path}")
            _ct = getattr(self, "_capture_target", "dhcp")
            self._log(f"[Capture] Saved {n} packets → {path}\n", "success", target=_ct)
        except Exception as e:
            messagebox.showerror("Capture Error", str(e))

    # ── Release / Renew ───────────────────────────────────────────────────────

    def _selected_leases(self):
        """Return list of (client_idx, lease_dict) for all selected rows that have a lease.
        Shows a warning if nothing is selected or none have a lease."""
        sel = self.client_tree.selection()
        if not sel:
            messagebox.showinfo("Release / Renew", "Chọn ít nhất một client trong bảng.")
            return []
        iid_to_idx = {v: k for k, v in self._client_rows.items()}
        result = []
        for iid in sel:
            idx = iid_to_idx.get(iid)
            if idx is not None and idx in self._client_leases:
                result.append((idx, self._client_leases[idx]))
        if not result:
            messagebox.showinfo("Release / Renew",
                                "Không có client nào được chọn có lease hợp lệ\n"
                                "(cần DORA thành công trước).")
        return result

    def _release_selected(self):
        pairs = self._selected_leases()
        for idx, lease in pairs:
            threading.Thread(target=self._release_worker,
                             args=(idx, lease), daemon=True).start()

    def _renew_selected(self):
        pairs = self._selected_leases()
        for idx, lease in pairs:
            threading.Thread(target=self._renew_worker,
                             args=(idx, lease), daemon=True).start()

    def _ping_selected(self):
        target = self.ping_target_var.get().strip()
        if not target:
            messagebox.showinfo("Ping", "Nhập địa chỉ IP đích vào ô 'Ping target' trước.")
            return
        try:
            count = max(1, int(self.ping_count_var.get()))
        except ValueError:
            count = 3

        tab = self._proto_nb.tab(self._proto_nb.select(), "text").strip()

        if "PPPoE" in tab:
            try:
                ping_interval_s = max(0.0, int(self.pppoe_ping_interval_var.get())) / 1000.0
            except ValueError:
                ping_interval_s = 1.0
            # PPPoE ping: ICMP must be wrapped inside PPPoE session frame
            sel = self.pppoe_tree.selection()
            if not sel:
                messagebox.showinfo("Ping", "Chọn ít nhất một client trong bảng PPPoE.")
                return
            iid_to_idx = {v: k for k, v in self._pppoe_client_rows.items()}
            found = False
            for iid in sel:
                idx = iid_to_idx.get(iid)
                if idx is not None and idx in self._pppoe_leases:
                    found = True
                    threading.Thread(target=self._pppoe_ping_worker,
                                     args=(idx, self._pppoe_leases[idx], target, count,
                                           ping_interval_s),
                                     daemon=True).start()
            if not found:
                messagebox.showinfo("Ping", "Không có client PPPoE nào đã kết nối (cần Connect trước).")
        else:
            try:
                ping_interval_s = max(0.0, int(self.ping_interval_var.get())) / 1000.0
            except ValueError:
                ping_interval_s = 1.0
            # DHCP ping: plain Ethernet ICMP
            pairs = self._selected_leases()
            for idx, lease in pairs:
                threading.Thread(target=self._manual_ping_worker,
                                 args=(idx, lease, target, count, ping_interval_s),
                                 daemon=True).start()

    # ── PPPoE ping worker (ICMP inside PPPoE session frame) ───────────────────

    def _pppoe_ping_worker(self, client_idx: int, pppoe_lease: dict,
                            target_ip: str, count: int = 3, interval_s: float = 1.0):
        import struct, socket as _socket, time as _time
        from scapy.layers.inet import ICMP, IP as _IP
        from scapy.packet import Raw

        src_mac    = pppoe_lease["mac"]
        src_ip     = pppoe_lease.get("ip4") or ""
        ac_mac     = pppoe_lease["ac_mac"]
        session_id = pppoe_lease["session_id"]
        iface      = pppoe_lease["iface"]
        vlan_id    = pppoe_lease.get("vlan_id")
        pcp        = pppoe_lease.get("pcp", 0)
        pfx        = f"[C{client_idx+1:02d}] "

        if not src_ip or src_ip == "-":
            self._log(f"{pfx}  Chưa có IPv4, không thể ping\n", "err", target="pppoe")
            self._pppoe_table_update(client_idx, ping="No IPv4")
            return

        self._pppoe_table_update(client_idx, ping="Pinging…")

        # DNS resolve (host DNS)
        try:
            resolved_ip = _socket.gethostbyname(target_ip)
        except _socket.gaierror as e:
            self._log(f"{pfx}  DNS resolve failed for '{target_ip}': {e}\n", "err", target="pppoe")
            self._pppoe_table_update(client_idx, ping="DNS fail")
            return

        display = f"{target_ip} ({resolved_ip})" if resolved_ip != target_ip else target_ip
        self._log(f"{pfx}⊙ PPPoE Ping  {src_ip} → {display}  ({count} pkt)\n", "sys", target="pppoe")

        def _build_eth():
            e = Ether(src=src_mac, dst=ac_mac)
            if vlan_id:
                e = e / Dot1Q(vlan=vlan_id, prio=pcp)
            return e

        icmp_id = random.randint(1, 0xFFFF)
        success = 0
        timeout = 2.0

        for seq in range(1, count + 1):
            if self._pppoe_stop_event.is_set():
                break

            # Encapsulate ICMP inside PPPoE session (PPP proto=0x0021 = IP)
            icmp_inner = _IP(src=src_ip, dst=resolved_ip, ttl=64) / \
                         ICMP(type=8, code=0, id=icmp_id, seq=seq)
            ppp_data = struct.pack("!H", 0x0021) + bytes(icmp_inner)
            pkt = (_build_eth() /
                   PPPoE(version=1, type=1, code=0, sessionid=session_id) /
                   Raw(ppp_data))

            def _lf(p, _id=icmp_id, _seq=seq, _sid=session_id):
                if PPPoE not in p or p[PPPoE].sessionid != _sid:
                    return False
                raw = bytes(p[PPPoE].payload)
                if len(raw) < 4:
                    return False
                if struct.unpack_from("!H", raw)[0] != 0x0021:  # not IP
                    return False
                try:
                    ip_pkt = _IP(raw[2:])
                    return (ICMP in ip_pkt and ip_pkt[ICMP].type == 0
                            and ip_pkt[ICMP].id == _id
                            and ip_pkt[ICMP].seq == _seq)
                except Exception:
                    return False

            sniffer = AsyncSniffer(iface=iface, lfilter=_lf,
                                   count=1, timeout=timeout)
            sniffer.start()
            sendp(pkt, iface=iface, verbose=False)
            sniffer.join(timeout=timeout + 0.5)

            if sniffer.results:
                success += 1
                self._log(f"{pfx}  seq={seq} ✔ reply\n", "recv", target="pppoe")
            else:
                self._log(f"{pfx}  seq={seq} timeout\n", "err", target="pppoe")

            if seq < count and interval_s > 0 and not self._pppoe_stop_event.is_set():
                _time.sleep(interval_s)

        result = f"{success}/{count} OK ({resolved_ip})"
        self._pppoe_table_update(client_idx, ping=result)
        self._log(f"{pfx}  → {result}\n", "success" if success > 0 else "err", target="pppoe")

        # Auto-stop capture when this was the last pending ping
        lock = getattr(self, "_pppoe_ping_lock", None)
        if lock is not None:
            with lock:
                self._pppoe_ping_remaining -= 1
                if self._pppoe_ping_remaining <= 0:
                    import time as _t
                    threading.Thread(
                        target=lambda: (_t.sleep(0.5), self._stop_capture()),
                        daemon=True
                    ).start()

    # ── Manual ping worker (Scapy ICMP from client IP) ────────────────────────

    def _manual_ping_worker(self, client_idx: int, lease: dict,
                             target_ip: str, count: int = 3, interval_s: float = 1.0):
        from scapy.layers.inet import ICMP
        from scapy.layers.l2 import ARP
        import time as _time
        import ipaddress

        import socket as _socket

        src_mac  = lease["mac"]
        src_ip   = lease["ip"]
        src_mask = lease.get("mask", "255.255.255.0")
        gw_ip    = lease.get("gw", "-")
        iface    = lease["iface"]
        vlan_id  = lease.get("vlan_id")
        pcp      = lease.get("pcp", 0)
        pfx      = f"[C{client_idx + 1:02d}] "

        # Resolve domain → IP using host DNS (Scapy does this too, but log it clearly)
        try:
            resolved_ip = _socket.gethostbyname(target_ip)
        except _socket.gaierror as e:
            self._log(f"{pfx}  DNS resolve failed for '{target_ip}': {e}\n", "err")
            self._table_update(client_idx, ping=f"DNS fail ({target_ip})")
            return

        display = f"{target_ip} ({resolved_ip})" if resolved_ip != target_ip else target_ip

        self._table_update(client_idx, ping="Pinging…")
        self._log(f"{pfx}⊙ Ping  {src_ip} → {display}  ({count} pkt)\n", "sys")

        def _build_eth(dst="ff:ff:ff:ff:ff:ff"):
            e = Ether(src=src_mac, dst=dst)
            if vlan_id:
                e = e / Dot1Q(vlan=vlan_id, prio=pcp)
            return e

        # ── Step 1: Gratuitous ARP ────────────────────────────────────────────
        # Announce "src_mac owns src_ip" so return traffic can reach us.
        garp = (_build_eth() /
                ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                    hwdst="ff:ff:ff:ff:ff:ff", pdst=src_ip))
        sendp(garp, iface=iface, verbose=False)
        self._log(f"{pfx}  GARP: {src_ip} is-at {src_mac}\n", "detail")
        _time.sleep(0.15)

        # ── Step 2: Resolve Ethernet dst ─────────────────────────────────────
        # For on-link targets → ARP for target directly.
        # For off-link (internet) → ARP for the default gateway.
        # Using broadcast as Ethernet dst causes gateway to drop the frame
        # without routing it, so unicast to the correct next-hop MAC is required.
        def _arp_resolve(resolve_ip: str, timeout_s: float = 2.0) -> str | None:
            req = (_build_eth() /
                   ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                       hwdst="ff:ff:ff:ff:ff:ff", pdst=resolve_ip))
            sniffer = AsyncSniffer(
                iface=iface,
                lfilter=lambda p: (
                    ARP in p and p[ARP].op == 2           # ARP reply
                    and p[ARP].pdst == src_ip             # addressed to us
                    and p[ARP].psrc == resolve_ip         # from the target we asked
                ),
                count=1, timeout=timeout_s,
            )
            sniffer.start()
            sendp(req, iface=iface, verbose=False)
            sniffer.join(timeout=timeout_s + 0.5)
            if sniffer.results:
                return sniffer.results[0][ARP].hwsrc
            return None

        # Determine next-hop IP
        try:
            t_addr = ipaddress.ip_address(target_ip)
            s_net  = ipaddress.ip_network(f"{src_ip}/{src_mask}", strict=False)
            on_link = t_addr in s_net
        except ValueError:
            on_link = False

        next_hop = target_ip if on_link else (gw_ip if gw_ip not in ("", "-") else target_ip)
        self._log(f"{pfx}  ARP → {next_hop} ...\n", "detail")
        eth_dst = _arp_resolve(next_hop)
        if eth_dst:
            self._log(f"{pfx}  ARP reply: {next_hop} is-at {eth_dst}\n", "detail")
        else:
            self._log(f"{pfx}  ARP timeout for {next_hop}, using broadcast\n", "err")
            eth_dst = "ff:ff:ff:ff:ff:ff"

        # ── Step 3: ICMP echo ─────────────────────────────────────────────────
        icmp_id = random.randint(1, 0xFFFF)
        success = 0
        timeout = 2.0

        for seq in range(1, count + 1):
            if self._stop_event.is_set():
                break

            pkt = (_build_eth(eth_dst) /
                   IP(src=src_ip, dst=target_ip, ttl=64) /
                   ICMP(type=8, code=0, id=icmp_id, seq=seq))

            sniffer = AsyncSniffer(
                iface=iface,
                lfilter=lambda p, _id=icmp_id, _seq=seq: (
                    ICMP in p
                    and p[ICMP].type == 0
                    and p[ICMP].id   == _id
                    and p[ICMP].seq  == _seq
                ),
                count=1,
                timeout=timeout,
            )
            sniffer.start()
            sendp(pkt, iface=iface, verbose=False)
            sniffer.join(timeout=timeout + 0.5)
            replied = bool(sniffer.results)

            if replied:
                success += 1
                self._log(f"{pfx}  seq={seq} ✔ reply\n", "recv")
            else:
                self._log(f"{pfx}  seq={seq} timeout\n", "err")

            if seq < count and interval_s > 0 and not self._stop_event.is_set():
                _time.sleep(interval_s)

        result = f"{success}/{count} OK ({target_ip})"
        self._table_update(client_idx, ping=result)
        self._log(f"{pfx}  → {result}\n",
                  "success" if success > 0 else "err")


    # ── DHCP Auto-Renew loop ──────────────────────────────────────────────────

    def _auto_renew_loop(self, client_idx: int, lease_time: int, t1: int):
        import time as _time
        pfx        = f"[C{client_idx + 1:02d}] "
        current_t1 = t1

        while not self._stop_event.is_set():
            # countdown display
            deadline = _time.monotonic() + current_t1
            while not self._stop_event.is_set():
                rem = int(deadline - _time.monotonic())
                if rem <= 0:
                    break
                h, r = divmod(rem, 3600)
                m, s = divmod(r, 60)
                label = (f"T1 {h}h{m:02d}m" if h else
                         f"T1 {m}m{s:02d}s" if m else f"T1 {s}s")
                self._table_update(client_idx, lease=label)
                _time.sleep(1)

            if self._stop_event.is_set():
                break

            lease = self._client_leases.get(client_idx)
            if not lease:
                break

            mac      = lease["mac"]
            assigned = lease["ip"]
            server   = lease["server"]
            iface    = lease["iface"]
            vlan_id  = lease.get("vlan_id")
            pcp      = lease.get("pcp", 0)

            self._log(f"{pfx}[Auto-Renew] Renew {assigned} → {server}\n", "send")
            self._table_update(client_idx, status="Renewing…")

            try:
                timeout   = 10
                mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
                client_id = b'\x01' + mac_to_bytes(mac)
                xid       = random.randint(1, 0xFFFFFFFF)

                eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
                if vlan_id:
                    eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)

                pkt = (
                    eth /
                    IP(src=assigned, dst=server) /
                    UDP(sport=68, dport=67) /
                    BOOTP(op=1, htype=1, hlen=6, ciaddr=assigned,
                          chaddr=mac_bytes, xid=xid, flags=0) /
                    DHCP(options=[("message-type", "request"),
                                  ("client_id",    client_id), "end"])
                )

                sniffer = AsyncSniffer(
                    iface=iface, filter="udp and dst port 68",
                    lfilter=lambda p, _x=xid: (
                        DHCP in p and p[BOOTP].xid == _x and
                        any(o[0] == "message-type" and o[1] in (5, 6)
                            for o in p[DHCP].options if isinstance(o, tuple))
                    ),
                    count=1, timeout=timeout,
                )
                sniffer.start()
                sendp(pkt, iface=iface, verbose=False)
                sniffer.join(timeout=timeout + 1)
                result = sniffer.results or []

                if not result:
                    self._log(f"{pfx}[Auto-Renew] TIMEOUT\n", "err")
                    self._table_update(client_idx, status="✗ Renew Timeout", lease="-")
                    break

                ack      = result[0]
                opts     = {o[0]: o[1] for o in ack[DHCP].options if isinstance(o, tuple)}
                if opts.get("message-type") == 6:
                    self._log(f"{pfx}[Auto-Renew] NAK\n", "err")
                    self._client_leases.pop(client_idx, None)
                    self._table_update(client_idx, status="✗ Renew NAK", lease="-")
                    break

                new_ip    = str(ack[BOOTP].yiaddr)
                if new_ip == "0.0.0.0":
                    new_ip = assigned
                new_lease = opts.get("lease_time", lease_time)
                new_t1    = opts.get("renewal_time", new_lease // 2)
                lease_str = lease_fmt(new_lease)

                self._log(f"{pfx}[Auto-Renew] ACK  IP={new_ip}  lease={lease_str}\n", "recv")
                lease["ip"] = new_ip
                self._client_leases[client_idx] = lease
                self._table_update(client_idx, status="✔ Active", ip=new_ip,
                                   lease=lease_str)
                current_t1 = new_t1

            except Exception as exc:
                self._log(f"{pfx}[Auto-Renew] Error: {exc}\n", "err")
                break

        self._log(f"{pfx}[Auto-Renew] Stopped.\n", "sys")

    # ── IGMP Auto-Renew loop ──────────────────────────────────────────────────

    def _igmp_auto_renew_loop(self, client_idx: int, lease_time: int, t1: int):
        import time as _time
        pfx        = f"[C{client_idx + 1:02d}] "
        current_t1 = t1

        while not self._igmp_stop_event.is_set():
            # countdown
            deadline = _time.monotonic() + current_t1
            while not self._igmp_stop_event.is_set():
                rem = int(deadline - _time.monotonic())
                if rem <= 0:
                    break
                h, r = divmod(rem, 3600)
                m, s = divmod(r, 60)
                label = (f"T1 {h}h{m:02d}m" if h else
                         f"T1 {m}m{s:02d}s" if m else f"T1 {s}s")
                self._igmp_table_update(client_idx, status=f"✔ IP Ready ({label})")
                _time.sleep(1)

            if self._igmp_stop_event.is_set():
                break

            lease = self._igmp_leases.get(client_idx)
            if not lease:
                break

            mac     = lease["mac"]
            cur_ip  = lease["ip"]
            server  = lease.get("server", "")
            iface   = lease["iface"]
            vlan_id = lease.get("vlan_id")
            pcp     = lease.get("pcp", 0)

            self._log(f"{pfx}[IGMP Auto-Renew] Renew {cur_ip} → {server}\n",
                      "send", target="igmp")
            self._igmp_table_update(client_idx, status="Renewing…")

            try:
                timeout   = 10
                mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
                client_id = b'\x01' + mac_to_bytes(mac)
                xid       = random.randint(1, 0xFFFFFFFF)

                eth = build_eth(mac, "ff:ff:ff:ff:ff:ff", vlan_id, pcp)
                pkt = (
                    eth /
                    IP(src=cur_ip, dst=server if server else "255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(op=1, htype=1, hlen=6, ciaddr=cur_ip,
                          chaddr=mac_bytes, xid=xid, flags=0) /
                    DHCP(options=[("message-type", "request"),
                                  ("client_id",    client_id), "end"])
                )

                sniffer = AsyncSniffer(
                    iface=iface, filter="udp and dst port 68",
                    lfilter=lambda p, _x=xid: (
                        DHCP in p and p[BOOTP].xid == _x and
                        any(o[0] == "message-type" and o[1] in (5, 6)
                            for o in p[DHCP].options if isinstance(o, tuple))
                    ),
                    count=1, timeout=timeout,
                    stop_filter=lambda _: self._igmp_stop_event.is_set(),
                )
                sniffer.start()
                sendp(pkt, iface=iface, verbose=False)
                sniffer.join(timeout=timeout + 1)
                result = sniffer.results or []

                if not result:
                    self._log(f"{pfx}[IGMP Auto-Renew] TIMEOUT\n", "err", target="igmp")
                    self._igmp_table_update(client_idx, status="✗ Renew Timeout")
                    break

                ack      = result[0]
                opts     = {o[0]: o[1] for o in ack[DHCP].options if isinstance(o, tuple)}
                if opts.get("message-type") == 6:
                    self._log(f"{pfx}[IGMP Auto-Renew] NAK\n", "err", target="igmp")
                    self._igmp_table_update(client_idx, status="✗ Renew NAK")
                    break

                new_ip    = str(ack[BOOTP].yiaddr)
                if new_ip == "0.0.0.0":
                    new_ip = cur_ip
                new_lease = opts.get("lease_time", lease_time)
                new_t1    = opts.get("renewal_time", new_lease // 2)
                lease_str = lease_fmt(new_lease)

                self._log(f"{pfx}[IGMP Auto-Renew] ACK  IP={new_ip}  lease={lease_str}\n",
                          "recv", target="igmp")
                lease["ip"] = new_ip
                self._igmp_leases[client_idx] = lease
                self._igmp_table_update(client_idx, status="✔ IP Ready", ip=new_ip)
                current_t1 = new_t1

            except Exception as exc:
                self._log(f"{pfx}[IGMP Auto-Renew] Error: {exc}\n", "err", target="igmp")
                break

        self._log(f"{pfx}[IGMP Auto-Renew] Stopped.\n", "sys", target="igmp")

    def _release_worker(self, client_idx: int, lease: dict):
        mac      = lease["mac"]
        assigned = lease["ip"]
        server   = lease["server"]
        iface    = lease["iface"]
        vlan_id  = lease["vlan_id"]
        pcp      = lease["pcp"]
        pfx      = f"[C{client_idx + 1:02d}] "

        try:
            mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
            client_id = b'\x01' + mac_to_bytes(mac)
            xid       = random.randint(1, 0xFFFFFFFF)

            eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
            if vlan_id:
                eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)

            pkt = (
                eth /
                IP(src=assigned, dst=server) /
                UDP(sport=68, dport=67) /
                BOOTP(op=1, htype=1, hlen=6, ciaddr=assigned,
                      chaddr=mac_bytes, xid=xid) /
                DHCP(options=[
                    ("message-type", "release"),
                    ("server_id",    server),
                    ("client_id",    client_id),
                    "end"
                ])
            )

            self._log(f"{pfx}>>> DHCP RELEASE  {assigned} → server {server}\n", "send")
            sendp(pkt, iface=iface, verbose=False)
            self._log(f"{pfx}    Release sent (no ACK expected by RFC 2131).\n", "detail")

            del self._client_leases[client_idx]
            self._table_update(client_idx, status="Released", ip="-",
                               mask="-", gw="-", dns="-", lease="-", ping="-")

        except Exception as exc:
            self._log(f"{pfx}[ERROR] Release: {exc}\n", "err")

    def _renew_worker(self, client_idx: int, lease: dict):
        mac      = lease["mac"]
        assigned = lease["ip"]
        server   = lease["server"]
        iface    = lease["iface"]
        vlan_id  = lease["vlan_id"]
        pcp      = lease["pcp"]
        pfx      = f"[C{client_idx + 1:02d}] "

        try:
            timeout   = 5
            mac_bytes = mac_to_bytes(mac) + b'\x00' * 10
            client_id = b'\x01' + mac_to_bytes(mac)
            xid       = random.randint(1, 0xFFFFFFFF)

            eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
            if vlan_id:
                eth = eth / Dot1Q(vlan=vlan_id, prio=pcp)

            pkt = (
                eth /
                IP(src=assigned, dst=server) /
                UDP(sport=68, dport=67) /
                BOOTP(op=1, htype=1, hlen=6, ciaddr=assigned,
                      chaddr=mac_bytes, xid=xid, flags=0) /
                DHCP(options=[
                    ("message-type", "request"),
                    ("client_id",    client_id),
                    "end"
                ])
            )

            self._log(f"{pfx}>>> DHCP RENEW  ciaddr={assigned} → server {server}\n", "send")
            self._table_update(client_idx, status="Renewing…")

            sniffer = AsyncSniffer(
                iface=iface,
                filter="udp and dst port 68",
                lfilter=lambda p: (
                    DHCP in p and p[BOOTP].xid == xid
                    and any(o[0] == "message-type" and o[1] in (5, 6)
                            for o in p[DHCP].options if isinstance(o, tuple))
                ),
                count=1,
                timeout=timeout,
            )
            sniffer.start()
            sendp(pkt, iface=iface, verbose=False)
            sniffer.join(timeout=timeout + 1)
            result = sniffer.results or []

            if not result:
                self._log(f"{pfx}[TIMEOUT] No ACK received for Renew.\n", "err")
                self._table_update(client_idx, status="✗ Renew Timeout")
                return

            ack      = result[0]
            opts     = {o[0]: o[1] for o in ack[DHCP].options if isinstance(o, tuple)}
            msg_type = opts.get("message-type", 0)

            if msg_type == 6:
                self._log(f"{pfx}[NAK] Server refused renew.\n", "err")
                del self._client_leases[client_idx]
                self._table_update(client_idx, status="✗ Renew NAK")
                return

            new_ip    = str(ack[BOOTP].yiaddr) if str(ack[BOOTP].yiaddr) != "0.0.0.0" else assigned
            lease_val = opts.get("lease_time", None)
            lease_str = lease_fmt(lease_val) if lease_val else "-"

            self._log(f"{pfx}<<< RENEW ACK  IP={new_ip}  lease={lease_str}\n", "recv")

            lease["ip"] = new_ip
            self._client_leases[client_idx] = lease
            self._table_update(client_idx, status="✔ Renewed",
                               ip=new_ip, lease=lease_str)

        except Exception as exc:
            self._log(f"{pfx}[ERROR] Renew: {exc}\n", "err")
            self._table_update(client_idx, status="✗ Renew Error")

    # ── Multi-client coordinator ───────────────────────────────────────────────

    def _multi_coordinator(self, iface, macs, timeout, vlan_id, pcp,
                           hostname, pad_bytes, interval_ms, ping_custom=None,
                           retry_enabled=True, max_retries=4,
):
        import time as _time

        num_clients      = len(macs)
        self._mc_success = 0
        self._mc_total   = num_clients
        lock = threading.Lock()

        self._log(f"\n{'='*60}\n", "sys")
        self._log(f"  Multi-Client DORA — {num_clients} clients  "
                  f"interval={interval_ms} ms\n", "sys")
        self._log(f"{'='*60}\n\n", "sys")

        def _on_done(success: bool):
            with lock:
                if success:
                    self._mc_success += 1
                done = self._mc_success
            self._update_summary(done, num_clients)

        workers = []
        for idx, client_mac in enumerate(macs):
            if self._stop_event.is_set():
                break
            t = threading.Thread(
                target=self._dora_worker,
                args=(iface, client_mac, timeout, vlan_id, pcp,
                      hostname, pad_bytes, idx, num_clients, _on_done,
                      ping_custom, retry_enabled, max_retries),
                daemon=True,
            )
            workers.append(t)
            t.start()
            if idx < num_clients - 1 and interval_ms > 0:
                _time.sleep(interval_ms / 1000.0)

        for t in workers:
            t.join()

        success = self._mc_success
        self._log(f"\n{'─'*60}\n", "detail")
        self._log(f"  Multi-Client done: {success}/{num_clients} succeeded\n",
                  "success" if success == num_clients else "err")
        self._log(f"{'─'*60}\n", "detail")
        self._update_summary(success, num_clients)

    def _dora_worker(self, iface, mac, timeout, vlan_id=None, pcp=0, hostname="",
                     pad_bytes=None, client_idx=0, total_clients=1, on_done=None,
                     ping_custom=None, retry_enabled=True, max_retries=4):
        # Prefix log messages when running multiple clients
        pfx = f"[C{client_idx + 1:02d}] " if total_clients > 1 else ""
        success = False

        def log(msg, tag=None):
            if pfx:
                parts = msg.split('\n')
                msg2 = '\n'.join((pfx + p) if p.strip() else p for p in parts)
            else:
                msg2 = msg
            self._log(msg2, tag)

        try:
            xid       = random.randint(1, 0xFFFFFFFF)
            mac_bytes = mac_to_bytes(mac) + b'\x00' * 10   # padded to 16 bytes (BOOTP chaddr)
            # Option 61: client identifier = hardware type (0x01 Ethernet) + MAC bytes
            client_id = b'\x01' + mac_to_bytes(mac)

            # RFC 951/2131: BOOTP UDP payload must be >= 300 bytes.
            # Use BOOTP layer size (not total frame) so Ethernet+IP+UDP headers
            # are not counted against the 300-byte minimum.
            # pad_bytes=None → auto; pad_bytes=N → fixed N zero bytes appended after "end".
            _BOOTP_MIN = 300

            def _make_padding(base_pkt, fixed=None):
                if fixed is not None:
                    return b'\x00' * fixed
                needed = _BOOTP_MIN - len(bytes(base_pkt[BOOTP]))
                return b'\x00' * max(0, needed)

            def _sniff_dhcp(msg_types, timeout_s):
                """Start capture, return sniffer so caller sends before joining."""
                return AsyncSniffer(
                    iface=iface,
                    filter="udp and dst port 68",
                    lfilter=lambda p: (
                        DHCP in p
                        and p[BOOTP].xid == xid
                        and any(o[0] == 'message-type' and o[1] in msg_types
                                for o in p[DHCP].options if isinstance(o, tuple))
                    ),
                    count=1,
                    timeout=timeout_s,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )

            vlan_info = f"VLAN {vlan_id}  PCP {pcp}" if vlan_id else "untagged"
            self._table_update(client_idx, status="Running")

            log("=" * 60 + "\n", "sys")
            log(f"  DHCP Client Emulator — DORA Sequence\n", "sys")
            log(f"  Interface : {iface}\n", "sys")
            log(f"  Client MAC: {mac}\n", "sys")
            log(f"  VLAN      : {vlan_info}\n", "sys")
            pad_desc = f"{pad_bytes} bytes (fixed)" if pad_bytes is not None else f"auto (BOOTP payload ≥ {_BOOTP_MIN} B)"
            log(f"  Hostname  : {hostname or '(none)'}\n", "sys")
            log(f"  Padding   : {pad_desc}\n", "sys")
            log(f"  XID       : {xid:#010x}\n", "sys")
            log("=" * 60 + "\n\n", "sys")

            def _l2(dst="ff:ff:ff:ff:ff:ff"):
                eth = Ether(dst=dst, src=mac)
                if vlan_id:
                    return eth / Dot1Q(vlan=vlan_id, prio=pcp)
                return eth

            import time as _time

            # RFC 2131 §4.4.1 retransmission helper
            # t_retry: current wait window; doubles each attempt (capped at 64s)
            # secs:    elapsed since DHCP process start → written into BOOTP header
            _RFC_INIT = 4.0      # initial retransmission timeout (seconds)
            _RFC_MAX  = 64.0     # maximum retransmission timeout

            def _next_t(t):
                """Double with ±1 s jitter, cap at RFC_MAX."""
                return max(1.0, min(t * 2, _RFC_MAX) + random.uniform(-1.0, 1.0))

            def _elapsed_secs(t0):
                return min(int(_time.time() - t0), 65535)

            # ── 1+2. DISCOVER with retry ───────────────────────────────────────
            log(">>> [1/4] DHCP DISCOVER\n", "send")
            t0_discover  = _time.time()
            t_retry      = _RFC_INIT if retry_enabled else float(timeout)
            n_retries    = max_retries if retry_enabled else 0
            offer_pkts   = []

            for attempt in range(n_retries + 1):
                if self._stop_event.is_set():
                    log("\n[Stopped]\n", "sys"); return

                secs = _elapsed_secs(t0_discover)
                if attempt == 0:
                    label = f"  attempt 1/{n_retries + 1}  timeout={t_retry:.1f}s"
                else:
                    label = (f"  retry {attempt}/{n_retries}  "
                             f"secs={secs}  timeout={t_retry:.1f}s")
                    self._table_update(client_idx,
                                       status=f"Retry {attempt}/{n_retries}")
                log(f"    DISCOVER {label}\n", "send" if attempt == 0 else "sys")

                _disc_base = (
                    _l2() /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000, secs=secs) /
                    DHCP(options=[
                        ("message-type",   "discover"),
                        ("param_req_list", [1, 121, 3, 33, 6, 42, 138, 43]),
                        *([("hostname", hostname)] if hostname else []),
                        ("client_id",      client_id),
                        "end"
                    ])
                )
                _pad     = _make_padding(_disc_base, pad_bytes)
                discover = _disc_base / _pad if _pad else _disc_base
                log(f"    size={len(bytes(discover))}B  "
                    f"BOOTP={len(bytes(discover[BOOTP]))}B  "
                    f"pad={len(_pad)}B\n", "detail")

                _offer_sniffer = _sniff_dhcp({2}, t_retry)
                _offer_sniffer.start()
                sendp(discover, iface=iface, verbose=False)
                log(f"<<< [2/4] Waiting for OFFER  ({t_retry:.1f}s) ...\n", "sys")
                _offer_sniffer.join(timeout=t_retry + 1)
                offer_pkts = _offer_sniffer.results or []

                if offer_pkts:
                    break
                if attempt < n_retries:
                    log(f"    No OFFER — will retry.\n", "err")
                    t_retry = _next_t(t_retry)

            if not offer_pkts:
                log(f"[TIMEOUT] No DHCP OFFER after "
                    f"{n_retries + 1} attempt(s).\n", "err")
                self._table_update(client_idx, status="✗ No OFFER")
                return

            offer      = offer_pkts[0]
            offered_ip = offer[BOOTP].yiaddr
            opts_offer = {o[0]: o[1] for o in offer[DHCP].options
                          if isinstance(o, tuple)}
            server_id  = opts_offer.get("server_id", offer[IP].src)

            log(f"<<< [OFFER] Offered IP : {offered_ip}\n", "recv")
            log(f"           Server ID  : {server_id}\n", "recv")
            self._table_update(client_idx, ip=str(offered_ip))

            if self._stop_event.is_set():
                log("\n[Stopped]\n", "sys"); return

            # ── 3+4. REQUEST with retry ────────────────────────────────────────
            log(">>> [3/4] DHCP REQUEST\n", "send")
            t_retry = _RFC_INIT if retry_enabled else float(timeout)
            ack_pkts   = []

            for attempt in range(n_retries + 1):
                if self._stop_event.is_set():
                    log("\n[Stopped]\n", "sys"); return

                secs = _elapsed_secs(t0_discover)  # secs counts from start of DORA
                if attempt > 0:
                    log(f"    retry {attempt}/{n_retries}  "
                        f"secs={secs}  timeout={t_retry:.1f}s\n", "sys")

                _req_base = (
                    _l2() /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000, secs=secs) /
                    DHCP(options=[
                        ("message-type",   "request"),
                        ("param_req_list", [1, 121, 3, 33, 6, 42, 138, 43]),
                        ("requested_addr", offered_ip),
                        ("server_id",      server_id),
                        *([("hostname", hostname)] if hostname else []),
                        ("client_id",      client_id),
                        "end"
                    ])
                )
                _pad    = _make_padding(_req_base, pad_bytes)
                request = _req_base / _pad if _pad else _req_base
                log(f"    size={len(bytes(request))}B  "
                    f"BOOTP={len(bytes(request[BOOTP]))}B  "
                    f"pad={len(_pad)}B\n", "detail")

                _ack_sniffer = _sniff_dhcp({5, 6}, t_retry)
                _ack_sniffer.start()
                sendp(request, iface=iface, verbose=False)
                log(f"<<< [4/4] Waiting for ACK  ({t_retry:.1f}s) ...\n", "sys")
                _ack_sniffer.join(timeout=t_retry + 1)
                ack_pkts = _ack_sniffer.results or []

                if ack_pkts:
                    break
                if attempt < n_retries:
                    log(f"    No ACK — will retry.\n", "err")
                    t_retry = _next_t(t_retry)

            if not ack_pkts:
                log(f"[TIMEOUT] No DHCP ACK after "
                    f"{n_retries + 1} attempt(s).\n", "err")
                self._table_update(client_idx, status="✗ No ACK")
                return

            ack      = ack_pkts[0]
            opts_ack = {o[0]: o[1] for o in ack[DHCP].options if isinstance(o, tuple)}
            msg_type = opts_ack.get("message-type", 0)

            if msg_type == 6:
                log("[NAK] DHCP Server refused the request.\n", "err")
                self._table_update(client_idx, status="✗ NAK")
                return

            # ── Parse results ─────────────────────────────────────────────────
            assigned = ack[BOOTP].yiaddr
            mask     = str(opts_ack.get("subnet_mask", "-"))
            gw_raw   = opts_ack.get("router", None)
            gw       = str(gw_raw[0]) if isinstance(gw_raw, list) and gw_raw else str(gw_raw or "-")
            dns_raw  = opts_ack.get("name_server", [])
            if isinstance(dns_raw, str):
                dns = dns_raw
            elif dns_raw:
                dns = ", ".join(str(d) for d in dns_raw)
            else:
                dns = "-"
            lease    = opts_ack.get("lease_time", None)
            srv      = str(opts_ack.get("server_id", server_id))
            t1       = opts_ack.get("renewal_time",  "")
            t2       = opts_ack.get("rebinding_time", "")

            lease_str = lease_fmt(lease) if lease else "-"

            log("\n", None)
            log("✔ DHCP DORA completed successfully!\n", "success")
            log("-" * 60 + "\n", "detail")
            log(f"  Assigned IP  : {assigned}\n",  "recv")
            log(f"  Subnet Mask  : {mask}\n",      "recv")
            log(f"  Gateway      : {gw}\n",        "recv")
            log(f"  DNS Server   : {dns}\n",       "recv")
            log(f"  DHCP Server  : {srv}\n",       "recv")
            log(f"  Lease Time   : {lease_str}\n", "recv")
            if t1:
                log(f"  Renewal  (T1): {lease_fmt(t1)}\n", "detail")
            if t2:
                log(f"  Rebinding(T2): {lease_fmt(t2)}\n", "detail")
            log("-" * 60 + "\n", "detail")

            # ── Ping connectivity check ───────────────────────────────────────
            ping_target = ping_custom or (gw if gw not in ("-", "") else str(assigned))
            ping_ok = self._ping_host(ping_target)
            ping_status = (f"OK ({ping_target})" if ping_ok
                          else f"Fail ({ping_target})")
            log(f"  Ping target  : {ping_target}\n", "detail")
            log(f"  Ping result  : {ping_status}\n", "detail")

            success = True
            self._client_leases[client_idx] = {
                "ip":       str(assigned),
                "mask":     mask,
                "server":   str(srv),
                "gw":       gw,
                "mac":      mac,
                "iface":    iface,
                "vlan_id":  vlan_id,
                "pcp":      pcp,
            }

            # ── Auto-renew timer ──────────────────────────────────────────────
            if lease and not self._stop_event.is_set():
                t1_val = int(t1) if t1 else lease // 2
                log(f"  Auto-Renew   : will renew in {lease_fmt(t1_val)}\n", "detail")
                threading.Thread(
                    target=self._auto_renew_loop,
                    args=(client_idx, lease, t1_val),
                    daemon=True,
                ).start()
            self._table_update(client_idx,
                               status="✔ ACK",
                               ip=str(assigned),
                               mask=mask,
                               gw=gw,
                               dns=dns,
                               lease=lease_str,
                               ping=ping_status)

        except PermissionError:
            log(
                "\n[PERMISSION ERROR] Run this tool as Administrator.\n"
                "Raw sockets require elevated privileges.\n", "err"
            )
            self._table_update(client_idx, status="✗ No Permission")
        except Exception as exc:
            log(f"\n[ERROR] {exc}\n", "err")
            import traceback
            log(traceback.format_exc(), "err")
            self._table_update(client_idx, status="✗ Error")
        finally:
            if on_done is not None:
                on_done(success)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app  = DHCPClientEmulator(root)
    root.mainloop()
