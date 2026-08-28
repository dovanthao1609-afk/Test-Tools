import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import socket
import re
import queue

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False


class GPONConfigGenerator:
    def __init__(self, root):
        self.root = root
        # Only manage window if root is a top-level Tk window (not an embedded Frame)
        if isinstance(root, tk.Tk) or isinstance(root, tk.Toplevel):
            self.root.title("GPON NSO Config Generator")
            self.root.geometry("1100x680")
            self.root.minsize(800, 500)
        self._last_config        = ""
        self._last_remove_config = ""
        self._rpc_stop_event     = threading.Event()
        self._rpc_client         = None
        self._olt_stop_event     = threading.Event()
        self._olt_client         = None
        self._olt_shell          = None
        self._olt_sock           = None
        self._olt_cmd_history    = []
        self._olt_hist_idx       = -1
        self._olt_pending_input  = ""
        self._olt_output_queue   = queue.Queue()
        self._olt_ansi_state     = []   # current SGR tags across output chunks
        self.dba_name_vars    = []
        self.dba_fixed_vars   = []
        self.dba_assured_vars = []
        self.dba_max_vars     = []
        self.dba_widgets      = []
        self.uni_sections     = []   # list of section-data dicts, one per UNI group
        self.uni_group_frames = []   # list of LabelFrame widgets, one per UNI group
        self.tcont_alloc_vars = []
        self.tcont_dba_vars   = []
        self.tcont_dba_cbs    = []
        self.tcont_gem_vars   = []
        self.tcont_vlan_vars  = []
        self.tcont_widgets    = []

        style = ttk.Style()
        style.theme_use("clam")

        # Section label
        style.configure("Section.TLabel", font=("Segoe UI", 9, "bold"), foreground="#1565c0")

        # Helper: configure a colored button + hover/press states
        def _btn(name, bg, hover, press):
            style.configure(f"{name}.TButton",
                            font=("Segoe UI", 9, "bold"), padding=6,
                            foreground="white", background=bg,
                            relief="flat",
                            bordercolor=bg, darkcolor=bg, lightcolor=bg)
            style.map(f"{name}.TButton",
                      background=[("active", hover), ("pressed", press)],
                      relief=[("pressed", "flat")])

        # Neutral (Generate / Save / Copy)
        style.configure("Action.TButton",
                        font=("Segoe UI", 9, "bold"), padding=6,
                        foreground="#1a2d44", background="#e8edf3",
                        relief="flat")
        style.map("Action.TButton",
                  background=[("active", "#c8d4e3"), ("pressed", "#b0c0d8")])

        # 🟢 OLT Connect — green
        _btn("OltConn",    "#2e7d32", "#43a047", "#1b5e20")
        # 🟣 OLT Disconnect — indigo
        _btn("OltDisc",    "#5e35b1", "#7e57c2", "#4527a0")
        # 🟠 Provisioning via SSH — deep orange
        _btn("Deploy",     "#e65100", "#f4511e", "#bf360c")
        # 🔴 Remove SERVICE via SSH — red
        _btn("NoSvcDeploy","#c62828", "#ef5350", "#b71c1c")
        # 🔵 Remove Service Config — blue-purple
        _btn("NoService",  "#283593", "#3949ab", "#1a237e")
        # 🩵 Start RPC Trace — teal
        _btn("RpcStart",   "#00695c", "#00897b", "#004d40")
        # ⬛ Stop RPC — blue-gray
        _btn("RpcStop",    "#455a64", "#607d8b", "#37474f")
        # 🔴 Reset to Defaults — red
        _btn("Reset",      "#c62828", "#ef5350", "#b71c1c")

        self._build_ui()

    # ─── UI Layout ────────────────────────────────────────────────────────────

    def _build_ui(self):
        pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.Frame(pane, width=400)
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=2)

        self._build_input_panel(left)
        self._build_preview_panel(right)

        # Set sash so the config panel (DBA, VLAN…) is fully visible on first open
        def _init_sash():
            try:
                # Use left panel's natural width as minimum; fallback to 400
                w = max(400, left.winfo_reqwidth())
                pane.sashpos(0, w)
            except Exception:
                pass
        pane.after(80, _init_sash)

    def _build_input_panel(self, parent):
        canvas = tk.Canvas(parent, highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Mouse-wheel scroll — guard against canvas being destroyed (e.g. embedded in Toplevel)
        def _scroll(e, c=canvas):
            try:
                c.yview_scroll(-1 * (e.delta // 120), "units")
            except Exception:
                pass
        canvas.bind_all("<MouseWheel>", _scroll)

        self.v = {}
        r = 0

        # ── Section 1: DBA Profiles ─────────────────────────────────────────
        MAX_DBA = 4
        r = self._sep(inner, "DBA Profiles", r)
        ttk.Label(inner, text="Number of Profiles:").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["num_dba"] = tk.StringVar(value="1")
        dba_spin = ttk.Spinbox(inner, from_=1, to=MAX_DBA,
                               textvariable=self.v["num_dba"],
                               width=5, command=self._update_dba_rows)
        dba_spin.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        dba_spin.bind("<FocusOut>", self._update_dba_rows)
        r += 1

        for d in range(MAX_DBA):
            lbl = ttk.Label(inner, text=f"  DBA {d + 1}:")
            lbl.grid(row=r, column=0, sticky="w", padx=(14, 4), pady=2)
            sub = ttk.Frame(inner)
            sub.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=2)
            r += 1

            name_var    = tk.StringVar(value="1G_Type5" if d == 0 else "")
            fixed_var   = tk.StringVar(value="0")
            assured_var = tk.StringVar(value="0")
            max_var     = tk.StringVar(value="102400000" if d == 0 else "0")

            ttk.Label(sub, text="Name:").pack(side="left")
            ttk.Entry(sub, textvariable=name_var, width=12).pack(side="left", padx=(2, 0))
            ttk.Label(sub, text="  Fixed BW:").pack(side="left", padx=(6, 0))
            ttk.Entry(sub, textvariable=fixed_var, width=8).pack(side="left", padx=(2, 0))
            ttk.Label(sub, text="  Assured:").pack(side="left", padx=(6, 0))
            ttk.Entry(sub, textvariable=assured_var, width=8).pack(side="left", padx=(2, 0))
            ttk.Label(sub, text="  Max BW:").pack(side="left", padx=(6, 0))
            ttk.Entry(sub, textvariable=max_var, width=12).pack(side="left", padx=(2, 0))

            self.dba_name_vars.append(name_var)
            self.dba_fixed_vars.append(fixed_var)
            self.dba_assured_vars.append(assured_var)
            self.dba_max_vars.append(max_var)
            self.dba_widgets.append((lbl, sub))
            if d > 0:
                lbl.grid_remove(); sub.grid_remove()

        # ── Section 2: VLAN & Uplink ────────────────────────────────────────
        r = self._sep(inner, "VLAN & Uplink", r)
        self.v["vlan_id"]    = self._row(inner, "VLAN IDs (spaces):", "1237",    r); r += 1
        self.v["uplink_eth"] = self._row(inner, "Uplink Interface:", "eth0/20", r); r += 1

        # ── Section 3: PON Interface ────────────────────────────────────────
        r = self._sep(inner, "PON Interface", r)

        ttk.Label(inner, text="PON Type:").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["pon_type"] = tk.StringVar(value="GPON")
        pon_frame = ttk.Frame(inner)
        pon_frame.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        ttk.Radiobutton(pon_frame, text="GPON",    variable=self.v["pon_type"],
                        value="GPON").pack(side="left", padx=(0, 12))
        ttk.Radiobutton(pon_frame, text="XGS-PON", variable=self.v["pon_type"],
                        value="XGSPON").pack(side="left")
        r += 1

        self.v["pon_slot"] = self._row(inner, "PON Slot:", "0", r); r += 1
        self.v["pon_port"] = self._row(inner, "PON Port:", "3", r); r += 1

        # ── Sections 5–9: ONT Information ───────────────────────────────────
        r = self._sep(inner, "ONT Information", r)
        self.v["onu_id"]     = self._row(inner, "ONU ID:",     "1",            r); r += 1
        self.v["ont_serial"] = self._row(inner, "ONT Serial:", "DSNW29775988", r); r += 1

        # Mode radio buttons
        ttk.Label(inner, text="ONT Mode:").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["mode"] = tk.StringVar(value="PPTP")
        mode_frame = ttk.Frame(inner)
        mode_frame.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        ttk.Radiobutton(mode_frame, text="PPTP", variable=self.v["mode"],
                        value="PPTP", command=self._toggle_uni_port).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(mode_frame, text="VEIP", variable=self.v["mode"],
                        value="VEIP", command=self._toggle_uni_port).pack(side="left")
        r += 1

        # UNI Ports — hidden when VEIP mode; space-separated for multiple ports
        self._uni_lbl = ttk.Label(inner, text="UNI Ports (space):")
        self._uni_lbl.grid(row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["uni_port"] = tk.StringVar(value="1")
        self._uni_entry = ttk.Entry(inner, textvariable=self.v["uni_port"], width=22)
        self._uni_entry.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=3)
        r += 1

        # ── Section 10: TCONT / GEM ─────────────────────────────────────────
        MAX_TCONT = 8
        r = self._sep(inner, "TCONT / GEM", r)
        ttk.Label(inner, text="Number of TCONT/GEM:").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["num_tcont"] = tk.StringVar(value="1")
        tcont_spin = ttk.Spinbox(inner, from_=1, to=MAX_TCONT,
                                 textvariable=self.v["num_tcont"],
                                 width=5, command=self._update_tcont_rows)
        tcont_spin.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        tcont_spin.bind("<FocusOut>", self._update_tcont_rows)
        r += 1

        for t in range(MAX_TCONT):
            t_lbl = ttk.Label(inner, text=f"  TCONT {t + 1}:")
            t_lbl.grid(row=r, column=0, sticky="w", padx=(14, 4), pady=2)
            t_sub = ttk.Frame(inner)
            t_sub.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=2)
            r += 1

            alloc_var = tk.StringVar(value="171" if t == 0 else "")
            dba_var   = tk.StringVar(value="")
            gem_var   = tk.StringVar(value="171" if t == 0 else "")
            vlan_var  = tk.StringVar(value="")

            ttk.Label(t_sub, text="Alloc ID:").pack(side="left")
            ttk.Entry(t_sub, textvariable=alloc_var, width=7).pack(side="left", padx=(2, 0))
            ttk.Label(t_sub, text="  DBA:").pack(side="left", padx=(6, 0))
            dba_cb = ttk.Combobox(t_sub, textvariable=dba_var, width=12, state="normal")
            dba_cb.pack(side="left", padx=(2, 0))
            dba_cb.bind("<<ComboboxDropdown>>", self._refresh_dba_in_cb)
            ttk.Label(t_sub, text="  GEM ID:").pack(side="left", padx=(6, 0))
            ttk.Entry(t_sub, textvariable=gem_var, width=7).pack(side="left", padx=(2, 0))
            ttk.Label(t_sub, text="  VLAN:").pack(side="left", padx=(6, 0))
            ttk.Entry(t_sub, textvariable=vlan_var, width=7).pack(side="left", padx=(2, 0))

            self.tcont_alloc_vars.append(alloc_var)
            self.tcont_dba_vars.append(dba_var)
            self.tcont_dba_cbs.append(dba_cb)
            self.tcont_gem_vars.append(gem_var)
            self.tcont_vlan_vars.append(vlan_var)
            self.tcont_widgets.append((t_lbl, t_sub))
            if t > 0:
                t_lbl.grid_remove(); t_sub.grid_remove()

        # ── Extended VLAN Rules (Section 8) — one group per UNI port ───────
        MAX_UNI_GROUPS = 4
        r = self._sep(inner, "Extended VLAN Rules", r)

        for u_idx in range(MAX_UNI_GROUPS):
            lf = ttk.LabelFrame(inner, text=f"UNI Port {u_idx + 1}")
            lf.grid(row=r, column=0, columnspan=2, sticky="ew", padx=6, pady=(2, 4))
            lf.columnconfigure(1, weight=1)
            r += 1
            section = self._build_rule_section(lf)
            self.uni_sections.append(section)
            self.uni_group_frames.append(lf)
            if u_idx > 0:
                lf.grid_remove()

        self.v["uni_port"].trace_add("write", self._update_uni_groups)

        # ── SSH Deploy ───────────────────────────────────────────────────────
        r = self._sep(inner, "NSO SSH Deploy", r)
        self.v["ssh_ip"]        = self._row(inner, "NSO IP:", "192.168.100.148", r); r += 1
        self.v["ssh_user"]      = self._row(inner, "Username:", "ducpct", r); r += 1
        self.v["ssh_pass"]      = self._row_password_default(inner, "Password:", "zh1234$$", r); r += 1
        self.v["ssh_root_pass"] = self._row_password_default(inner, "Root Password:", "zh1234$$", r); r += 1
        self.v["ssh_device"]    = self._row(inner, "Device Name:", "", r); r += 1
        self.v["ssh_cmd_delay"] = self._row(inner, "Cmd delay (s):", "0.05", r); r += 1

        # ── OLT Terminal ─────────────────────────────────────────────────────
        r = self._sep(inner, "OLT Terminal", r)
        ttk.Label(inner, text="Protocol:").grid(row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["olt_proto"] = tk.StringVar(value="SSH")
        _pf = ttk.Frame(inner)
        _pf.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        ttk.Radiobutton(_pf, text="SSH",    variable=self.v["olt_proto"],
                        value="SSH",    command=self._olt_proto_changed).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(_pf, text="Telnet", variable=self.v["olt_proto"],
                        value="Telnet", command=self._olt_proto_changed).pack(side="left")
        r += 1
        self.v["olt_ip"]   = self._row(inner, "OLT IP:", "", r); r += 1
        self.v["olt_user"] = self._row(inner, "Username:", "", r); r += 1
        self.v["olt_pass"] = self._row_password_default(inner, "Password:", "", r); r += 1
        self.v["olt_port"] = self._row(inner, "Port:", "22", r); r += 1
        _obf = ttk.Frame(inner)
        _obf.grid(row=r, column=0, columnspan=2, pady=(4, 2), padx=6, sticky="ew")
        _obf.columnconfigure((0, 1), weight=1)
        ttk.Button(_obf, text="⬤  Connect OLT", style="OltConn.TButton",
                   command=self._connect_olt).grid(row=0, column=0, padx=(0, 3), sticky="ew")
        ttk.Button(_obf, text="✕  Disconnect",  style="OltDisc.TButton",
                   command=self._disconnect_olt).grid(row=0, column=1, padx=(3, 0), sticky="ew")
        r += 1

        # ── Buttons ─────────────────────────────────────────────────────────
        r += 1
        btn_frame = ttk.Frame(inner)
        btn_frame.grid(row=r, column=0, columnspan=2, pady=(8, 4), padx=6, sticky="ew")
        btn_frame.columnconfigure((0, 1, 2), weight=1)

        ttk.Button(btn_frame, text="Generate Config", style="Action.TButton",
                   command=self.generate).grid(row=0, column=0, padx=3, sticky="ew")
        ttk.Button(btn_frame, text="Save Config", style="Action.TButton",
                   command=self.save_file).grid(row=0, column=1, padx=3, sticky="ew")
        ttk.Button(btn_frame, text="Copy to Clipboard", style="Action.TButton",
                   command=self.copy_to_clipboard).grid(row=0, column=2, padx=3, sticky="ew")

        ttk.Button(btn_frame, text="Remove Service Config", style="NoService.TButton",
                   command=self.generate_remove).grid(row=1, column=0, padx=3, pady=(6, 0), sticky="ew")
        ttk.Button(btn_frame, text="Save Remove Config", style="NoService.TButton",
                   command=self.save_remove_file).grid(row=1, column=1, padx=3, pady=(6, 0), sticky="ew")
        ttk.Button(btn_frame, text="Copy to Clipboard", style="NoService.TButton",
                   command=self.copy_remove_to_clipboard).grid(row=1, column=2, padx=3, pady=(6, 0), sticky="ew")

        ttk.Button(btn_frame, text="▶  Start RPC Trace Log", style="RpcStart.TButton",
                   command=self._start_rpc_trace).grid(
                   row=2, column=0, columnspan=2, padx=3, pady=(6, 0), sticky="ew")
        ttk.Button(btn_frame, text="■  Stop", style="RpcStop.TButton",
                   command=self._stop_rpc_trace).grid(
                   row=2, column=2, padx=3, pady=(6, 0), sticky="ew")

        ttk.Button(btn_frame, text="Save RPC Trace Log", style="RpcStart.TButton",
                   command=self.save_rpc_log).grid(row=3, column=0, padx=3, pady=(3, 0), sticky="ew")
        ttk.Button(btn_frame, text="Copy RPC Trace Log", style="RpcStart.TButton",
                   command=self.copy_rpc_log).grid(row=3, column=1, columnspan=2, padx=3, pady=(3, 0), sticky="ew")

        ttk.Button(btn_frame, text="Provisioning ONU Configuration from NSO via SSH", style="Deploy.TButton",
                   command=self._deploy_to_nso).grid(
                   row=4, column=0, columnspan=3, padx=3, pady=(6, 0), sticky="ew")

        ttk.Button(btn_frame, text="Remove ONU SERVICE from NSO via SSH", style="NoSvcDeploy.TButton",
                   command=self._deploy_remove_to_nso).grid(
                   row=5, column=0, columnspan=3, padx=3, pady=(3, 0), sticky="ew")

        ttk.Button(btn_frame, text="↺  Reset to Defaults", style="Reset.TButton",
                   command=self._reset_defaults).grid(
                   row=6, column=0, columnspan=3, padx=3, pady=(6, 0), sticky="ew")

    def _build_rule_section(self, parent):
        MAX_RULES   = 8
        PBIT_VALUES = ["any", "0", "1", "2", "3", "4", "5", "6", "7"]
        sec = {
            "num_rules_var":        tk.StringVar(value="1"),
            "rule_type_vars":       [],
            "rule_vlan_vars":       [],
            "rule_untag_pbit_vars": [],
            "rule_pbit_vars":       [],
            "rule_rewrite_vars":    [],
            "rule_rw_vlan_vars":    [],
            "rule_rw_pbit_vars":    [],
            "rule_widgets":         [],
            "rule_type_callbacks":  [],
        }
        r = 0
        ttk.Label(parent, text="Number of Rules:").grid(
            row=r, column=0, sticky="w", padx=(8, 4), pady=3)
        spin = ttk.Spinbox(parent, from_=1, to=MAX_RULES,
                           textvariable=sec["num_rules_var"], width=5,
                           command=lambda s=sec: self._update_rule_rows_for(s))
        spin.grid(row=r, column=1, sticky="w", padx=(0, 10), pady=3)
        spin.bind("<FocusOut>", lambda e, s=sec: self._update_rule_rows_for(s))
        r += 1

        for i in range(MAX_RULES):
            lbl = ttk.Label(parent, text=f"  Rule {i + 1}:")
            lbl.grid(row=r, column=0, sticky="w", padx=(14, 4), pady=2)
            sub = ttk.Frame(parent)
            sub.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=2)
            r += 1

            type_var       = tk.StringVar(value="Untag")
            vlan_var       = tk.StringVar(value="")
            untag_pbit_var = tk.StringVar(value="0")
            pbit_var       = tk.StringVar(value="any")
            rewrite_var    = tk.BooleanVar(value=False)
            rw_vlan_var    = tk.StringVar(value="")
            rw_pbit_var    = tk.StringVar(value="0")

            type_cb = ttk.Combobox(sub, textvariable=type_var,
                                   values=["Untag", "Single Tag"],
                                   width=11, state="readonly")
            type_cb.grid(row=0, column=0)

            vlan_lbl = ttk.Label(sub, text="  Add VLAN:")
            vlan_lbl.grid(row=0, column=1, padx=(4, 0))
            ttk.Entry(sub, textvariable=vlan_var, width=7).grid(row=0, column=2, padx=(2, 0))

            wpbit_lbl = ttk.Label(sub, text="  write-pbit:")
            wpbit_lbl.grid(row=0, column=3, padx=(6, 0))
            wpbit_cb = ttk.Combobox(sub, textvariable=untag_pbit_var,
                                    values=["0","1","2","3","4","5","6","7"],
                                    width=4, state="readonly")
            wpbit_cb.grid(row=0, column=4, padx=(2, 0))

            fpbit_lbl = ttk.Label(sub, text="  Filter pbit:")
            fpbit_lbl.grid(row=0, column=3, padx=(6, 0))
            fpbit_cb = ttk.Combobox(sub, textvariable=pbit_var, values=PBIT_VALUES,
                                    width=5, state="readonly")
            fpbit_cb.grid(row=0, column=4, padx=(2, 0))
            rewrite_chk = ttk.Checkbutton(sub, text=" Rewrite", variable=rewrite_var)
            rewrite_chk.grid(row=0, column=5, padx=(10, 0))
            rw_vlan_lbl = ttk.Label(sub, text="  VLAN:")
            rw_vlan_lbl.grid(row=0, column=6, padx=(4, 0))
            rw_vlan_entry = ttk.Entry(sub, textvariable=rw_vlan_var, width=6)
            rw_vlan_entry.grid(row=0, column=7, padx=(2, 0))
            rw_pbit_lbl = ttk.Label(sub, text="  pbit:")
            rw_pbit_lbl.grid(row=0, column=8, padx=(4, 0))
            rw_pbit_cb = ttk.Combobox(sub, textvariable=rw_pbit_var, values=PBIT_VALUES,
                                      width=5, state="readonly")
            rw_pbit_cb.grid(row=0, column=9, padx=(2, 0))

            fpbit_lbl.grid_remove(); fpbit_cb.grid_remove()
            rewrite_chk.grid_remove()
            rw_vlan_lbl.grid_remove(); rw_vlan_entry.grid_remove()
            rw_pbit_lbl.grid_remove(); rw_pbit_cb.grid_remove()

            def _on_type(ev=None, tv=type_var, vl=vlan_lbl,
                         wl=wpbit_lbl, wc=wpbit_cb,
                         fl=fpbit_lbl, fc=fpbit_cb, rchk=rewrite_chk,
                         rvll=rw_vlan_lbl, rvle=rw_vlan_entry,
                         rpl=rw_pbit_lbl, rpc=rw_pbit_cb):
                if tv.get() == "Single Tag":
                    vl.config(text="  Filter VLAN:")
                    wl.grid_remove(); wc.grid_remove()
                    fl.grid(); fc.grid(); rchk.grid()
                    rvll.grid(); rvle.grid(); rpl.grid(); rpc.grid()
                else:
                    vl.config(text="  Add VLAN:")
                    wl.grid(); wc.grid()
                    fl.grid_remove(); fc.grid_remove(); rchk.grid_remove()
                    rvll.grid_remove(); rvle.grid_remove()
                    rpl.grid_remove(); rpc.grid_remove()

            type_cb.bind("<<ComboboxSelected>>", _on_type)
            sec["rule_type_callbacks"].append(_on_type)

            sec["rule_type_vars"].append(type_var)
            sec["rule_vlan_vars"].append(vlan_var)
            sec["rule_untag_pbit_vars"].append(untag_pbit_var)
            sec["rule_pbit_vars"].append(pbit_var)
            sec["rule_rewrite_vars"].append(rewrite_var)
            sec["rule_rw_vlan_vars"].append(rw_vlan_var)
            sec["rule_rw_pbit_vars"].append(rw_pbit_var)
            sec["rule_widgets"].append((lbl, sub))

        self._update_rule_rows_for(sec)
        return sec

    @staticmethod
    def _enable_tab_drag(nb):
        """Allow tabs to be reordered by holding and dragging."""
        state = {"idx": None}

        def _press(e):
            try:
                state["idx"] = nb.index(f"@{e.x},{e.y}")
            except Exception:
                state["idx"] = None

        def _motion(e):
            src = state["idx"]
            if src is None:
                return
            try:
                dst = nb.index(f"@{e.x},{e.y}")
            except Exception:
                return
            if dst != src:
                nb.insert(dst, nb.tabs()[src])
                state["idx"] = dst

        def _release(_e):
            state["idx"] = None

        nb.bind("<ButtonPress-1>",   _press)
        nb.bind("<B1-Motion>",       _motion)
        nb.bind("<ButtonRelease-1>", _release)

    def _sep(self, parent, text, row):
        ttk.Label(parent, text=text, style="Section.TLabel").grid(
            row=row, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 2))
        ttk.Separator(parent, orient="horizontal").grid(
            row=row + 1, column=0, columnspan=2, sticky="ew", padx=6)
        return row + 2

    def _row(self, parent, label, default, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(14, 4), pady=3)
        var = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=var, width=22).grid(
            row=row, column=1, sticky="ew", padx=(0, 10), pady=3)
        parent.columnconfigure(1, weight=1)
        return var

    def _row_password(self, parent, label, row):
        return self._row_password_default(parent, label, "", row)

    def _row_password_default(self, parent, label, default, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(14, 4), pady=3)
        var = tk.StringVar(value=default)
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=1, sticky="ew", padx=(0, 10), pady=3)
        frame.columnconfigure(0, weight=1)
        entry = ttk.Entry(frame, textvariable=var, show="*")
        entry.grid(row=0, column=0, sticky="ew")

        def _toggle(e=entry):
            e.config(show="" if e.cget("show") == "*" else "*")

        ttk.Button(frame, text="👁", width=2, command=_toggle).grid(
            row=0, column=1, padx=(4, 0))
        return var

    def _toggle_uni_port(self, *_):
        if self.v["mode"].get() == "PPTP":
            self._uni_lbl.grid()
            self._uni_entry.grid()
        else:
            self._uni_lbl.grid_remove()
            self._uni_entry.grid_remove()
        self._update_uni_groups()

    def _update_rule_rows_for(self, section, *_):
        try:
            n = max(1, min(8, int(section["num_rules_var"].get())))
        except (ValueError, KeyError):
            n = 1
        for i, (lbl, frm) in enumerate(section["rule_widgets"]):
            if i < n:
                lbl.grid(); frm.grid()
            else:
                lbl.grid_remove(); frm.grid_remove()

    def _update_uni_groups(self, *_):
        if self.v["mode"].get() == "VEIP":
            ports = [1]
        else:
            try:
                ports = [int(v) for v in self.v["uni_port"].get().split() if v.strip()]
            except ValueError:
                ports = [1]
            if not ports:
                ports = [1]
        for i, lf in enumerate(self.uni_group_frames):
            if i < len(ports):
                lf.config(text=f"UNI Port {ports[i]}")
                lf.grid()
            else:
                lf.grid_remove()

    def _update_dba_rows(self, *_):
        try:
            n = max(1, min(4, int(self.v["num_dba"].get())))
        except (ValueError, KeyError):
            n = 1
        for i, (lbl, frm) in enumerate(self.dba_widgets):
            if i < n:
                lbl.grid(); frm.grid()
            else:
                lbl.grid_remove(); frm.grid_remove()

    def _update_tcont_rows(self, *_):
        try:
            n = max(1, min(8, int(self.v["num_tcont"].get())))
        except (ValueError, KeyError):
            n = 1
        for i, (lbl, frm) in enumerate(self.tcont_widgets):
            if i < n:
                lbl.grid(); frm.grid()
            else:
                lbl.grid_remove(); frm.grid_remove()

    def _reset_defaults(self):
        if not messagebox.askyesno("Reset", "Reset tất cả về giá trị mặc định?"):
            return

        # DBA
        self.v["num_dba"].set("1")
        dba_defaults = [("1G_Type5", "0", "0", "102400000"),
                        ("", "0", "0", "0"),
                        ("", "0", "0", "0"),
                        ("", "0", "0", "0")]
        for d, (n, f, a, m) in enumerate(dba_defaults):
            self.dba_name_vars[d].set(n)
            self.dba_fixed_vars[d].set(f)
            self.dba_assured_vars[d].set(a)
            self.dba_max_vars[d].set(m)
        self._update_dba_rows()

        # VLAN & Uplink
        self.v["vlan_id"].set("1237")
        self.v["uplink_eth"].set("eth0/20")

        # PON
        self.v["pon_type"].set("GPON")
        self.v["pon_slot"].set("0")
        self.v["pon_port"].set("3")

        # ONT
        self.v["onu_id"].set("1")
        self.v["ont_serial"].set("DSNW29775988")
        self.v["mode"].set("PPTP")
        self.v["uni_port"].set("1")
        self._toggle_uni_port()

        # TCONT — GPON base 170
        base = 170
        self.v["num_tcont"].set("1")
        for t in range(len(self.tcont_alloc_vars)):
            self.tcont_alloc_vars[t].set(str(base + t))
            self.tcont_gem_vars[t].set(str(base + t))
            self.tcont_dba_vars[t].set("")
            self.tcont_vlan_vars[t].set("")
        self._update_tcont_rows()

        # UNI rules
        for sec in self.uni_sections:
            sec["num_rules_var"].set("1")
            for i in range(8):
                sec["rule_type_vars"][i].set("Untag")
                sec["rule_vlan_vars"][i].set("")
                sec["rule_untag_pbit_vars"][i].set("0")
                sec["rule_pbit_vars"][i].set("any")
                sec["rule_rewrite_vars"][i].set(False)
                sec["rule_rw_vlan_vars"][i].set("")
                sec["rule_rw_pbit_vars"][i].set("0")
                sec["rule_type_callbacks"][i]()
            self._update_rule_rows_for(sec)

        # Clear previews
        self._last_config = ""
        self._last_remove_config = ""
        self.preview.delete("1.0", tk.END)
        self.remove_preview.delete("1.0", tk.END)
        self.nb.select(0)

    def _refresh_dba_in_cb(self, event):
        try:
            n = max(1, int(self.v["num_dba"].get()))
        except (ValueError, KeyError):
            n = 1
        names = [self.dba_name_vars[i].get() for i in range(n)]
        event.widget["values"] = names

    def _build_preview_panel(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True)
        self._enable_tab_drag(self.nb)

        # ── Tab 1: Config Preview ────────────────────────────────────────────
        tab_cfg = ttk.Frame(self.nb)
        self.nb.add(tab_cfg, text="Config Preview")

        self.preview = tk.Text(
            tab_cfg, font=("Consolas", 9), wrap=tk.WORD,
            bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", borderwidth=1,
        )
        vsb1 = ttk.Scrollbar(tab_cfg, orient="vertical", command=self.preview.yview)
        self.preview.configure(yscrollcommand=vsb1.set)
        vsb1.pack(side="right", fill="y")
        self.preview.pack(fill="both", expand=True)

        self.preview.tag_configure("section", foreground="#569cd6", font=("Consolas", 9, "bold"))
        self.preview.tag_configure("keyword", foreground="#4ec9b0")

        # ── Tab 2: Deploy Log ────────────────────────────────────────────────
        tab_log = ttk.Frame(self.nb)
        self.nb.add(tab_log, text="Deploy Log")

        self.deploy_log = tk.Text(
            tab_log, font=("Consolas", 9), wrap=tk.WORD,
            bg="#0d1117", fg="#e6edf3",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", borderwidth=1, state="disabled",
        )
        vsb2 = ttk.Scrollbar(tab_log, orient="vertical", command=self.deploy_log.yview)
        self.deploy_log.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self.deploy_log.pack(fill="both", expand=True)

        self.deploy_log.tag_configure("ok",  foreground="#3fb950")
        self.deploy_log.tag_configure("err", foreground="#f85149")
        self.deploy_log.tag_configure("cmd", foreground="#79c0ff", font=("Consolas", 9, "bold"))

        # ── Tab 3: No Service Preview ────────────────────────────────────────
        tab_rm = ttk.Frame(self.nb)
        self.nb.add(tab_rm, text="No Service Preview")

        self.remove_preview = tk.Text(
            tab_rm, font=("Consolas", 9), wrap=tk.WORD,
            bg="#1e1e1e", fg="#f48771",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", borderwidth=1,
        )
        vsb3 = ttk.Scrollbar(tab_rm, orient="vertical", command=self.remove_preview.yview)
        self.remove_preview.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self.remove_preview.pack(fill="both", expand=True)

        self.remove_preview.tag_configure("section", foreground="#ce9178", font=("Consolas", 9, "bold"))
        self.remove_preview.tag_configure("no_cmd",  foreground="#f44747")

        # ── Tab 4: RPC Trace Log ─────────────────────────────────────────────
        tab_rpc = ttk.Frame(self.nb)
        self.nb.add(tab_rpc, text="RPC Trace Log")

        self.rpc_log_widget = tk.Text(
            tab_rpc, font=("Consolas", 9), wrap=tk.WORD,
            bg="#001a00", fg="#00ff41",
            insertbackground="white", selectbackground="#004d00",
            relief="flat", borderwidth=1, state="disabled",
        )
        vsb4 = ttk.Scrollbar(tab_rpc, orient="vertical", command=self.rpc_log_widget.yview)
        self.rpc_log_widget.configure(yscrollcommand=vsb4.set)
        vsb4.pack(side="right", fill="y")
        self.rpc_log_widget.pack(fill="both", expand=True)

        self.rpc_log_widget.tag_configure("ok",  foreground="#00ff41", font=("Consolas", 9, "bold"))
        self.rpc_log_widget.tag_configure("err", foreground="#ff4444")
        self.rpc_log_widget.tag_configure("cmd", foreground="#00ccff", font=("Consolas", 9, "bold"))

        # ── Tab 5: OLT Terminal ──────────────────────────────────────────────
        tab_olt = ttk.Frame(self.nb)
        self.nb.add(tab_olt, text="OLT Terminal")

        # Terminal widget — no wrap, horizontal scroll for long OLT output lines
        term_frame = tk.Frame(tab_olt, bg="#0d0d0d")
        term_frame.pack(fill="both", expand=True)

        self.olt_terminal = tk.Text(
            term_frame, font=("Consolas", 10), wrap=tk.NONE,
            bg="#0d0d0d", fg="#e0e0e0",
            insertbackground="#00d4ff", selectbackground="#264f78",
            relief="flat", borderwidth=0, state="normal",
            cursor="xterm", padx=6, pady=4,
        )
        vsb5 = ttk.Scrollbar(term_frame, orient="vertical",
                              command=self.olt_terminal.yview)
        hsb5 = ttk.Scrollbar(term_frame, orient="horizontal",
                              command=self.olt_terminal.xview)
        self.olt_terminal.configure(yscrollcommand=vsb5.set,
                                    xscrollcommand=hsb5.set)
        vsb5.pack(side="right",  fill="y")
        hsb5.pack(side="bottom", fill="x")
        self.olt_terminal.pack(fill="both", expand=True)

        # ── Built-in tags ──────────────────────────────────────────────────────
        _bf = ("Consolas", 10, "bold")
        _nf = ("Consolas", 10)
        self.olt_terminal.tag_configure("input", foreground="#00d4ff", font=_bf)
        self.olt_terminal.tag_configure("err",   foreground="#ff6b6b", font=_nf)
        self.olt_terminal.tag_configure("sys",   foreground="#ffa500", font=_bf)

        # ── ANSI SGR color tags ────────────────────────────────────────────────
        _FG = {30:"#555753", 31:"#ef2929", 32:"#8ae234", 33:"#fce94f",
               34:"#729fcf", 35:"#ad7fa8", 36:"#34e2e2", 37:"#d3d7cf",
               90:"#888a85", 91:"#ff5555", 92:"#50fa7b", 93:"#f1fa8c",
               94:"#6272a4", 95:"#ff79c6", 96:"#8be9fd", 97:"#f8f8f2"}
        _BG = {40:"#000000", 41:"#c01c28", 42:"#26a269", 43:"#a2734c",
               44:"#12488b", 45:"#a347ba", 46:"#2aa1b3", 47:"#d0cfcc",
              100:"#5e5c64",101:"#f66151",102:"#33d17a",103:"#e9ad0c",
              104:"#2a7bde",105:"#c061cb",106:"#33c7de",107:"#ffffff"}
        for code, color in _FG.items():
            self.olt_terminal.tag_configure(f"fg{code}", foreground=color)
        for code, color in _BG.items():
            self.olt_terminal.tag_configure(f"bg{code}", background=color)
        self.olt_terminal.tag_configure("bold", font=_bf)
        self.olt_terminal.tag_configure("dim",  foreground="#888888")
        self.olt_terminal.tag_configure("underline", underline=True)

        # ── Key bindings ───────────────────────────────────────────────────────
        self.olt_terminal.bind("<Key>",       self._olt_key_handler)
        self.olt_terminal.bind("<BackSpace>", self._olt_key_handler)

        # ── Right-click context menu ───────────────────────────────────────────
        _menu = tk.Menu(self.olt_terminal, tearoff=0)
        _menu.add_command(label="Copy",        command=lambda: self.olt_terminal.event_generate("<<Copy>>"))
        _menu.add_command(label="Paste to CLI",
                          command=lambda: self._olt_paste_from_clipboard())
        _menu.add_separator()
        _menu.add_command(label="Clear",       command=self._olt_clear_terminal)
        _menu.add_command(label="Select All",  command=lambda: self.olt_terminal.tag_add(
            "sel", "1.0", "end"))
        self.olt_terminal.bind("<Button-3>",
                               lambda e: _menu.tk_popup(e.x_root, e.y_root))

        # ── Status bar ─────────────────────────────────────────────────────────
        _sb = tk.Frame(tab_olt, bg="#1a1a2e", height=22)
        _sb.pack(fill="x")
        _sb.pack_propagate(False)
        self._olt_status_var = tk.StringVar(value="  ○  Disconnected")
        tk.Label(_sb, textvariable=self._olt_status_var,
                 bg="#1a1a2e", fg="#888888",
                 font=("Segoe UI", 8)).pack(side="left", padx=4)
        ttk.Button(_sb, text="Clear", command=self._olt_clear_terminal,
                   width=5).pack(side="right", padx=4, pady=2)

        # Start output polling loop (runs for lifetime of app)
        self.root.after(50, self._olt_poll_output)

    # ─── Actions ──────────────────────────────────────────────────────────────

    def generate(self):
        params = self._parse_inputs()
        if params is None:
            return
        self._last_config = self._build_config(params)
        self._show_preview(self._last_config)

    def save_file(self):
        if not self._last_config:
            self.generate()
        if not self._last_config:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="GPON_NSO_Config.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_config)
            messagebox.showinfo("Saved", f"Config saved to:\n{path}")

    def copy_to_clipboard(self):
        if not self._last_config:
            self.generate()
        if self._last_config:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._last_config)
            messagebox.showinfo("Copied", "Config copied to clipboard.")

    def generate_remove(self):
        params = self._parse_inputs()
        if params is None:
            return
        self._last_remove_config = self._build_remove_config(params)
        self._show_remove_preview(self._last_remove_config)
        self.nb.select(2)

    def save_remove_file(self):
        if not self._last_remove_config:
            self.generate_remove()
        if not self._last_remove_config:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="GPON_NSO_NoService.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_remove_config)
            messagebox.showinfo("Saved", f"No Service config saved to:\n{path}")

    def copy_remove_to_clipboard(self):
        if not self._last_remove_config:
            self.generate_remove()
        if self._last_remove_config:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._last_remove_config)
            messagebox.showinfo("Copied", "No Service config copied to clipboard.")

    def _deploy_remove_to_nso(self):
        if not _PARAMIKO_OK:
            messagebox.showerror(
                "Missing library",
                "paramiko is not installed.\n\nRun:  pip install paramiko")
            return

        if not self._last_remove_config:
            self.generate_remove()
        if not self._last_remove_config:
            return

        ip        = self.v["ssh_ip"].get().strip()
        user      = self.v["ssh_user"].get().strip()
        passwd    = self.v["ssh_pass"].get()
        root_pw   = self.v["ssh_root_pass"].get()
        device    = self.v["ssh_device"].get().strip()
        try:
            cmd_delay = float(self.v["ssh_cmd_delay"].get())
        except ValueError:
            cmd_delay = 0.05

        if not all([ip, user, passwd, device]):
            messagebox.showerror("SSH Error", "Please fill in: NSO IP, Username, Password, Device Name.")
            return

        self.nb.select(1)
        self._log_clear()
        self._log(f"Starting NO SERVICE deploy to {ip} …\n", "cmd")

        t = threading.Thread(
            target=self._ssh_worker,
            args=(ip, user, passwd, root_pw, device, self._last_remove_config, cmd_delay),
            daemon=True,
        )
        t.start()

    def _start_rpc_trace(self):
        if not _PARAMIKO_OK:
            messagebox.showerror(
                "Missing library",
                "paramiko is not installed.\n\nRun:  pip install paramiko")
            return

        ip      = self.v["ssh_ip"].get().strip()
        user    = self.v["ssh_user"].get().strip()
        passwd  = self.v["ssh_pass"].get()
        root_pw = self.v["ssh_root_pass"].get()
        device  = self.v["ssh_device"].get().strip()

        if not all([ip, user, passwd, device]):
            messagebox.showerror("SSH Error", "Please fill in: NSO IP, Username, Password, Device Name.")
            return

        self.nb.select(3)
        self._rpc_stop_event.clear()
        self._rpc_log_clear()
        self._rpc_log(f"Connecting to {ip} for RPC trace ...\n", "cmd")

        t = threading.Thread(
            target=self._rpc_trace_worker,
            args=(ip, user, passwd, root_pw, device),
            daemon=True,
        )
        t.start()

    def _stop_rpc_trace(self):
        self._rpc_stop_event.set()
        if self._rpc_client:
            try:
                self._rpc_client.close()
            except Exception:
                pass
            self._rpc_client = None
        self._rpc_log("\n[RPC Trace stopped by user]\n", "cmd")

    def _rpc_trace_worker(self, ip, username, password, root_password, device_name):
        def drain(shell, timeout=3):
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    shell.recv(4096)
                    deadline = time.time() + 0.5
                else:
                    time.sleep(0.1)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=30)
            self._rpc_log("Connected.\n", "ok")
            self._rpc_client = client

            shell = client.invoke_shell(width=220, height=50)
            drain(shell, timeout=3)

            # sudo su
            shell.send("sudo su\n")
            time.sleep(2)
            out = b""
            deadline = time.time() + 5
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(4096)
                    out += chunk
                    deadline = time.time() + 0.5
                else:
                    time.sleep(0.1)
            if b"assword" in out:
                shell.send((root_password or password) + "\n")
                drain(shell, timeout=4)

            # cd to logs directory
            shell.send("cd /root/nso/ncs-run/logs/\n")
            drain(shell, timeout=2)

            # tail -f
            trace_file = f"netconf-{device_name}.trace"
            shell.send(f"tail -f {trace_file}\n")
            self._rpc_log(f">>> tail -f {trace_file}\n", "cmd")

            # Stream until stop event
            while not self._rpc_stop_event.is_set():
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="replace")
                    self._rpc_log(chunk)
                else:
                    time.sleep(0.1)

            self._rpc_log("\n[Stream ended]\n", "ok")
            client.close()
            self._rpc_client = None

        except Exception as exc:
            self._rpc_log(f"\n[ERROR] {exc}\n", "err")
            self._rpc_client = None

    def _rpc_log(self, text, tag=None):
        self.root.after(0, self._rpc_log_ui, text, tag)

    def _rpc_log_ui(self, text, tag):
        self.rpc_log_widget.configure(state="normal")
        if tag:
            self.rpc_log_widget.insert(tk.END, text, tag)
        else:
            self.rpc_log_widget.insert(tk.END, text)
        self.rpc_log_widget.see(tk.END)
        self.rpc_log_widget.configure(state="disabled")

    def _rpc_log_clear(self):
        self.root.after(0, self._rpc_log_clear_ui)

    def _rpc_log_clear_ui(self):
        self.rpc_log_widget.configure(state="normal")
        self.rpc_log_widget.delete("1.0", tk.END)
        self.rpc_log_widget.configure(state="disabled")

    def save_rpc_log(self):
        content = self.rpc_log_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Empty", "RPC Trace Log is empty.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="RPC_Trace_Log.txt",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Saved", f"RPC Trace Log saved to:\n{path}")

    def copy_rpc_log(self):
        content = self.rpc_log_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Empty", "RPC Trace Log is empty.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "RPC Trace Log copied to clipboard.")

    # ─── OLT Terminal ─────────────────────────────────────────────────────────

    def _olt_proto_changed(self):
        self.v["olt_port"].set("22" if self.v["olt_proto"].get() == "SSH" else "23")

    def _connect_olt(self):
        if self.v["olt_proto"].get() == "SSH" and not _PARAMIKO_OK:
            messagebox.showerror("Error", "paramiko not installed.\nRun: pip install paramiko")
            return
        ip    = self.v["olt_ip"].get().strip()
        user  = self.v["olt_user"].get().strip()
        pw    = self.v["olt_pass"].get()
        proto = self.v["olt_proto"].get()
        try:
            port = int(self.v["olt_port"].get() or ("22" if proto == "SSH" else "23"))
        except ValueError:
            port = 22 if proto == "SSH" else 23
        if not ip:
            messagebox.showerror("Error", "OLT IP is required.")
            return
        self._olt_stop_event.clear()
        self.nb.select(4)
        self._olt_log(f"[Connecting to {ip}:{port} via {proto} ...]\n", "sys")
        threading.Thread(target=self._olt_worker,
                         args=(ip, user, pw, port, proto), daemon=True).start()

    def _olt_worker(self, ip, user, pw, port, proto):
        try:
            if proto == "SSH":
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=pw, timeout=15)
                self._olt_client = client
                shell = client.invoke_shell(width=220, height=50)
                self._olt_shell = shell
                self._olt_log("[Connected via SSH]\n", "sys")
                self.root.after(0, lambda: self._olt_status_var.set(
                    f"  ●  SSH  {ip}:{port}  |  {user}")
                    if hasattr(self, '_olt_status_var') else None)
                time.sleep(0.8)
                if shell.recv_ready():
                    self._olt_log(shell.recv(4096).decode("utf-8", errors="replace"))
                while not self._olt_stop_event.is_set():
                    if shell.recv_ready():
                        self._olt_log(shell.recv(4096).decode("utf-8", errors="replace"))
                    elif shell.closed:
                        break
                    else:
                        time.sleep(0.05)
            else:  # Telnet via raw socket
                sock = socket.create_connection((ip, port), timeout=15)
                sock.settimeout(0.2)
                self._olt_sock = sock
                self._olt_log("[Connected via Telnet]\n", "sys")
                self.root.after(0, lambda: self._olt_status_var.set(
                    f"  ●  Telnet  {ip}:{port}")
                    if hasattr(self, '_olt_status_var') else None)
                # Banner + IAC negotiation (respond + display)
                self._olt_telnet_drain(sock, silence=0.8)
                # Auto-send credentials if provided
                if user:
                    sock.send((user + "\r\n").encode("utf-8"))
                    self._olt_telnet_drain(sock, silence=0.6)
                if pw:
                    sock.send((pw + "\r\n").encode("utf-8"))
                    self._olt_telnet_drain(sock, silence=0.6)
                # Main receive loop
                while not self._olt_stop_event.is_set():
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        text = self._olt_handle_iac(sock, chunk)
                        if text:
                            self._olt_log(text)
                    except socket.timeout:
                        pass
        except Exception as exc:
            self._olt_log(f"\n[ERROR] {exc}\n", "err")
        finally:
            self._olt_log("\n[Session ended]\n", "sys")
            self.root.after(0, lambda: self._olt_status_var.set("  ○  Disconnected")
                            if hasattr(self, '_olt_status_var') else None)
            self._olt_client = None
            self._olt_shell  = None
            self._olt_sock   = None

    def _olt_handle_iac(self, sock, data):
        IAC = 255; DO = 253; DONT = 254; WILL = 251; WONT = 252; SB = 250; SE = 240
        out, i = [], 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd == SB:
                    end = data.find(bytes([IAC, SE]), i + 2)
                    i = (end + 2) if end != -1 else len(data)
                elif cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                    opt = data[i + 2]
                    try:
                        sock.send(bytes([IAC, WONT if cmd == DO else DONT, opt]))
                    except Exception:
                        pass
                    i += 3
                else:
                    i += 2
            else:
                if b != 0:
                    out.append(b)
                i += 1
        text = bytes(out).decode("latin-1")
        # Keep SGR color codes (\x1b[...m); strip cursor/erase/other escapes
        text = re.sub(r'\x1b\[[0-9;]*[ABCDEFGHJKSTfnsu]', '', text)
        text = re.sub(r'\x1b\[[?][0-9;]*[hl]', '', text)
        text = re.sub(r'\x1b\][^\x07\x1b]*\x07', '', text)
        text = re.sub(r'\x1b[()][AB012]', '', text)
        text = re.sub(r'\x1b[>=<M78]', '', text)
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        return text

    def _olt_telnet_drain(self, sock, silence=0.5):
        last = time.time()
        while time.time() - last < silence:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                text = self._olt_handle_iac(sock, chunk)
                if text:
                    self._olt_log(text)
                last = time.time()
            except socket.timeout:
                pass

    def _disconnect_olt(self):
        self._olt_stop_event.set()
        for obj in (self._olt_shell, self._olt_client, self._olt_sock):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        self._olt_client = None
        self._olt_shell  = None
        self._olt_sock   = None

    # ── Direct terminal input ─────────────────────────────────────────────────

    def _olt_key_handler(self, event):
        """Intercept all keypresses — route to pending input buffer or send raw."""
        ctrl = bool(event.state & 0x4)

        # ── Ctrl combos ────────────────────────────────────────────────────────
        if ctrl:
            if event.keysym in ('c', 'C'):
                # Ctrl+C: send interrupt (ETX) if connected, else allow copy
                if self._olt_shell or self._olt_sock:
                    self._olt_send_raw(b'\x03')
                    self._olt_pending_input = ""
                    self._olt_update_input_line()
                    return "break"
                return None   # let Ctrl+C copy selection
            if event.keysym in ('d', 'D'):
                self._olt_send_raw(b'\x04'); return "break"   # EOF / logout
            if event.keysym in ('l', 'L'):
                self._olt_clear_terminal(); return "break"    # clear screen
            if event.keysym in ('a', 'A'):
                return None   # allow Ctrl+A select-all
            if event.keysym in ('z', 'Z'):
                self._olt_send_raw(b'\x1a'); return "break"   # suspend
            return None   # other Ctrl: pass through

        # ── Navigation ────────────────────────────────────────────────────────
        if event.keysym in ("Return", "KP_Enter"):
            self._olt_do_send(); return "break"
        if event.keysym == "BackSpace":
            if self._olt_pending_input:
                self._olt_pending_input = self._olt_pending_input[:-1]
                self._olt_update_input_line()
            else:
                self._olt_send_raw(b'\x7f')
            return "break"
        if event.keysym == "Delete":
            self._olt_send_raw(b'\x1b[3~'); return "break"
        if event.keysym == "Up":
            self._olt_hist_prev(); return "break"
        if event.keysym == "Down":
            self._olt_hist_next(); return "break"
        if event.keysym == "Left":
            self._olt_send_raw(b'\x1b[D'); return "break"
        if event.keysym == "Right":
            self._olt_send_raw(b'\x1b[C'); return "break"
        if event.keysym == "Home":
            self._olt_send_raw(b'\x01'); return "break"
        if event.keysym == "End":
            self._olt_send_raw(b'\x05'); return "break"
        if event.keysym == "Tab":
            # Tab completion — send raw, also display in input if no connection
            if self._olt_shell or self._olt_sock:
                self._olt_send_raw(b'\t')
            else:
                self._olt_pending_input += '\t'
                self._olt_update_input_line()
            return "break"
        if event.keysym in ("Escape",):
            self._olt_send_raw(b'\x1b'); return "break"

        # ── Printable characters ───────────────────────────────────────────────
        if event.char and event.char.isprintable():
            self._olt_pending_input += event.char
            self._olt_update_input_line()
            return "break"
        return "break"

    def _olt_send_raw(self, data: bytes):
        """Send raw bytes directly to SSH shell or Telnet socket."""
        try:
            if self._olt_shell and not self._olt_shell.closed:
                self._olt_shell.send(data)
            elif self._olt_sock:
                self._olt_sock.send(data)
        except Exception:
            pass

    def _olt_paste_from_clipboard(self):
        """Paste clipboard text into pending input and send."""
        try:
            text = self.root.clipboard_get()
            self._olt_pending_input += text
            self._olt_update_input_line()
        except Exception:
            pass

    def _olt_update_input_line(self):
        """Redraw last line of terminal to reflect _olt_pending_input."""
        t = self.olt_terminal
        last = t.index("end-1l linestart")
        t.delete(last, "end-1c")
        if self._olt_pending_input:
            t.insert(last, self._olt_pending_input, "input")
        t.mark_set("insert", "end-1c")
        t.see("end")

    def _olt_do_send(self):
        cmd = self._olt_pending_input.strip()
        if not self._olt_shell and not self._olt_sock:
            self._olt_log("[Not connected. Use 'Connect OLT' button.]\n", "err")
            self._olt_pending_input = ""
            self._olt_update_input_line()
            return
        if cmd and (not self._olt_cmd_history or self._olt_cmd_history[-1] != cmd):
            self._olt_cmd_history.append(cmd)
        self._olt_hist_idx = -1
        self._olt_pending_input = ""
        self._olt_update_input_line()
        self._olt_log(f"{cmd}\n", "input")
        try:
            if self._olt_shell and not self._olt_shell.closed:
                self._olt_shell.send(cmd + "\n")
            elif self._olt_sock:
                self._olt_sock.send((cmd + "\r\n").encode("utf-8"))
        except Exception as exc:
            self._olt_log(f"[Send error: {exc}]\n", "err")

    def _olt_hist_prev(self):
        if not self._olt_cmd_history:
            return
        if self._olt_hist_idx == -1:
            self._olt_hist_idx = len(self._olt_cmd_history) - 1
        elif self._olt_hist_idx > 0:
            self._olt_hist_idx -= 1
        self._olt_pending_input = self._olt_cmd_history[self._olt_hist_idx]
        self._olt_update_input_line()

    def _olt_hist_next(self):
        if self._olt_hist_idx == -1:
            return
        self._olt_hist_idx += 1
        if self._olt_hist_idx >= len(self._olt_cmd_history):
            self._olt_hist_idx = -1
            self._olt_pending_input = ""
        else:
            self._olt_pending_input = self._olt_cmd_history[self._olt_hist_idx]
        self._olt_update_input_line()

    def _olt_log(self, text, tag=None):
        """Thread-safe: queue output for main-thread insertion."""
        self._olt_output_queue.put((text, tag))

    # ── ANSI SGR parser ────────────────────────────────────────────────────────

    _ANSI_SGR = re.compile(r'\x1b\[([0-9;]*)m')

    def _olt_ansi_insert(self, widget, text, override_tag=None):
        """Insert text with ANSI SGR color codes rendered as tkinter tags.
        Maintains self._olt_ansi_state across successive calls."""
        if override_tag:
            # System/error messages: insert plain with fixed tag
            widget.insert(tk.END, text, override_tag)
            return

        state = self._olt_ansi_state
        pos   = 0

        for m in self._ANSI_SGR.finditer(text):
            # Insert plain segment before this escape
            if m.start() > pos:
                widget.insert(tk.END, text[pos:m.start()], tuple(state))

            codes = m.group(1).split(';') if m.group(1) else ['0']
            for raw in codes:
                n = int(raw) if raw.isdigit() else 0
                if n == 0:
                    state.clear()
                elif n == 1:
                    if 'bold' not in state:
                        state.append('bold')
                elif n in (2, 22):
                    state[:] = [t for t in state if t != 'bold']
                elif n == 4:
                    if 'underline' not in state:
                        state.append('underline')
                elif n == 24:
                    state[:] = [t for t in state if t != 'underline']
                elif 30 <= n <= 37 or 90 <= n <= 97:
                    state[:] = [t for t in state if not t.startswith('fg')]
                    state.append(f'fg{n}')
                elif n == 39:
                    state[:] = [t for t in state if not t.startswith('fg')]
                elif 40 <= n <= 47 or 100 <= n <= 107:
                    state[:] = [t for t in state if not t.startswith('bg')]
                    state.append(f'bg{n}')
                elif n == 49:
                    state[:] = [t for t in state if not t.startswith('bg')]
            pos = m.end()

        if pos < len(text):
            widget.insert(tk.END, text[pos:], tuple(state))

    # ── Output poll ────────────────────────────────────────────────────────────

    def _olt_poll_output(self):
        """Main-thread polling loop: drain queue, insert with ANSI colors."""
        t       = self.olt_terminal
        changed = False
        while not self._olt_output_queue.empty():
            try:
                text, tag = self._olt_output_queue.get_nowait()
            except queue.Empty:
                break
            if text and not text.endswith("\n"):
                text += "\n"
            # Remove pending input before inserting server output
            if self._olt_pending_input:
                last = t.index("end-1l linestart")
                t.delete(last, "end-1c")
            self._olt_ansi_insert(t, text, override_tag=tag)
            # Re-draw pending input
            if self._olt_pending_input:
                t.insert(tk.END, self._olt_pending_input, "input")
            t.mark_set("insert", "end-1c")
            changed = True
        if changed:
            t.see("end")
        self.root.after(50, self._olt_poll_output)

    def _olt_clear_terminal(self):
        self._olt_pending_input = ""
        self._olt_ansi_state    = []
        self.olt_terminal.delete("1.0", tk.END)

    def _deploy_to_nso(self):
        if not _PARAMIKO_OK:
            messagebox.showerror(
                "Missing library",
                "paramiko is not installed.\n\nRun:  pip install paramiko")
            return

        if not self._last_config:
            self.generate()
        if not self._last_config:
            return

        ip        = self.v["ssh_ip"].get().strip()
        user      = self.v["ssh_user"].get().strip()
        passwd    = self.v["ssh_pass"].get()
        root_pw   = self.v["ssh_root_pass"].get()
        device    = self.v["ssh_device"].get().strip()
        try:
            cmd_delay = float(self.v["ssh_cmd_delay"].get())
        except ValueError:
            cmd_delay = 0.05

        if not all([ip, user, passwd, device]):
            messagebox.showerror("SSH Error", "Please fill in: NSO IP, Username, Password, Device Name.")
            return

        self.nb.select(1)   # switch to Deploy Log tab
        self._log_clear()
        self._log(f"Starting deploy to {ip} …\n", "cmd")

        t = threading.Thread(
            target=self._ssh_worker,
            args=(ip, user, passwd, root_pw, device, self._last_config, cmd_delay),
            daemon=True,
        )
        t.start()

    def _ssh_worker(self, ip, username, password, root_password, device_name, config, cmd_delay=0.05):
        def send(cmd, wait=1):
            self._log(f">>> {cmd}\n", "cmd")
            shell.send(cmd + "\n")
            time.sleep(wait)

        def recv(timeout=8):
            out = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="replace")
                    out += chunk
                    self._log(chunk)
                    deadline = time.time() + 2   # extend on activity
                else:
                    time.sleep(0.1)
            return out

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=30)
            self._log("Connected.\n", "ok")

            shell = client.invoke_shell(width=220, height=50)
            time.sleep(1)
            recv(timeout=3)

            # Step 1: sudo su
            send("sudo su", wait=1)
            out = recv(timeout=5)
            if "assword" in out:
                shell.send((root_password or password) + "\n")
                time.sleep(1)
                recv(timeout=4)

            # Step 2: ncs_cli
            send("ncs_cli -C -u admin", wait=0.5)
            recv(timeout=10)

            # Step 3: config
            send("config", wait=0.5)
            recv(timeout=5)

            # Step 4: devices device <name>
            send(f"devices device {device_name}", wait=0.5)
            recv(timeout=5)

            # Step 5: sync-from
            send("sync-from", wait=0.5)
            recv(timeout=30)

            # Step 6: ssh fetch-host-keys
            send("ssh fetch-host-keys", wait=0.5)
            recv(timeout=15)

            # Step 7: sync-from again
            send("sync-from", wait=0.5)
            recv(timeout=30)

            # Step 8: devices device <name> config
            send(f"devices device {device_name} config", wait=0.5)
            recv(timeout=5)

            # Step 9: paste config lines
            self._log("\n>>> [Deploying config lines...]\n", "cmd")
            for line in config.splitlines():
                if line.strip():
                    shell.send(line + "\n")
                    time.sleep(cmd_delay)
            time.sleep(2)
            recv(timeout=8)

            self._log("\n✓ Deploy completed successfully!\n", "ok")
            client.close()

        except Exception as exc:
            self._log(f"\n[ERROR] {exc}\n", "err")

    def _log(self, text, tag=None):
        self.root.after(0, self._log_ui, text, tag)

    def _log_ui(self, text, tag):
        self.deploy_log.configure(state="normal")
        if tag:
            self.deploy_log.insert(tk.END, text, tag)
        else:
            self.deploy_log.insert(tk.END, text)
        self.deploy_log.see(tk.END)
        self.deploy_log.configure(state="disabled")

    def _log_clear(self):
        self.root.after(0, self._log_clear_ui)

    def _log_clear_ui(self):
        self.deploy_log.configure(state="normal")
        self.deploy_log.delete("1.0", tk.END)
        self.deploy_log.configure(state="disabled")

    # ─── Input parsing ─────────────────────────────────────────────────────────

    def _parse_rules(self, section):
        n = max(1, int(section["num_rules_var"].get()))
        rules = []
        for i in range(n):
            rule = {
                "type": section["rule_type_vars"][i].get(),
                "vlan": int(section["rule_vlan_vars"][i].get()),
            }
            if rule["type"] == "Untag":
                rule["untag_pbit"] = section["rule_untag_pbit_vars"][i].get()
            else:  # Single Tag
                rule["filter_pbit"] = section["rule_pbit_vars"][i].get()
                rule["rewrite"]     = section["rule_rewrite_vars"][i].get()
                if rule["rewrite"]:
                    rule["rw_vlan"] = int(section["rule_rw_vlan_vars"][i].get())
                    rule["rw_pbit"] = section["rule_rw_pbit_vars"][i].get()
            rules.append(rule)
        return rules

    def _parse_inputs(self):
        try:
            mode = self.v["mode"].get()
            uni_ports = [int(v) for v in self.v["uni_port"].get().split()] if mode == "PPTP" else []
            n_uni = len(uni_ports) if mode == "PPTP" else 1
            n_dba   = max(1, int(self.v["num_dba"].get()))
            n_tcont = max(1, int(self.v["num_tcont"].get()))
            result = {
                "dba_profiles": [
                    {
                        "name":       self.dba_name_vars[i].get().strip(),
                        "fixed_bw":   int(self.dba_fixed_vars[i].get()),
                        "assured_bw": int(self.dba_assured_vars[i].get()),
                        "max_bw":     int(self.dba_max_vars[i].get()),
                    }
                    for i in range(n_dba)
                ],
                "vlan_ids":     [int(v) for v in self.v["vlan_id"].get().split()],
                "uplink_eth":   self.v["uplink_eth"].get().strip(),
                "pon_type":     self.v["pon_type"].get(),
                "pon_slot":     int(self.v["pon_slot"].get()),
                "pon_port":     int(self.v["pon_port"].get()),
                "onu_id":       int(self.v["onu_id"].get()),
                "ont_serial":   self.v["ont_serial"].get().strip().upper(),
                "mode":         mode,
                "uni_ports":    uni_ports,
                "tconts": [
                    {
                        "alloc_id": int(self.tcont_alloc_vars[i].get()),
                        "dba":      self.tcont_dba_vars[i].get().strip(),
                        "gem_id":   int(self.tcont_gem_vars[i].get()),
                        "vlan":     int(self.tcont_vlan_vars[i].get()),
                    }
                    for i in range(n_tcont)
                ],
                "rules_per_uni": [self._parse_rules(self.uni_sections[i]) for i in range(n_uni)],
            }
        except ValueError as exc:
            messagebox.showerror("Input Error", f"Invalid value: {exc}\n\nPlease check numeric fields.")
            return None
        if not result["vlan_ids"]:
            messagebox.showerror("Input Error", "Please enter at least one VLAN ID.")
            return None
        return result

    # ─── Config builder ────────────────────────────────────────────────────────

    def _build_config(self, p):
        vlans    = p["vlan_ids"]
        uplink   = p["uplink_eth"]
        pon_type = p["pon_type"]   # "GPON" or "XGSPON"

        if pon_type == "GPON":
            pon_if = f"gpon{p['pon_slot']}/{p['pon_port']}"
            cg     = f"CG_{p['pon_port']:02d}_gpon"
            pt_str = "gpon"
        else:  # XGSPON
            pon_if = f"xgspon{p['pon_slot']}/{p['pon_port']}"
            cg     = f"CG_{p['pon_port']:02d}_xgs"
            pt_str = "xgs"

        onu_str  = f"onu{p['onu_id']:03d}"
        pfx      = f"{pon_if}_{onu_str}"   # e.g. gpon0/3_onu001 or xgspon0/3_onu001
        onu_id   = p["onu_id"]
        serial   = p["ont_serial"]
        mode      = p["mode"]
        uni_ports = p["uni_ports"]   # list of UNI port numbers (PPTP) or [] (VEIP)

        # Build per-UNI config tuples: (uni_idx, ont_uni_if, olt_lower, vp_base)
        if mode == "PPTP":
            pbit_kw_pfx = "write-pbit"
            uni_configs = [(u, f"{pfx}_eth1_{u}", f"{pfx}_venet1_{u}", f"o_venet1_{u}")
                           for u in uni_ports]
        else:  # VEIP
            pbit_kw_pfx = "write-pbit"
            uni_configs = [(1, f"{pfx}_veip_1", f"{pfx}_venet1_1", "o_venet1_1")]

        L = []

        # ── Section 1: DBA Profiles ─────────────────────────────────────────
        L.append("!##############DBA-profile")
        for dba_prof in p["dba_profiles"]:
            L.append(
                f"xpongemtcont traffic-descriptor-profiles traffic-descriptor-profile"
                f" {dba_prof['name']}"
                f" fixed-bandwidth {dba_prof['fixed_bw']}"
                f" assured-bandwidth {dba_prof['assured_bw']}"
                f" maximum-bandwidth {dba_prof['max_bw']}"
            )
        L.append("")

        # ── Section 2: VLAN & Uplink ────────────────────────────────────────
        L.append("!############VLAN AND UPLINK")
        for vlan in vlans:
            L += [
                f"forwarding forwarders forwarder fwd.vlan{vlan}.cli.attach"
                f" mac-learning forwarding-database fwd.db.vlan{vlan}.cli.attach",
                f"forwarding forwarding-databases forwarding-database fwd.db.vlan{vlan}.cli.attach",
                f"interfaces interface uplink_{uplink}.{vlan}"
                f" type vlan-sub-interface subif-lower-layer interface {uplink}",
                f"interfaces interface uplink_{uplink}.{vlan}"
                f" inline-frame-processing ingress-rule rule rule.tag priority 1"
                f" flexible-match match-criteria tag 0 dot1q-tag tag-type s-vlan"
                f" vlan-id {vlan} pbit any dei any",
                f"forwarding forwarders forwarder fwd.vlan{vlan}.cli.attach"
                f" ports port fwd.uplink_{uplink}.{vlan} sub-interface uplink_{uplink}.{vlan}",
                "",
            ]
        L.append("")

        # ── Section 3: PON Interface ────────────────────────────────────────
        L += [
            "!##############PON interface",
            f"interfaces interface {cg} type channel-group enabled channel-group"
            f" polling-period 100 raman-mitigation raman-none system-id 00000"
            f" pon-pools pon-pool pool1 channel-termination-ref {pon_if}",
            f"interfaces interface {cg}.CPart type channel-partition enabled channel-partition"
            f" channel-group-ref {cg} channel-partition-index 1 downstream-fec true"
            f" closest-onu-distance 0 maximum-differential-xpon-distance 20"
            f" authentication-method serial-number multicast-aes-indicator false",
            f"interfaces interface {cg}.CPart tm-root scheduler-node NODE_DEF scheduling-level 1",
        ]
        for q in range(8):
            L.append(f"interfaces interface {cg}.CPart tm-root scheduler-node NODE_DEF queue {q}")
        L += [
            f"interfaces interface {cg}.CPart tm-root child-scheduler-nodes NODE_DEF",
            f"interfaces interface {cg}.CPart.CPair type channel-pair enabled channel-pair"
            f" channel-group-ref {cg} channel-partition-ref {cg}.CPart channel-pair-type {pt_str}",
            f"interfaces interface {pon_if} type channel-termination enabled channel-termination"
            f" channel-termination-type {pt_str} channel-pair-ref {cg}.CPart.CPair"
            f" ber-calc-period 10 location inside-olt",
            "exit",
            "",
        ]

        # ── Section 4: OLT Hardware Component ──────────────────────────────
        L += [
            "!##############OLT Hardware component",
            f"hardware component {pon_if}_cage class cage",
            f"hardware component {pon_if}_port class transceiver-link",
            f"hardware component {pon_if}_sfp class transceiver",
            f"interfaces interface {pon_if} hardware-component port-layer-if {pon_if}_port",
            "exit",
            "",
        ]

        # ── Section 5: ONT Hardware Component ──────────────────────────────
        L += [
            "!##############ONT hardware component",
            f"hardware component {pfx} class chassis parent-rel-pos 1",
            f"hardware component {pfx}_card1 class board parent {pfx}",
            f"hardware component {pfx}_cage1_1 class cage parent {pfx}_card1",
            f"hardware component {pfx}_sfp1_1 class transceiver parent {pfx}_cage1_1",
            f"hardware component {pfx}_aniport1_1 class transceiver-link parent {pfx}_sfp1_1",
        ]
        if mode == "PPTP":
            for idx_u, u in enumerate(uni_ports):
                L += [
                    f"hardware component {pfx}_uniport1_{u} class rj45"
                    f" parent {pfx}_card1 parent-rel-pos {u}",
                    f"interfaces interface {pfx}_eth1_{u} type ethernetCsmacd enabled"
                    f" hardware-component port-layer-if {pfx}_uniport1_{u}",
                ]
                if idx_u < len(uni_ports) - 1:
                    L.append("exit")
        L.append("")

        # ── Section 6: ONT Register ─────────────────────────────────────────
        L += [
            "!##############ONT register",
            f"interfaces interface {pfx}_ani1_1 type ani enabled"
            f" hardware-component port-layer-if {pfx}_aniport1_1",
            f"interfaces interface {pfx}_ani1_1 ani upstream-fec true"
            f" management-gemport-aes-indicator false onu-id {onu_id}",
            f"interfaces interface {pfx}_vani1_1 type v-ani v-ani onu-id {onu_id}"
            f" channel-partition {cg}.CPart expected-serial-number {serial}"
            f" preferred-channel-pair {cg}.CPart.CPair upstream-fec true",
            f"link-table link-table {pfx}_ani1_1 to-interface {pfx}_vani1_1",
            "",
        ]

        # ── Section 7: OLT VENET ────────────────────────────────────────────
        L.append("!##############OLT VENET")
        if mode == "PPTP":
            for u in uni_ports:
                L += [
                    f"interfaces interface {pfx}_venet1_{u} type olt-v-enet"
                    f" olt-v-enet lower-layer-interface {pfx}_vani1_1",
                    f"link-table link-table {pfx}_eth1_{u} to-interface {pfx}_venet1_{u}",
                ]
            L.append("")
        else:  # VEIP
            L += [
                f"interfaces interface {pfx}_veip_1 type onu-v-vrefpoint"
                f" onu-v-vrefpoint related-onu {pfx}_ani1_1",
                f"interfaces interface {pfx}_veip_1 enabled",
                f"interfaces interface {pfx}_venet1_1 type olt-v-enet"
                f" olt-v-enet lower-layer-interface {pfx}_vani1_1",
                f"link-table link-table {pfx}_veip_1 to-interface {pfx}_venet1_1",
                "",
            ]

        # ── Section 8: ONT Extended VLAN ────────────────────────────────────
        rules_per_uni = p["rules_per_uni"]
        L.append("!##############ONT Extended vlan")
        for idx_u, (_u, ont_uni_if, _olt_lower, _vp_base) in enumerate(uni_configs):
            rules = rules_per_uni[idx_u]
            for rule in rules:
                rtype = rule["type"]
                rvlan = rule["vlan"]
                if rtype == "Untag":
                    subif      = f"{ont_uni_if}_c{rvlan:04d}_untag"
                    untag_pbit = rule.get("untag_pbit", "0")
                    L += [
                        f"interfaces interface {subif}"
                        f" type vlan-sub-interface subif-lower-layer interface {ont_uni_if}",
                        f"interfaces interface {subif} enabled",
                        f"interfaces interface {subif}"
                        f" inline-frame-processing ingress-rule rule rule_1 priority 100"
                        f" flexible-match match-criteria untagged",
                        f"interfaces interface {subif}"
                        f" inline-frame-processing ingress-rule rule rule_1 ingress-rewrite"
                        f" push-tag 0 dot1q-tag tag-type c-vlan vlan-id {rvlan}"
                        f" {pbit_kw_pfx} {untag_pbit} write-dei-0",
                    ]
                else:  # Single Tag
                    eff_vlan_s8 = rule["rw_vlan"] if rule.get("rewrite") else rvlan
                    subif       = f"{ont_uni_if}_c{eff_vlan_s8:04d}_any"
                    filter_pbit = rule.get("filter_pbit", "any")
                    L += [
                        f"interfaces interface {subif}"
                        f" type vlan-sub-interface subif-lower-layer interface {ont_uni_if}",
                        f"interfaces interface {subif} enabled",
                        f"interfaces interface {subif}"
                        f" inline-frame-processing ingress-rule rule rule_1 priority 100"
                        f" flexible-match match-criteria tag 0 dot1q-tag tag-type c-vlan"
                        f" vlan-id {rvlan} pbit {filter_pbit} dei any",
                    ]
                    if rule.get("rewrite"):
                        rw_vlan = rule["rw_vlan"]
                        rw_pbit = rule["rw_pbit"]
                        L.append(
                            f"interfaces interface {subif}"
                            f" inline-frame-processing ingress-rule rule rule_1"
                            f" ingress-rewrite pop-tags 1 push-tag 0 dot1q-tag tag-type c-vlan"
                            f" vlan-id {rw_vlan} write-pbit {rw_pbit} write-dei-0"
                        )
        L += ["exit", "exit", "exit", ""]

        # ── Section 9: OLT V-NET SUB (VP) ───────────────────────────────────
        # Per UNI: one VP per rule; effective VLAN = rewrite target when present
        L.append("!##############OLT V-NET SUB (VP)")
        for idx_u, (_u, _ont_uni_if, olt_lower, vp_base) in enumerate(uni_configs):
            for rule in rules_per_uni[idx_u]:
                eff_vlan = (rule["rw_vlan"]
                            if rule["type"] == "Single Tag" and rule.get("rewrite")
                            else rule["vlan"])
                vp_if = f"{pfx}_{vp_base}_c{eff_vlan:04d}_any"
                L += [
                    f"interfaces interface {vp_if}"
                    f" type vlan-sub-interface subif-lower-layer interface {olt_lower}",
                    f"interfaces interface {vp_if} enabled",
                    f"interfaces interface {vp_if}"
                    f" inline-frame-processing ingress-rule rule rule_1 priority 100"
                    f" flexible-match match-criteria tag 0 dot1q-tag tag-type c-vlan"
                    f" vlan-id {eff_vlan} pbit any dei any",
                    f"forwarding forwarders forwarder fwd.vlan{eff_vlan}.cli.attach"
                    f" ports port fwd_{vp_if} sub-interface {vp_if}",
                    "exit",
                    "",
                ]

        # ── Section 10: TCONT / GEM / DBA ───────────────────────────────────
        L.append("!##############ONT TCONT/GEM/DBA")
        for i, tcont in enumerate(p["tconts"]):
            vlan = tcont["vlan"]
            # Find matching VP interface from uni_configs + rules by effective VLAN
            vp_if = None
            for idx_u, (_u, _ont, _lower, vp_base) in enumerate(uni_configs):
                for rule in rules_per_uni[idx_u]:
                    eff = (rule["rw_vlan"]
                           if rule["type"] == "Single Tag" and rule.get("rewrite")
                           else rule["vlan"])
                    if eff == vlan:
                        vp_if = f"{pfx}_{vp_base}_c{vlan:04d}_any"
                        break
                if vp_if:
                    break
            if vp_if is None:
                vp_if = f"{pfx}_{uni_configs[0][3]}_c{vlan:04d}_any"
            L += [
                f"xpongemtcont tconts tcont {pfx}_tcont1_{i + 1}"
                f" alloc-id {tcont['alloc_id']}"
                f" interface-reference {pfx}_vani1_1"
                f" traffic-descriptor-profile-ref {tcont['dba']}",
                f"xpongemtcont gemports gemport {pfx}_gem1_{i + 1}"
                f" interface {vp_if}"
                f" tcont-ref {pfx}_tcont1_{i + 1}"
                f" gemport-id {tcont['gem_id']}",
            ]
        L += ["commit", "exit"]

        return "\n".join(L)

    # ─── No Service (Remove) config builder ───────────────────────────────────

    def _build_remove_config(self, p):
        pon_type  = p["pon_type"]
        mode      = p["mode"]
        uni_ports = p["uni_ports"]

        if pon_type == "GPON":
            pon_if = f"gpon{p['pon_slot']}/{p['pon_port']}"
        else:
            pon_if = f"xgspon{p['pon_slot']}/{p['pon_port']}"

        onu_str = f"onu{p['onu_id']:03d}"
        pfx     = f"{pon_if}_{onu_str}"

        if mode == "PPTP":
            uni_configs = [(u, f"{pfx}_eth1_{u}", f"{pfx}_venet1_{u}", f"o_venet1_{u}")
                           for u in uni_ports]
        else:
            uni_configs = [(1, f"{pfx}_veip_1", f"{pfx}_venet1_1", "o_venet1_1")]

        rules_per_uni = p["rules_per_uni"]
        n_tcont       = len(p["tconts"])

        L = []
        if mode == "VEIP":
            L.append("!###########No Service VEIP")
        else:
            L.append("!###########No Service PPTP")
        L.append("")

        # Step 1: Remove GEM/TCONT in reverse order
        for i in range(n_tcont, 0, -1):
            L.append(f"no xpongemtcont gemports gemport {pfx}_gem1_{i}")
            L.append(f"no xpongemtcont tconts tcont {pfx}_tcont1_{i}")
        L.append("")

        if mode == "VEIP":
            # Step 2: Remove VP (OLT V-NET sub) for each rule, reverse order
            vp_list = []
            for idx_u, (_u, _ont, _lower, vp_base) in enumerate(uni_configs):
                for rule in rules_per_uni[idx_u]:
                    eff_vlan = (rule["rw_vlan"]
                                if rule["type"] == "Single Tag" and rule.get("rewrite")
                                else rule["vlan"])
                    vp_if = f"{pfx}_{vp_base}_c{eff_vlan:04d}_any"
                    vp_list.append((eff_vlan, vp_if))
            for eff_vlan, vp_if in reversed(vp_list):
                L.append(f"no forwarding forwarders forwarder fwd.vlan{eff_vlan}.cli.attach"
                         f" ports port fwd_{vp_if}")
                L.append(f"no interfaces interface {vp_if}")
            L.append("")

            # Step 3: Remove ONT Extended VLAN sub-interfaces on veip_1, reverse order
            subif_list = []
            for idx_u, (_u, ont_uni_if, *_) in enumerate(uni_configs):
                for rule in rules_per_uni[idx_u]:
                    eff_vlan = (rule["rw_vlan"]
                                if rule["type"] == "Single Tag" and rule.get("rewrite")
                                else rule["vlan"])
                    if rule["type"] == "Untag":
                        subif_list.append(f"{ont_uni_if}_c{rule['vlan']:04d}_untag")
                    else:
                        subif_list.append(f"{ont_uni_if}_c{eff_vlan:04d}_any")
            for subif in reversed(subif_list):
                L.append(f"no interfaces interface {subif}")
            L.append("")

            # Step 4: Remove VEIP, VENET, ANI, hardware
            L += [
                f"no link-table link-table {pfx}_veip_1",
                f"no interfaces interface {pfx}_veip_1",
                f"no interfaces interface {pfx}_venet1_1",
                f"no link-table link-table {pfx}_ani1_1",
                f"no interfaces interface {pfx}_vani1_1",
                f"no interfaces interface {pfx}_ani1_1",
                f"no hardware component {pfx}_aniport1_1",
                f"no hardware component {pfx}_sfp1_1",
                f"no hardware component {pfx}_cage1_1",
                f"no hardware component {pfx}_card1",
                f"no hardware component {pfx}",
                "commit",
                "exit",
            ]

        else:  # PPTP
            # Per UNI: remove VP → remove extended VLAN sub-if → remove link-table + venet
            for idx_u, (u, ont_uni_if, olt_lower, vp_base) in enumerate(uni_configs):
                rules = rules_per_uni[idx_u]

                vp_list = []
                for rule in rules:
                    eff_vlan = (rule["rw_vlan"]
                                if rule["type"] == "Single Tag" and rule.get("rewrite")
                                else rule["vlan"])
                    vp_if = f"{pfx}_{vp_base}_c{eff_vlan:04d}_any"
                    vp_list.append((eff_vlan, vp_if))
                for eff_vlan, vp_if in reversed(vp_list):
                    L.append(f"no forwarding forwarders forwarder fwd.vlan{eff_vlan}.cli.attach"
                             f" ports port fwd_{vp_if}")
                    L.append(f"no interfaces interface {vp_if}")

                for rule in reversed(rules):
                    eff_vlan = (rule["rw_vlan"]
                                if rule["type"] == "Single Tag" and rule.get("rewrite")
                                else rule["vlan"])
                    if rule["type"] == "Untag":
                        L.append(f"no interfaces interface {ont_uni_if}_c{rule['vlan']:04d}_untag")
                    else:
                        L.append(f"no interfaces interface {ont_uni_if}_c{eff_vlan:04d}_any")

                L.append(f"no link-table link-table {ont_uni_if}")
                L.append(f"no interfaces interface {olt_lower}")
            L.append("")

            L += [
                f"no link-table link-table {pfx}_ani1_1",
                f"no interfaces interface {pfx}_vani1_1",
                f"no interfaces interface {pfx}_ani1_1",
                "",
            ]

            for (u, ont_uni_if, *_) in reversed(uni_configs):
                L.append(f"no interfaces interface {ont_uni_if}")
                L.append(f"no link-table link-table {ont_uni_if} to-interface")
                L.append(f"no hardware component {pfx}_uniport1_{u}")
                L.append(f"no hardware component ontUni_{pfx}_{u}")
            L.append("")

            L += [
                f"no hardware component {pfx}_aniport1_1",
                f"no hardware component {pfx}_sfp1_1",
                f"no hardware component {pfx}_cage1_1",
                f"no hardware component {pfx}_card1",
                f"no hardware component {pfx}",
                "commit",
                "exit",
            ]

        return "\n".join(L)

    # ─── Preview with basic highlighting ──────────────────────────────────────

    def _show_preview(self, text):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", text)

        for i, line in enumerate(text.splitlines(), start=1):
            start = f"{i}.0"
            end   = f"{i}.end"
            if line.startswith("!"):
                self.preview.tag_add("section", start, end)
            elif line.strip() in ("exit", "commit"):
                self.preview.tag_add("keyword", start, end)

        self.preview.configure(state="disabled")

    def _show_remove_preview(self, text):
        self.remove_preview.configure(state="normal")
        self.remove_preview.delete("1.0", tk.END)
        self.remove_preview.insert("1.0", text)

        for i, line in enumerate(text.splitlines(), start=1):
            start = f"{i}.0"
            end   = f"{i}.end"
            if line.startswith("!"):
                self.remove_preview.tag_add("section", start, end)
            elif line.startswith("no "):
                self.remove_preview.tag_add("no_cmd", start, end)

        self.remove_preview.configure(state="disabled")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    GPONConfigGenerator(root)
    root.mainloop()
