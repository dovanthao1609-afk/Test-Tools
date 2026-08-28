#!/usr/bin/env python3
"""NETCONF RPC Sender — native Tkinter tab.

A self-contained port of the NETCONF_RPC_Sender.html web tool into a Tkinter
widget so it can live as a tab inside DHCP_PPPoE_Client_Emulator_Final.py.
Connects to an OLT over NETCONF/SSH (ncclient) and dispatches RPC messages —
multiple RPCs separated by a line containing only ``---`` are sent over one
session. Also fetches server capabilities.

The UI is built from ttk widgets so it inherits the host application's active
theme (matching the DHCP / PPPoE / GPON tabs). All custom ttk styles it defines
are namespaced with an ``Rpc`` prefix so they never collide with other tabs.

Can also run standalone:  python NETCONF_RPC_Sender_Tab.py
"""
import re
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ── ncclient / lxml import (optional) with paramiko kex workaround ────────────
try:
    from ncclient import manager
    from ncclient.xml_ import to_ele
    from lxml import etree
    import paramiko

    # Restrict kex to DH-only algorithms to avoid KeyError on old paramiko builds
    # where _preferred_kex lists ecdh-sha2-* but _kex_info has no implementation.
    try:
        import paramiko.transport as _pmt
        _kex_impl = {}
        for _src in (paramiko.Transport, _pmt):
            _d = getattr(_src, '_kex_info', {})
            if isinstance(_d, dict):
                _kex_impl.update(_d)
        _want = [
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group14-sha256',
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1',
        ]
        _safe = [a for a in _want if a in _kex_impl]
        if _safe:
            paramiko.Transport._preferred_kex = tuple(_safe)
    except Exception:
        pass

    _HAS_NCCLIENT = True
    _MISSING = None
except ImportError as _imp_err:
    _HAS_NCCLIENT = False
    _MISSING = str(_imp_err)


# ── Default connection ────────────────────────────────────────────────────────
DEFAULT_HOST = "192.168.100.249"
DEFAULT_PORT = "830"
DEFAULT_USER = "admin"
DEFAULT_PASS = "Zhone1234%^&*"
DEFAULT_TIMEOUT = "30"

# ── RPC templates (ported from NETCONF_RPC_Sender.html) ───────────────────────
TEMPLATES = {
    "FW Download (bbf-software-management)": """<action xmlns="urn:ietf:params:xml:ns:yang:1">
  <hardware xmlns="urn:ietf:params:xml:ns:yang:ietf-hardware">
    <component>
      <name>gpon0/3_onu007_card1</name>
      <software xmlns="urn:bbf:yang:bbf-software-management">
        <software>
          <name>image</name>
          <revisions>
            <download>
              <download>
                <source>
                  <url>ftp://admin:123456@192.168.100.104:21/ZNID/hx2428xxsip_0700105.img</url>
                </source>
                <target>
                  <selected-by-system>
                    <operation>create-or-replace</operation>
                  </selected-by-system>
                </target>
              </download>
            </download>
          </revisions>
        </software>
      </software>
    </component>
  </hardware>
</action>""",

    "get-config — hardware": """<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <source>
    <running/>
  </source>
  <filter type="subtree">
    <hardware xmlns="urn:ietf:params:xml:ns:yang:ietf-hardware"/>
  </filter>
</get-config>""",

    "get-config — running (full)": """<get-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <source>
    <running/>
  </source>
</get-config>""",

    "get — ONU list": """<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <filter type="subtree">
    <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
      <interface/>
    </interfaces>
  </filter>
</get>""",

    "edit-config example": """<edit-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <target>
    <candidate/>
  </target>
  <test-option>test-then-set</test-option>
  <error-option>rollback-on-error</error-option>
  <config>
    <!-- Add your config here -->
  </config>
</edit-config>""",
}

COMMIT_RPC = '<commit xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>'
_WRITE_OP_RE = re.compile(r'<\s*(?:[\w.\-]+:)?(edit-config|copy-config|delete-config)[\s>/]', re.I)
_COMMIT_RE   = re.compile(r'<\s*(?:[\w.\-]+:)?commit[\s>/]', re.I)


# ── RPC text helpers ──────────────────────────────────────────────────────────
def _strip_rpc_envelope(block):
    """Users sometimes paste a full <rpc ...>…</rpc> envelope; ncclient adds its
    own, which would double-wrap. Strip the outer <rpc> and any <?xml?> line."""
    s = block.strip()
    s = re.sub(r'^<\?xml[^>]*\?>\s*', '', s, flags=re.I)
    m = re.match(r'^<rpc(?:\s[^>]*)?>([\s\S]*)</rpc>\s*$', s, flags=re.I)
    if m:
        s = m.group(1).strip()
    return s


def _normalize_rpc(xml):
    blocks = [_strip_rpc_envelope(b) for b in xml.split('---')]
    return '\n---\n'.join(b for b in blocks if b)


def _needs_commit(xml):
    return bool(_WRITE_OP_RE.search(xml)) and not _COMMIT_RE.search(xml)


def pretty_xml(xml):
    """Lightweight re-indent identical in spirit to the HTML prettyXml()."""
    out, indent = [], 0
    text = re.sub(r'>\s*<', '>\n<', xml.strip())
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        if re.match(r'^</\w', line):
            indent = max(0, indent - 1)
        out.append('  ' * indent + line)
        if re.match(r'^<\w[^>]*[^/]>$', line) and not re.match(r'^<[?!]', line):
            indent += 1
    return '\n'.join(out).strip()


# ── NETCONF operations (blocking — call from a worker thread) ─────────────────
def _connect(host, port, username, password, timeout):
    return manager.connect(
        host=host, port=int(port),
        username=username, password=password,
        hostkey_verify=False, timeout=int(timeout),
        look_for_keys=False, allow_agent=False,
    )


def _parse_result(result_xml):
    root = etree.fromstring(result_xml.encode('utf-8'))
    pretty = etree.tostring(root, pretty_print=True).decode('utf-8')
    ns = 'urn:ietf:params:xml:ns:netconf:base:1.0'
    errors = root.findall('.//{%s}rpc-error' % ns)
    if errors:
        err_msgs = []
        for e in errors:
            err_msgs.append({
                'tag':     (e.findtext('{%s}error-tag' % ns) or '').strip(),
                'message': (e.findtext('{%s}error-message' % ns) or '').strip(),
                'path':    (e.findtext('{%s}error-path' % ns) or '').strip(),
            })
        return {'rpc_ok': False, 'rpc_errors': err_msgs, 'result': pretty}
    return {'rpc_ok': True, 'rpc_errors': [], 'result': pretty}


def netconf_send(host, port, username, password, timeout, rpc_xml):
    """Dispatch one or more (---separated) RPCs over a single session.
    Returns {'success': bool, 'results': [...]} or {'success': False, 'error': str}."""
    if not _HAS_NCCLIENT:
        return {'success': False,
                'error': f'Required packages not installed: {_MISSING}\n'
                         f'Run: pip install ncclient lxml'}
    blocks = [b.strip() for b in rpc_xml.split('---') if b.strip()]
    if not blocks:
        return {'success': False, 'error': 'rpc_xml is required'}

    elems = []
    for i, block in enumerate(blocks):
        try:
            elems.append(to_ele(block))
        except Exception as e:
            return {'success': False, 'error': f'RPC #{i+1} invalid XML: {e}'}

    try:
        conn = _connect(host, port, username, password, timeout)
    except Exception as e:
        return {'success': False, 'error': str(e)}

    try:
        results = []
        for i, elem in enumerate(elems):
            try:
                r = conn.dispatch(elem)
                parsed = _parse_result(r.xml)
            except Exception as e:
                parsed = {'rpc_ok': False, 'rpc_errors': [], 'error': str(e), 'result': ''}
            parsed['index'] = i + 1
            results.append(parsed)
    finally:
        try:
            conn.close_session()
        except Exception:
            pass
    return {'success': True, 'results': results}


def netconf_capabilities(host, port, username, password, timeout):
    if not _HAS_NCCLIENT:
        return {'success': False, 'error': f'ncclient not installed: {_MISSING}'}
    try:
        conn = _connect(host, port, username, password, timeout)
        caps = list(conn.server_capabilities)
        try:
            conn.close_session()
        except Exception:
            pass
        return {'success': True, 'capabilities': caps}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ── The Tkinter tab ───────────────────────────────────────────────────────────
class NETCONFRPCSender:
    # XML highlight colors (tuned for a light editor surface)
    C_TAG  = "#0550ae"
    C_ATTR = "#953800"
    C_VAL  = "#116329"
    C_COMM = "#6e7781"
    C_OK   = "#1a7a3c"
    C_ERR  = "#c0392b"

    HIST_MAX = 30

    def __init__(self, root):
        self.root = root
        if isinstance(root, (tk.Tk, tk.Toplevel)):
            self.root.title("NETCONF RPC Sender")
            self.root.geometry("1150x700")
            self.root.minsize(820, 520)

        self._history = []           # list of dicts: time/host/port/req/resp/ok/elapsed
        self._commit_idx = 0
        self._busy = False
        self._last_caps = []

        self.T = self._load_theme()
        self._init_styles()
        self._build_ui()

        if not _HAS_NCCLIENT:
            self._warn.configure(
                text=f"⚠ Thiếu thư viện backend: {_MISSING}  —  chạy: pip install ncclient lxml")
            self._warn.pack(fill="x", padx=6, pady=(6, 0), before=self._pane)
            self._btn_send.configure(state="disabled")
            self._btn_caps.configure(state="disabled")
            self._set_status("Backend chưa sẵn sàng — thiếu ncclient/lxml", "warn")

    # ─── Theme / styles ────────────────────────────────────────────────────────
    def _load_theme(self):
        """Read the host app's active ttk colors so tk-only widgets match it.
        Falls back to the app palette when run standalone."""
        st = ttk.Style()

        def lk(style, opt, fb):
            try:
                v = st.lookup(style, opt)
            except Exception:
                v = None
            return v or fb

        return dict(
            bg    = lk("TFrame", "background", "#f4f7fb"),
            surf  = lk("Treeview", "background", "#ffffff"),
            input = lk("TEntry", "fieldbackground", "#ffffff"),
            fg    = lk("TLabel", "foreground", "#1a2d44"),
            acc   = lk("Treeview.Heading", "foreground", "#1a6fc4"),
            dim   = "#8fa3b8",
        )

    def _init_styles(self):
        """Namespaced (Rpc*) styles — never collide with other tabs' styles."""
        st = ttk.Style()
        _btn = dict(font=("Segoe UI", 9, "bold"), foreground="white",
                    padding=(10, 5), relief="flat")
        st.configure("RpcSend.TButton", background="#1a7a3c",
                     bordercolor="#1a7a3c", darkcolor="#1a7a3c",
                     lightcolor="#1a7a3c", **_btn)
        st.map("RpcSend.TButton",
               background=[("active", "#218a45"), ("pressed", "#136030")])
        st.configure("RpcCaps.TButton", background="#5e35b1",
                     bordercolor="#5e35b1", darkcolor="#5e35b1",
                     lightcolor="#5e35b1", **_btn)
        st.map("RpcCaps.TButton",
               background=[("active", "#6d44c0"), ("pressed", "#4527a0")])
        st.configure("RpcWarn.TLabel", background="#fff9c3", foreground="#8a6a00",
                     font=("Segoe UI", 9), padding=(10, 4))
        st.configure("RpcHint.TLabel", foreground=self.T["dim"],
                     font=("Segoe UI", 8))
        st.configure("RpcStatus.TLabel", foreground=self.T["dim"],
                     font=("Segoe UI", 9))

    # ─── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._warn = ttk.Label(self.root, text="", style="RpcWarn.TLabel",
                               anchor="w", justify="left")

        self._pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self._pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        left = ttk.Frame(self._pane)
        right = ttk.Frame(self._pane)
        self._pane.add(left, weight=2)
        self._pane.add(right, weight=3)

        self._build_left(left)
        self._build_right(right)

    # -- left panel --
    def _build_left(self, parent):
        # Connection
        conn = ttk.LabelFrame(parent, text="SSH / NETCONF Connection")
        conn.pack(fill="x", padx=2, pady=(2, 6))
        conn.columnconfigure(1, weight=1)

        self.v_host = tk.StringVar(value=DEFAULT_HOST)
        self.v_port = tk.StringVar(value=DEFAULT_PORT)
        self.v_user = tk.StringVar(value=DEFAULT_USER)
        self.v_pass = tk.StringVar(value=DEFAULT_PASS)
        self.v_timeout = tk.StringVar(value=DEFAULT_TIMEOUT)

        self._field(conn, "Host (OLT IP):", self.v_host, 0)
        self._field(conn, "Port:", self.v_port, 1, width=8)
        self._field(conn, "Username:", self.v_user, 2)

        ttk.Label(conn, text="Password:").grid(row=3, column=0, sticky="w",
                                               padx=(0, 8), pady=3)
        pw = ttk.Frame(conn)
        pw.grid(row=3, column=1, sticky="ew", pady=3)
        self._pass_entry = ttk.Entry(pw, textvariable=self.v_pass, show="•",
                                     font=("Consolas", 9))
        self._pass_entry.pack(side="left", fill="x", expand=True)
        self._pass_shown = False
        ttk.Button(pw, text="👁", width=3, command=self._toggle_pass).pack(
            side="left", padx=(4, 0))

        self._field(conn, "Timeout (s):", self.v_timeout, 4, width=8)

        # RPC message
        rpc = ttk.LabelFrame(parent, text="RPC Message")
        rpc.pack(fill="both", expand=True, padx=2, pady=(0, 6))

        tpl_row = ttk.Frame(rpc)
        tpl_row.pack(fill="x", pady=(2, 0))
        ttk.Label(tpl_row, text="Template:").pack(side="left")
        self.v_tpl = tk.StringVar(value="")
        self._tpl_cb = ttk.Combobox(tpl_row, textvariable=self.v_tpl, state="readonly",
                                    values=["— Select template —"] + list(TEMPLATES.keys()))
        self._tpl_cb.current(0)
        self._tpl_cb.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self._tpl_cb.bind("<<ComboboxSelected>>", self._on_template)

        self.v_autocommit = tk.BooleanVar(value=True)
        ttk.Checkbutton(rpc, text="Auto-append <commit/> sau write RPC "
                                  "(edit / copy / delete-config)",
                        variable=self.v_autocommit).pack(fill="x", pady=(4, 0))
        ttk.Label(rpc, text="Tip: nhiều RPC trong 1 session → ngăn mỗi khối bằng "
                            "dòng chỉ chứa  ---", style="RpcHint.TLabel",
                  anchor="w").pack(fill="x", pady=(0, 4))

        editor = ttk.Frame(rpc)
        editor.pack(fill="both", expand=True)
        self.txt_rpc = tk.Text(editor, font=("Consolas", 10), wrap="none",
                               relief="solid", bd=1, undo=True,
                               bg=self.T["surf"], fg=self.T["fg"],
                               insertbackground=self.T["fg"],
                               selectbackground=self.T["acc"],
                               selectforeground="#ffffff",
                               highlightthickness=1,
                               highlightbackground=self.T["dim"],
                               highlightcolor=self.T["acc"])
        ysb = ttk.Scrollbar(editor, orient="vertical", command=self.txt_rpc.yview)
        self.txt_rpc.configure(yscrollcommand=ysb.set)
        ysb.pack(side="right", fill="y")
        self.txt_rpc.pack(side="left", fill="both", expand=True)
        self.txt_rpc.insert("1.0", TEMPLATES["FW Download (bbf-software-management)"])

        # Buttons
        btns = ttk.Frame(parent)
        btns.pack(fill="x", padx=2, pady=(0, 4))
        row1 = ttk.Frame(btns); row1.pack(fill="x", pady=(0, 4))
        self._btn_send = ttk.Button(row1, text="▶  Send RPC", style="RpcSend.TButton",
                                    command=self._send)
        self._btn_send.pack(side="left", fill="x", expand=True, padx=(0, 2))
        self._btn_caps = ttk.Button(row1, text="ⓘ  Capabilities", style="RpcCaps.TButton",
                                    command=self._get_caps)
        self._btn_caps.pack(side="left", fill="x", expand=True, padx=(2, 0))

        row2 = ttk.Frame(btns); row2.pack(fill="x")
        for txt, cmd in (("⭷ Format XML", self._format),
                         ("⎘ Copy RPC", self._copy_rpc),
                         ("✕ Clear", self._clear_rpc)):
            ttk.Button(row2, text=txt, command=cmd).pack(
                side="left", fill="x", expand=True, padx=1)

        # Status bar
        status = ttk.Frame(parent)
        status.pack(fill="x", padx=2, pady=(2, 2))
        self._dot = ttk.Label(status, text="●", foreground=self.T["dim"],
                              font=("Segoe UI", 10))
        self._dot.pack(side="left", padx=(2, 6))
        self._status = ttk.Label(status, text="Ready", style="RpcStatus.TLabel",
                                 anchor="w")
        self._status.pack(side="left", fill="x", expand=True)

    # -- right panel (nested notebook: Response / History / Capabilities) --
    def _build_right(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        self._right_nb = nb

        # Response
        resp = ttk.Frame(nb)
        nb.add(resp, text="  Response  ")
        bar = ttk.Frame(resp)
        bar.pack(fill="x", pady=(2, 2))
        self._resp_lbl = ttk.Label(bar, text="No response yet",
                                   font=("Segoe UI", 9, "bold"), anchor="w")
        self._resp_lbl.pack(side="left", fill="x", expand=True, padx=6)
        self._resp_elapsed = ttk.Label(bar, text="", style="RpcHint.TLabel")
        self._resp_elapsed.pack(side="left", padx=6)
        ttk.Button(bar, text="Copy", command=self._copy_resp, width=6).pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self._clear_resp, width=6).pack(side="left", padx=(2, 6))
        self.txt_resp = self._make_readonly_text(resp)

        # History
        hist = ttk.Frame(nb)
        nb.add(hist, text="  History  ")
        htop = ttk.Frame(hist); htop.pack(fill="x", pady=(2, 2))
        ttk.Button(htop, text="Load RPC → editor", command=self._load_from_hist).pack(
            side="left", padx=(6, 2))
        ttk.Button(htop, text="Clear History", command=self._clear_history).pack(side="left")
        cols = ("time", "host", "status", "elapsed")
        self.tree_hist = ttk.Treeview(hist, columns=cols, show="headings", height=8)
        for c, w, txt in (("time", 90, "Time"), ("host", 160, "Host:Port"),
                          ("status", 70, "Status"), ("elapsed", 70, "Elapsed")):
            self.tree_hist.heading(c, text=txt)
            self.tree_hist.column(c, width=w, anchor="w")
        self.tree_hist.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.tree_hist.bind("<<TreeviewSelect>>", self._on_hist_select)

        # Capabilities
        caps = ttk.Frame(nb)
        nb.add(caps, text="  Capabilities  ")
        ctop = ttk.Frame(caps); ctop.pack(fill="x", pady=(2, 2))
        self._caps_lbl = ttk.Label(ctop, text="Not fetched", anchor="w")
        self._caps_lbl.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(ctop, text="Copy All", command=self._copy_caps).pack(side="left", padx=6)
        cf = ttk.Frame(caps); cf.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.lst_caps = tk.Listbox(cf, font=("Consolas", 9), fg=self.T["acc"],
                                   bg=self.T["surf"], activestyle="none",
                                   relief="solid", bd=1,
                                   highlightthickness=0,
                                   selectbackground=self.T["acc"],
                                   selectforeground="#ffffff")
        csb = ttk.Scrollbar(cf, orient="vertical", command=self.lst_caps.yview)
        self.lst_caps.configure(yscrollcommand=csb.set)
        csb.pack(side="right", fill="y")
        self.lst_caps.pack(side="left", fill="both", expand=True)

    def _make_readonly_text(self, parent):
        f = ttk.Frame(parent)
        f.pack(fill="both", expand=True, padx=2, pady=(0, 2))
        t = tk.Text(f, font=("Consolas", 10), wrap="word", relief="solid", bd=1,
                    bg=self.T["surf"], fg=self.T["fg"], state="disabled",
                    padx=10, pady=8, highlightthickness=0,
                    selectbackground=self.T["acc"], selectforeground="#ffffff")
        sb = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        # highlight tags
        t.tag_configure("xt", foreground=self.C_TAG)
        t.tag_configure("xa", foreground=self.C_ATTR)
        t.tag_configure("xv", foreground=self.C_VAL)
        t.tag_configure("xc", foreground=self.C_COMM)
        t.tag_configure("xs", foreground=self.T["fg"])
        t.tag_configure("ok", foreground=self.C_OK, font=("Segoe UI", 9, "bold"))
        t.tag_configure("err", foreground=self.C_ERR, font=("Segoe UI", 9, "bold"))
        t.tag_configure("errtxt", foreground="#991b1b")
        t.tag_configure("dim", foreground=self.T["dim"])
        return t

    def _field(self, parent, label, var, row, width=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w",
                                           padx=(0, 8), pady=3)
        e = ttk.Entry(parent, textvariable=var, font=("Consolas", 9),
                      width=width or 0)
        e.grid(row=row, column=1, sticky="w" if width else "ew", pady=3)
        return e

    # ─── XML highlighting into a Text widget ───────────────────────────────────
    def _insert_xml(self, widget, xml):
        pattern = re.compile(r'<!--.*?-->|<[^>]+>', re.DOTALL)
        idx = 0
        for m in pattern.finditer(xml):
            if m.start() > idx:
                widget.insert("end", xml[idx:m.start()], "xs")
            token = m.group()
            if token.startswith('<!--'):
                widget.insert("end", token, "xc")
            elif token.startswith('<?'):
                widget.insert("end", token, "xt")
            else:
                self._insert_tag(widget, token)
            idx = m.end()
        if idx < len(xml):
            widget.insert("end", xml[idx:], "xs")

    def _insert_tag(self, widget, token):
        inner = token[1:-1]                       # strip < >
        trailing = ""
        if inner.endswith('/'):
            inner, trailing = inner[:-1], '/'
        m = re.match(r'(/?)([\w:.\-]+)([\s\S]*)', inner)
        widget.insert("end", "<", "xt")
        if not m:
            widget.insert("end", inner + trailing + ">", "xt")
            return
        slash, name, rest = m.groups()
        widget.insert("end", slash + name, "xt")
        apos = 0
        for am in re.finditer(r'([\w:.\-]+)(=)("[^"]*"|\'[^\']*\')', rest):
            if am.start() > apos:
                widget.insert("end", rest[apos:am.start()], "xt")
            aname, eq, aval = am.groups()
            widget.insert("end", aname, "xa")
            widget.insert("end", eq, "xt")
            widget.insert("end", aval, "xv")
            apos = am.end()
        if apos < len(rest):
            widget.insert("end", rest[apos:], "xt")
        widget.insert("end", trailing + ">", "xt")

    # ─── Actions ───────────────────────────────────────────────────────────────
    def _on_template(self, _evt=None):
        name = self.v_tpl.get()
        if name in TEMPLATES:
            self.txt_rpc.delete("1.0", "end")
            self.txt_rpc.insert("1.0", TEMPLATES[name])
        self.root.after(10, lambda: self._tpl_cb.current(0))

    def _toggle_pass(self):
        self._pass_shown = not self._pass_shown
        self._pass_entry.configure(show="" if self._pass_shown else "•")

    def _clear_rpc(self):
        self.txt_rpc.delete("1.0", "end")

    def _copy_rpc(self):
        self._to_clipboard(self.txt_rpc.get("1.0", "end-1c"))
        self._set_status("RPC copied to clipboard", "ok")

    def _format(self):
        raw = self.txt_rpc.get("1.0", "end-1c").strip()
        if not raw:
            return
        try:
            formatted = '\n---\n'.join(pretty_xml(b) for b in raw.split('---') if b.strip())
            self.txt_rpc.delete("1.0", "end")
            self.txt_rpc.insert("1.0", formatted)
        except Exception as e:
            messagebox.showerror("Format XML", f"Invalid XML: {e}")

    def _to_clipboard(self, text):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except Exception:
            pass

    def _params(self):
        return dict(host=self.v_host.get().strip(),
                    port=self.v_port.get().strip() or "830",
                    username=self.v_user.get().strip(),
                    password=self.v_pass.get(),
                    timeout=self.v_timeout.get().strip() or "30")

    def _set_status(self, msg, state=""):
        colors = {"": self.T["dim"], "sending": "#1a7a3c", "ok": self.T["acc"],
                  "error": "#c0392b", "warn": "#c05a00"}
        self._status.configure(text=msg or "Ready")
        self._dot.configure(foreground=colors.get(state, self.T["dim"]))

    def _set_busy(self, busy):
        self._busy = busy
        st = "disabled" if busy else "normal"
        if _HAS_NCCLIENT:
            self._btn_send.configure(state=st)
            self._btn_caps.configure(state=st)

    # -- Send --
    def _send(self):
        if self._busy:
            return
        p = self._params()
        raw = self.txt_rpc.get("1.0", "end-1c").strip()
        if not p["host"]:
            messagebox.showwarning("RPC Sender", "Nhập Host/IP của OLT.")
            return
        if not raw:
            messagebox.showwarning("RPC Sender", "Nhập RPC XML.")
            return

        rpc_xml = _normalize_rpc(raw)          # strip any pasted <rpc> envelope
        self._commit_idx = 0
        if self.v_autocommit.get() and _needs_commit(rpc_xml):
            rpc_xml = f"{rpc_xml}\n---\n{COMMIT_RPC}"
            self._commit_idx = len([b for b in rpc_xml.split('---') if b.strip()])

        self._set_busy(True)
        self._set_status(f"Connecting to {p['host']}:{p['port']}...", "sending")
        ts = time.strftime("%H:%M:%S")
        t0 = time.time()

        def work():
            data = netconf_send(p["host"], p["port"], p["username"],
                                p["password"], p["timeout"], rpc_xml)
            elapsed = f"{time.time() - t0:.2f}"
            self.root.after(0, lambda: self._on_send_done(data, elapsed, ts, p, rpc_xml))

        threading.Thread(target=work, daemon=True).start()

    def _on_send_done(self, data, elapsed, ts, p, rpc_xml):
        self._set_busy(False)
        if not data.get("success"):
            err = data.get("error", "Unknown error")
            self._set_status(f"Connection error: {err.splitlines()[0]}", "error")
            self._show_conn_error(err, elapsed)
            self._add_history(ts, p["host"], p["port"], rpc_xml, err, False, elapsed)
            return

        results = data["results"]
        total = len(results)
        ok = sum(1 for r in results if r.get("rpc_ok"))
        all_ok = ok == total

        # status line
        if total > 1:
            n_user = total - 1 if self._commit_idx else total
            if all_ok:
                self._set_status(
                    (f"{n_user} RPC accepted và committed — {elapsed}s"
                     if self._commit_idx else f"All {total} RPCs accepted — {elapsed}s"), "ok")
            else:
                commit_failed = self._commit_idx and not next(
                    (r for r in results if r.get("index") == self._commit_idx and r.get("rpc_ok")), None)
                self._set_status(
                    f"{ok}/{total} RPCs accepted"
                    + (" — COMMIT FAILED, changes not saved" if commit_failed else "")
                    + f" — {elapsed}s", "error")
        else:
            r = results[0]
            if r.get("rpc_ok"):
                self._set_status(f"Device accepted — {elapsed}s", "ok")
            elif r.get("error"):
                self._set_status(f"Connection error: {r['error'].splitlines()[0]}", "error")
            else:
                summ = " | ".join(f"[{e.get('tag')}] {e.get('message')}"
                                  for e in r.get("rpc_errors", [])) or "rpc-error"
                self._set_status(f"Device rejected RPC: {summ}", "error")

        self._render_results(results, elapsed, all_ok, total, ok)
        joined = "\n---\n".join(r.get("result") or r.get("error") or "" for r in results)
        self._add_history(ts, p["host"], p["port"], rpc_xml, joined, all_ok, elapsed)
        self._right_nb.select(0)

    def _render_results(self, results, elapsed, all_ok, total, ok):
        t = self.txt_resp
        t.configure(state="normal")
        t.delete("1.0", "end")

        if total > 1:
            tag = "ok" if all_ok else "err"
            t.insert("end", f"{ok}/{total} RPCs accepted", tag)
            t.insert("end", f"   ·   {elapsed}s\n\n", "dim")

        for r in results:
            if total > 1:
                icon = "✓" if r.get("rpc_ok") else "✗"
                label = "commit (auto)" if r.get("index") == self._commit_idx else f"RPC #{r.get('index')}"
                t.insert("end", f"{icon} {label}\n", "ok" if r.get("rpc_ok") else "err")

            if r.get("error"):
                t.insert("end", r["error"] + "\n", "errtxt")
            elif not r.get("rpc_ok") and r.get("rpc_errors"):
                t.insert("end", "⚠ Device returned rpc-error\n", "err")
                for e in r["rpc_errors"]:
                    line = f"  [{e.get('tag') or 'error'}] {e.get('message') or ''}"
                    if e.get("path"):
                        line += f"  @ {e.get('path')}"
                    t.insert("end", line + "\n", "errtxt")
                if r.get("result"):
                    self._insert_xml(t, r["result"])
            else:
                if r.get("result"):
                    self._insert_xml(t, r["result"])
            t.insert("end", "\n")

        t.configure(state="disabled")
        if total > 1:
            self._resp_lbl.configure(
                text=("✓ All %d RPCs accepted" % total) if all_ok
                else ("⚠ %d/%d RPCs accepted" % (ok, total)))
        else:
            self._resp_lbl.configure(
                text="✓ Device accepted (OK)" if results[0].get("rpc_ok")
                else "⚠ Device rejected (rpc-error)")
        self._resp_elapsed.configure(text=f"{elapsed}s")

    def _show_conn_error(self, text, elapsed):
        t = self.txt_resp
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", text, "errtxt")
        t.configure(state="disabled")
        self._resp_lbl.configure(text="✗ Connection error")
        self._resp_elapsed.configure(text=f"{elapsed}s")
        self._right_nb.select(0)

    def _copy_resp(self):
        self._to_clipboard(self.txt_resp.get("1.0", "end-1c"))
        self._set_status("Response copied", "ok")

    def _clear_resp(self):
        t = self.txt_resp
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.configure(state="disabled")
        self._resp_lbl.configure(text="No response yet")
        self._resp_elapsed.configure(text="")
        self._set_status("", "")

    # -- Capabilities --
    def _get_caps(self):
        if self._busy:
            return
        p = self._params()
        if not p["host"]:
            messagebox.showwarning("RPC Sender", "Nhập Host/IP của OLT.")
            return
        self._set_busy(True)
        self._set_status(f"Fetching capabilities from {p['host']}:{p['port']}...", "sending")
        t0 = time.time()

        def work():
            data = netconf_capabilities(p["host"], p["port"], p["username"],
                                        p["password"], p["timeout"])
            elapsed = f"{time.time() - t0:.2f}"
            self.root.after(0, lambda: self._on_caps_done(data, elapsed, p))

        threading.Thread(target=work, daemon=True).start()

    def _on_caps_done(self, data, elapsed, p):
        self._set_busy(False)
        if not data.get("success"):
            self._set_status(f"Error: {data.get('error','').splitlines()[0]}", "error")
            return
        caps = sorted(data["capabilities"])
        self._last_caps = caps
        self.lst_caps.delete(0, "end")
        for c in caps:
            self.lst_caps.insert("end", c)
        self._caps_lbl.configure(text=f"{len(caps)} capabilities from {p['host']}")
        self._set_status(f"{len(caps)} capabilities — {elapsed}s", "ok")
        self._right_nb.select(2)

    def _copy_caps(self):
        if self._last_caps:
            self._to_clipboard("\n".join(self._last_caps))
            self._set_status("Capabilities copied", "ok")

    # -- History --
    def _add_history(self, ts, host, port, req, resp, ok, elapsed):
        self._history.insert(0, dict(time=ts, host=host, port=port, req=req,
                                     resp=resp, ok=ok, elapsed=elapsed))
        if len(self._history) > self.HIST_MAX:
            self._history.pop()
        self._refresh_history()

    def _refresh_history(self):
        self.tree_hist.delete(*self.tree_hist.get_children())
        for i, h in enumerate(self._history):
            self.tree_hist.insert("", "end", iid=str(i),
                                  values=(h["time"], f"{h['host']}:{h['port']}",
                                          "OK" if h["ok"] else "Error", f"{h['elapsed']}s"))

    def _selected_hist(self):
        sel = self.tree_hist.selection()
        if not sel:
            return None
        try:
            return self._history[int(sel[0])]
        except (ValueError, IndexError):
            return None

    def _on_hist_select(self, _evt=None):
        h = self._selected_hist()
        if not h:
            return
        t = self.txt_resp
        t.configure(state="normal")
        t.delete("1.0", "end")
        self._insert_xml(t, h["resp"])
        t.configure(state="disabled")
        self._resp_lbl.configure(
            text=f"History · {h['host']}:{h['port']} · "
                 + ("OK" if h["ok"] else "Error"))
        self._resp_elapsed.configure(text=f"{h['elapsed']}s")

    def _load_from_hist(self):
        h = self._selected_hist()
        if not h:
            messagebox.showinfo("History", "Chọn một mục trong History trước.")
            return
        self.txt_rpc.delete("1.0", "end")
        self.txt_rpc.insert("1.0", h["req"])
        self._set_status("RPC loaded from history", "ok")

    def _clear_history(self):
        self._history.clear()
        self._refresh_history()


if __name__ == "__main__":
    root = tk.Tk()
    NETCONFRPCSender(root)
    root.mainloop()
