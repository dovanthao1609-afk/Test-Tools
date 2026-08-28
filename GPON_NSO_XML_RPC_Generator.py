import re
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ─── XML namespaces (from BBF / IETF YANG modules used by the NSO XML RPC) ────
NS_NETCONF      = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_HW           = "urn:ietf:params:xml:ns:yang:ietf-hardware"
NS_BBFHW        = "urn:bbf:yang:bbf-hardware"
NS_HWT          = "urn:bbf:yang:bbf-hardware-types"
NS_IANAHW       = "urn:ietf:params:xml:ns:yang:iana-hardware"
NS_FWD          = "urn:bbf:yang:bbf-l2-forwarding"
NS_LINKTABLE    = "urn:bbf:yang:bbf-link-table"
NS_IF           = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
NS_XPONIFT      = "urn:bbf:yang:bbf-xpon-if-type"
NS_XPON         = "urn:bbf:yang:bbf-xpon"
NS_QOSTM        = "urn:bbf:yang:bbf-qos-traffic-mngt"
NS_QOSSCHED     = "urn:bbf:yang:bbf-qos-enhanced-scheduling"
NS_XPONTYPES    = "urn:bbf:yang:bbf-xpon-types"
NS_XPONANI      = "urn:bbf:yang:bbf-xponani"
NS_IANAIFT      = "urn:ietf:params:xml:ns:yang:iana-if-type"
NS_BBFIFT       = "urn:bbf:yang:bbf-if-type"
NS_SUBIF        = "urn:bbf:yang:bbf-sub-interfaces"
NS_SUBIFTAG     = "urn:bbf:yang:bbf-sub-interface-tagging"
NS_DOT1QT       = "urn:bbf:yang:bbf-dot1q-types"
NS_XPONVANI     = "urn:bbf:yang:bbf-xponvani"
NS_XPONGEMTCONT = "urn:bbf:yang:bbf-xpongemtcont"
NS_L2DHCPV4     = "urn:bbf:yang:bbf-l2-dhcpv4-relay"
NS_LDRA         = "urn:bbf:yang:bbf-ldra"
NS_PPPOE        = "urn:bbf:yang:bbf-pppoe-intermediate-agent"


# ─── DHCP relay / PPPoE-IA defaults (fixed — profile / syntax / suboptions hidden) ─
DHCP_V4_PROFILE          = "DHCP_V4_PROFILE"
DHCP_V6_PROFILE          = "DHCP_V6_PROFILE"
PPPOE_IA_PROFILE         = "PPPOE_IA"
DHCP_REMOTE_ID_SYNTAX    = "T:::PON_TEST%S%H%S%C%S%S%"
DHCP_CIRCUIT_ID_SYNTAX   = "IF%S%V%S%EV%S%P%S%OI%S%OM%S%OSN"
DHCP_INTERFACE_ID_SYNTAX = "IF%S%V%S%EV%S%P%S%OI%S%OM%S%OSN"


# ─── Minimal declarative XML tree builder / renderer ──────────────────────────

def esc(value):
    s = str(value)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def E(tag, attrs=None, children=None, text=None):
    return {"tag": tag, "attrs": attrs or "", "children": children, "text": text}


def render(node, depth, out):
    indent = "  " * depth
    tag = node["tag"]
    attr_str = f" {node['attrs']}" if node["attrs"] else ""
    if node["children"] is not None:
        if not node["children"]:
            out.append(f"{indent}<{tag}{attr_str}/>")
        else:
            out.append(f"{indent}<{tag}{attr_str}>")
            for child in node["children"]:
                render(child, depth + 1, out)
            out.append(f"{indent}</{tag}>")
    else:
        out.append(f"{indent}<{tag}{attr_str}>{node['text']}</{tag}>")


# ─── Small reusable XML fragment builders (match the reference RPC exactly) ───

def _hw_component(name, prefix, uri, cls_value, parent_rel_pos=None, parent=None):
    children = [
        E("name", None, text=esc(name)),
        E("class", f'xmlns:{prefix}="{uri}"', text=f"{prefix}:{cls_value}"),
    ]
    if parent_rel_pos is not None:
        children.append(E("parent-rel-pos", None, text=str(parent_rel_pos)))
    if parent is not None:
        children.append(E("parent", None, text=esc(parent)))
    return name, E("component", None, children=children)


def _match_tag(tag_type, vlan_id, pbit, dei="any"):
    return E("tag", None, children=[
        E("index", None, text="0"),
        E("dot1q-tag", None, children=[
            E("tag-type", f'xmlns:bbf-dot1qt="{NS_DOT1QT}"', text=f"bbf-dot1qt:{tag_type}"),
            E("dei", None, text=dei),
            E("vlan-id", None, text=str(vlan_id)),
            E("pbit", None, text=str(pbit)),
        ]),
    ])


def _push_tag(vlan_id, write_pbit):
    return E("push-tag", f'xmlns="{NS_SUBIFTAG}"', children=[
        E("index", None, text="0"),
        E("dot1q-tag", None, children=[
            E("tag-type", f'xmlns:bbf-dot1qt="{NS_DOT1QT}"', text="bbf-dot1qt:c-vlan"),
            E("vlan-id", None, text=str(vlan_id)),
            E("write-pbit", None, text=str(write_pbit)),
            E("write-dei-0", None, children=[]),
        ]),
    ])


def _iface_cg(cg, pon_if):
    return E("interface", None, children=[
        E("name", None, text=esc(cg)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:channel-group"),
        E("channel-group", f'xmlns="{NS_XPON}"', children=[
            E("raman-mitigation", None, text="raman-none"),
            E("polling-period", None, text="100"),
            E("system-id", None, text="00000"),
            E("pon-pools", None, children=[
                E("pon-pool", None, children=[
                    E("name", None, text="pool1"),
                    E("channel-termination-ref", None, text=esc(pon_if)),
                ]),
            ]),
        ]),
    ])


def _iface_cpart(name, cg):
    queues = [E("queue", None, children=[E("local-queue-id", None, text=str(q))]) for q in range(8)]
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:channel-partition"),
        E("tm-root", f'xmlns="{NS_QOSTM}"', children=[
            E("child-scheduler-nodes", f'xmlns="{NS_QOSSCHED}"', children=[
                E("name", None, text="NODE_DEF"),
            ]),
            E("scheduler-node", f'xmlns="{NS_QOSSCHED}"', children=[
                E("name", None, text="NODE_DEF"),
                *queues,
                E("scheduling-level", None, text="1"),
            ]),
        ]),
        E("channel-partition", f'xmlns="{NS_XPON}"', children=[
            E("channel-partition-index", None, text="1"),
            E("maximum-differential-xpon-distance", None, text="20"),
            E("authentication-method", None, text="serial-number"),
            E("closest-onu-distance", None, text="0"),
            E("multicast-aes-indicator", None, text="false"),
            E("channel-group-ref", None, text=esc(cg)),
            E("downstream-fec", None, text="true"),
        ]),
    ])


def _iface_cpair(name, cg, cpart, pt_str):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:channel-pair"),
        E("channel-pair", f'xmlns="{NS_XPON}"', children=[
            E("channel-pair-type", f'xmlns:bbf-xpon-types="{NS_XPONTYPES}"', text=f"bbf-xpon-types:{pt_str}"),
            E("channel-partition-ref", None, text=esc(cpart)),
            E("channel-group-ref", None, text=esc(cg)),
        ]),
    ])


def _iface_ct(pon_if, port_hw, cpair):
    return E("interface", None, children=[
        E("name", None, text=esc(pon_if)),
        E("enabled", None, text="true"),
        E("hardware-component", f'xmlns="{NS_BBFHW}"', children=[
            E("port-layer-if", None, text=esc(port_hw)),
        ]),
        E("channel-termination", f'xmlns="{NS_XPON}"', children=[
            E("ber-calc-period", None, text="10"),
            E("channel-pair-ref", None, text=esc(cpair)),
        ]),
    ])


def _iface_ani(name, aniport_hw, onu_id):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:ani"),
        E("hardware-component", f'xmlns="{NS_BBFHW}"', children=[
            E("port-layer-if", None, text=esc(aniport_hw)),
        ]),
        E("ani", f'xmlns="{NS_XPONANI}"', children=[
            E("management-gemport-aes-indicator", None, text="false"),
            E("onu-id", None, text=str(onu_id)),
            E("upstream-fec", None, text="true"),
        ]),
    ])


def _iface_eth(name, uniport_hw, max_host=None):
    children = [
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:ianaift="{NS_IANAIFT}"', text="ianaift:ethernetCsmacd"),
        E("hardware-component", f'xmlns="{NS_BBFHW}"', children=[
            E("port-layer-if", None, text=esc(uniport_hw)),
        ]),
    ]
    if max_host is not None:
        children.append(E("mac-learning", f'xmlns="{NS_FWD}"', children=[
            E("max-number-mac-addresses", None, text=str(max_host)),
        ]))
    return E("interface", None, children=children)


def _iface_subif_untag(name, lower_if, vlan_id, untag_pbit):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbfift="{NS_BBFIFT}"', text="bbfift:vlan-sub-interface"),
        E("subif-lower-layer", f'xmlns="{NS_SUBIF}"', children=[E("interface", None, text=esc(lower_if))]),
        E("inline-frame-processing", f'xmlns="{NS_SUBIF}"', children=[
            E("ingress-rule", None, children=[
                E("rule", None, children=[
                    E("name", None, text="rule_1"),
                    E("ingress-rewrite", None, children=[_push_tag(vlan_id, untag_pbit)]),
                    E("flexible-match", None, children=[
                        E("match-criteria", f'xmlns="{NS_SUBIFTAG}"', children=[
                            E("untagged", None, children=[]),
                        ]),
                    ]),
                    E("priority", None, text="100"),
                ]),
            ]),
        ]),
    ])


def _iface_subif_tag(name, lower_if, filter_vlan, filter_pbit, rewrite):
    rule_children = [E("name", None, text="rule_1")]
    if rewrite:
        rw_vlan, rw_pbit = rewrite
        rule_children.append(E("ingress-rewrite", None, children=[
            E("pop-tags", f'xmlns="{NS_SUBIFTAG}"', text="1"),
            _push_tag(rw_vlan, rw_pbit),
        ]))
    rule_children.append(E("flexible-match", None, children=[
        E("match-criteria", f'xmlns="{NS_SUBIFTAG}"', children=[_match_tag("c-vlan", filter_vlan, filter_pbit)]),
    ]))
    rule_children.append(E("priority", None, text="100"))
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbfift="{NS_BBFIFT}"', text="bbfift:vlan-sub-interface"),
        E("subif-lower-layer", f'xmlns="{NS_SUBIF}"', children=[E("interface", None, text=esc(lower_if))]),
        E("inline-frame-processing", f'xmlns="{NS_SUBIF}"', children=[
            E("ingress-rule", None, children=[E("rule", None, children=rule_children)]),
        ]),
    ])


def _iface_vp(name, lower_if, vlan_id, dhcp_v4=False, dhcp_v6=False, pppoe=False):
    children = [
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbfift="{NS_BBFIFT}"', text="bbfift:vlan-sub-interface"),
        E("subif-lower-layer", f'xmlns="{NS_SUBIF}"', children=[E("interface", None, text=esc(lower_if))]),
        E("inline-frame-processing", f'xmlns="{NS_SUBIF}"', children=[
            E("ingress-rule", None, children=[
                E("rule", None, children=[
                    E("name", None, text="rule_1"),
                    E("flexible-match", None, children=[
                        E("match-criteria", f'xmlns="{NS_SUBIFTAG}"', children=[_match_tag("c-vlan", vlan_id, "any")]),
                    ]),
                    E("priority", None, text="100"),
                ]),
            ]),
        ]),
    ]
    if dhcp_v4:
        children.append(E("l2-dhcpv4-relay", f'xmlns="{NS_L2DHCPV4}"', children=[
            E("enable", None, text="true"),
            E("profile-ref", None, text=esc(DHCP_V4_PROFILE)),
            E("trusted-port", None, text="false"),
        ]))
    if dhcp_v6:
        children.append(E("dhcpv6-ldra", f'xmlns="{NS_LDRA}"', children=[
            E("enable", None, text="true"),
            E("profile-ref", None, text=esc(DHCP_V6_PROFILE)),
            E("trusted-port", None, text="false"),
        ]))
    if pppoe:
        children.append(E("pppoe", f'xmlns="{NS_PPPOE}"', children=[
            E("enable", None, text="true"),
            E("profile-ref", None, text=esc(PPPOE_IA_PROFILE)),
        ]))
    return E("interface", None, children=children)


def _l2_dhcpv4_relay_profiles():
    """DHCPv4 Option 82 relay profile — fixed defaults, not user-editable."""
    return E("l2-dhcpv4-relay-profiles", f'xmlns="{NS_L2DHCPV4}"', children=[
        E("l2-dhcpv4-relay-profile", None, children=[
            E("name", None, text=esc(DHCP_V4_PROFILE)),
            E("option82-format", None, children=[
                E("default-remote-id-syntax", None, text=esc(DHCP_REMOTE_ID_SYNTAX)),
                E("default-circuit-id-syntax", None, text=esc(DHCP_CIRCUIT_ID_SYNTAX)),
                E("suboptions", None, text="circuit-id"),
                E("suboptions", None, text="remote-id"),
            ]),
        ]),
    ])


def _dhcpv6_ldra_profiles():
    """DHCPv6 LDRA profile — fixed defaults, not user-editable."""
    return E("dhcpv6-ldra-profiles", f'xmlns="{NS_LDRA}"', children=[
        E("dhcpv6-ldra-profile", None, children=[
            E("name", None, text=esc(DHCP_V6_PROFILE)),
            E("options", None, children=[
                E("option", None, text="interface-id"),
                E("option", None, text="remote-id"),
                E("default-remote-id-syntax", None, text=esc(DHCP_REMOTE_ID_SYNTAX)),
                E("default-interface-id-syntax", None, text=esc(DHCP_INTERFACE_ID_SYNTAX)),
            ]),
        ]),
    ])


def _pppoe_profiles():
    """PPPoE Intermediate Agent profile — fixed defaults, not user-editable."""
    return E("pppoe-profiles", f'xmlns="{NS_PPPOE}"', children=[
        E("pppoe-profile", None, children=[
            E("name", None, text=esc(PPPOE_IA_PROFILE)),
            E("pppoe-vendor-specific-tag", None, children=[
                E("default-remote-id-syntax", None, text=esc(DHCP_REMOTE_ID_SYNTAX)),
                E("default-circuit-id-syntax", None, text=esc(DHCP_CIRCUIT_ID_SYNTAX)),
                E("subtag", None, text="circuit-id"),
                E("subtag", None, text="remote-id"),
            ]),
        ]),
    ])


def _iface_vani(name, cpart, cpair, serial, onu_id):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:v-ani"),
        E("v-ani", f'xmlns="{NS_XPONVANI}"', children=[
            E("channel-partition", None, text=esc(cpart)),
            E("preferred-channel-pair", None, text=esc(cpair)),
            E("expected-serial-number", None, text=esc(serial)),
            E("onu-id", None, text=str(onu_id)),
            E("upstream-fec", None, text="true"),
        ]),
    ])


def _iface_venet_olt(name, vani):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:olt-v-enet"),
        E("olt-v-enet", f'xmlns="{NS_XPONVANI}"', children=[E("lower-layer-interface", None, text=esc(vani))]),
    ])


def _iface_veip(name, ani):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("enabled", None, text="true"),
        E("type", f'xmlns:bbf-xponift="{NS_XPONIFT}"', text="bbf-xponift:onu-v-vrefpoint"),
        E("onu-v-vrefpoint", f'xmlns="{NS_XPONANI}"', children=[E("related-onu", None, text=esc(ani))]),
    ])


def _iface_uplink(name, phys_if, vlan_id):
    return E("interface", None, children=[
        E("name", None, text=esc(name)),
        E("type", f'xmlns:bbfift="{NS_BBFIFT}"', text="bbfift:vlan-sub-interface"),
        E("subif-lower-layer", f'xmlns="{NS_SUBIF}"', children=[E("interface", None, text=esc(phys_if))]),
        E("inline-frame-processing", f'xmlns="{NS_SUBIF}"', children=[
            E("ingress-rule", None, children=[
                E("rule", None, children=[
                    E("name", None, text="rule.tag"),
                    E("flexible-match", None, children=[
                        E("match-criteria", f'xmlns="{NS_SUBIFTAG}"', children=[_match_tag("s-vlan", vlan_id, "any")]),
                    ]),
                    E("priority", None, text="1"),
                ]),
            ]),
        ]),
    ])


class GPONRPCGenerator:
    def __init__(self, root):
        self.root = root
        # Only manage window if root is a top-level Tk window (not an embedded Frame)
        if isinstance(root, (tk.Tk, tk.Toplevel)):
            self.root.title("GPON NSO XML RPC Generator")
            self.root.geometry("1150x700")
            self.root.minsize(800, 500)
        self._last_config     = ""
        self._last_remove_config = ""
        self.dba_name_vars    = []
        self.dba_fixed_vars   = []
        self.dba_assured_vars = []
        self.dba_max_vars     = []
        self.dba_widgets      = []
        self.uni_sections     = []
        self.uni_group_frames = []
        self.uni_check_vars   = []
        self.uni_maxhost_en_vars  = []
        self.uni_maxhost_val_vars = []
        self.uni_maxhost_en_widgets  = []
        self.uni_maxhost_val_widgets = []
        self.tcont_alloc_vars = []
        self.tcont_dba_vars   = []
        self.tcont_dba_cbs    = []
        self.tcont_gem_vars   = []
        self.tcont_vlan_vars  = []
        self.tcont_ds_aes_vars = []
        self.tcont_us_aes_vars = []
        self.tcont_widgets    = []

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("RpcSection.TLabel", font=("Segoe UI", 9, "bold"), foreground="#005a9e")
        style.configure("RpcAction.TButton", font=("Segoe UI", 9, "bold"), padding=6)

        self._build_ui()

    # ─── UI Layout ────────────────────────────────────────────────────────────

    def _build_ui(self):
        pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.Frame(pane, width=370)
        right = ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=2)

        self._build_input_panel(left)
        self._build_preview_panel(right)

    def _build_input_panel(self, parent):
        canvas = tk.Canvas(parent, highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self.v = {}
        r = 0

        # ── Section 1: DBA Profiles ─────────────────────────────────────────
        MAX_DBA = 4
        r = self._sep(inner, "Section 1 — DBA Profiles", r)
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
        r = self._sep(inner, "Section 2 — VLAN & Uplink", r)

        self.v["include_uplink"] = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            inner, text="Include VLAN & Uplink section (uncheck for an ONT-only\n"
                        "RPC into an already-provisioned VLAN)",
            variable=self.v["include_uplink"], command=self._toggle_uplink_section,
        ).grid(row=r, column=0, columnspan=2, sticky="w", padx=(14, 4), pady=(0, 3))
        r += 1

        ttk.Label(inner, text="VLAN IDs (spaces):").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["vlan_id"] = tk.StringVar(value="30 31 35")
        self._vlan_entry = ttk.Entry(inner, textvariable=self.v["vlan_id"], width=22)
        self._vlan_entry.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=3)
        r += 1

        ttk.Label(inner, text="Uplink Interface:").grid(
            row=r, column=0, sticky="w", padx=(14, 4), pady=3)
        self.v["uplink_eth"] = tk.StringVar(value="eth0/20")
        self._uplink_entry = ttk.Entry(inner, textvariable=self.v["uplink_eth"], width=22)
        self._uplink_entry.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=3)
        r += 1

        # ── Section 3: PON Interface ────────────────────────────────────────
        r = self._sep(inner, "Section 3 — PON Interface", r)

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
        r = self._sep(inner, "Sections 5–9 — ONT Information", r)
        self.v["onu_id"]     = self._row(inner, "ONU ID:",     "1",            r); r += 1
        self.v["ont_serial"] = self._row(inner, "ONT Serial:", "DSNW29775988", r); r += 1

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

        MAX_UNI = 8
        self._uni_lbl = ttk.Label(inner, text="UNI Ports:")
        self._uni_lbl.grid(row=r, column=0, sticky="nw", padx=(14, 4), pady=3)
        self._uni_frame = ttk.Frame(inner)
        self._uni_frame.grid(row=r, column=1, sticky="ew", padx=(0, 10), pady=3)
        for u in range(MAX_UNI):
            sel_var    = tk.BooleanVar(value=(u == 0))  # UNI 1 ticked by default
            mh_en_var  = tk.BooleanVar(value=False)
            mh_val_var = tk.StringVar(value="")
            self.uni_check_vars.append(sel_var)
            self.uni_maxhost_en_vars.append(mh_en_var)
            self.uni_maxhost_val_vars.append(mh_val_var)

            # 4 ports per row -> 2 rows
            cell = ttk.Frame(self._uni_frame, relief="groove", borderwidth=1)
            cell.grid(row=u // 4, column=u % 4, padx=2, pady=2, sticky="w")
            ttk.Checkbutton(cell, text=str(u + 1), width=2, variable=sel_var,
                            command=self._on_uni_toggle).pack(side="left")
            mh_chk = ttk.Checkbutton(cell, text="Max-host", variable=mh_en_var,
                                     command=self._update_uni_maxhost_states)
            mh_chk.pack(side="left", padx=(2, 0))
            mh_ent = ttk.Entry(cell, textvariable=mh_val_var, width=5)
            mh_ent.pack(side="left", padx=(2, 0))
            self.uni_maxhost_en_widgets.append(mh_chk)
            self.uni_maxhost_val_widgets.append(mh_ent)
        r += 1

        # ── Section 10: TCONT / GEM ─────────────────────────────────────────
        MAX_TCONT = 8
        r = self._sep(inner, "Section 10 — TCONT / GEM", r)
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
            ds_aes_var = tk.BooleanVar(value=False)
            us_aes_var = tk.BooleanVar(value=False)

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
            ttk.Checkbutton(t_sub, text="DS-AES", variable=ds_aes_var).pack(side="left", padx=(6, 0))
            ttk.Checkbutton(t_sub, text="US-AES", variable=us_aes_var).pack(side="left", padx=(2, 0))

            self.tcont_alloc_vars.append(alloc_var)
            self.tcont_dba_vars.append(dba_var)
            self.tcont_dba_cbs.append(dba_cb)
            self.tcont_gem_vars.append(gem_var)
            self.tcont_vlan_vars.append(vlan_var)
            self.tcont_ds_aes_vars.append(ds_aes_var)
            self.tcont_us_aes_vars.append(us_aes_var)
            self.tcont_widgets.append((t_lbl, t_sub))
            if t > 0:
                t_lbl.grid_remove(); t_sub.grid_remove()

        # ── Extended VLAN Rules (Section 8) — one group per UNI port ───────
        MAX_UNI_GROUPS = MAX_UNI
        r = self._sep(inner, "Extended VLAN Rules (Section 8)", r)

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

        # keep the Extended VLAN groups + Max-host controls in sync with ticked UNI
        self._update_uni_groups()
        self._update_uni_maxhost_states()

        # ── Buttons: Add Service ─────────────────────────────────────────────
        r += 1
        ttk.Label(inner, text="Add Service", style="RpcSection.TLabel").grid(
            row=r, column=0, columnspan=2, sticky="w", padx=6, pady=(4, 2))
        r += 1
        btn_frame = ttk.Frame(inner)
        btn_frame.grid(row=r, column=0, columnspan=2, pady=(0, 8), padx=6, sticky="ew")
        btn_frame.columnconfigure((0, 1, 2), weight=1)
        r += 1

        ttk.Button(btn_frame, text="Generate RPC", style="RpcAction.TButton",
                   command=self.generate).grid(row=0, column=0, padx=3, sticky="ew")
        ttk.Button(btn_frame, text="Save to File", style="RpcAction.TButton",
                   command=self.save_file).grid(row=0, column=1, padx=3, sticky="ew")
        ttk.Button(btn_frame, text="Copy to Clipboard", style="RpcAction.TButton",
                   command=self.copy_to_clipboard).grid(row=0, column=2, padx=3, sticky="ew")

        # ── Buttons: Remove Service ──────────────────────────────────────────
        ttk.Label(inner, text="Remove Service", style="RpcSection.TLabel").grid(
            row=r, column=0, columnspan=2, sticky="w", padx=6, pady=(4, 2))
        r += 1
        remove_btn_frame = ttk.Frame(inner)
        remove_btn_frame.grid(row=r, column=0, columnspan=2, pady=(0, 12), padx=6, sticky="ew")
        remove_btn_frame.columnconfigure((0, 1, 2), weight=1)
        r += 1

        ttk.Button(remove_btn_frame, text="Generate Remove RPC", style="RpcAction.TButton",
                   command=self.generate_remove).grid(row=0, column=0, padx=3, sticky="ew")
        ttk.Button(remove_btn_frame, text="Save to File", style="RpcAction.TButton",
                   command=self.save_remove_file).grid(row=0, column=1, padx=3, sticky="ew")
        ttk.Button(remove_btn_frame, text="Copy to Clipboard", style="RpcAction.TButton",
                   command=self.copy_remove_to_clipboard).grid(row=0, column=2, padx=3, sticky="ew")

        # ── SSH / NETCONF Connection ────────────────────────────────────────
        r += 1
        conn_frame = ttk.LabelFrame(inner, text="SSH / NETCONF Connection")
        conn_frame.grid(row=r, column=0, columnspan=2, sticky="ew", padx=6, pady=(4, 10))
        conn_frame.columnconfigure(1, weight=1)
        r += 1

        self.v["ssh_host"]    = tk.StringVar(value="192.168.100.249")
        self.v["ssh_port"]    = tk.StringVar(value="830")
        self.v["ssh_user"]    = tk.StringVar(value="admin")
        self.v["ssh_pass"]    = tk.StringVar(value="Zhone1234%^&*")
        self.v["ssh_timeout"] = tk.StringVar(value="60")

        cr = 0
        ttk.Label(conn_frame, text="Host (OLT IP):").grid(
            row=cr, column=0, sticky="w", padx=(8, 4), pady=3)
        ttk.Entry(conn_frame, textvariable=self.v["ssh_host"]).grid(
            row=cr, column=1, sticky="ew", padx=(0, 8), pady=3)
        cr += 1

        ttk.Label(conn_frame, text="Port:").grid(
            row=cr, column=0, sticky="w", padx=(8, 4), pady=3)
        ttk.Entry(conn_frame, textvariable=self.v["ssh_port"], width=10).grid(
            row=cr, column=1, sticky="w", padx=(0, 8), pady=3)
        cr += 1

        ttk.Label(conn_frame, text="Username:").grid(
            row=cr, column=0, sticky="w", padx=(8, 4), pady=3)
        ttk.Entry(conn_frame, textvariable=self.v["ssh_user"]).grid(
            row=cr, column=1, sticky="ew", padx=(0, 8), pady=3)
        cr += 1

        ttk.Label(conn_frame, text="Password:").grid(
            row=cr, column=0, sticky="w", padx=(8, 4), pady=3)
        pass_frame = ttk.Frame(conn_frame)
        pass_frame.grid(row=cr, column=1, sticky="ew", padx=(0, 8), pady=3)
        pass_frame.columnconfigure(0, weight=1)
        self._ssh_pass_entry = ttk.Entry(pass_frame, textvariable=self.v["ssh_pass"], show="*")
        self._ssh_pass_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(pass_frame, text="\U0001F441", width=3,
                   command=self._toggle_password_visibility).grid(row=0, column=1, padx=(4, 0))
        cr += 1

        ttk.Label(conn_frame, text="Timeout (s):").grid(
            row=cr, column=0, sticky="w", padx=(8, 4), pady=3)
        ttk.Entry(conn_frame, textvariable=self.v["ssh_timeout"], width=10).grid(
            row=cr, column=1, sticky="w", padx=(0, 8), pady=3)
        cr += 1

        self.send_btn = ttk.Button(conn_frame, text="Send Add RPC to OLT", style="RpcAction.TButton",
                                    command=self.send_rpc)
        self.send_btn.grid(row=cr, column=0, columnspan=2, sticky="ew", padx=8, pady=(6, 2))
        cr += 1

        self.send_remove_btn = ttk.Button(conn_frame, text="Send Remove RPC to OLT",
                                           style="RpcAction.TButton", command=self.send_remove_rpc)
        self.send_remove_btn.grid(row=cr, column=0, columnspan=2, sticky="ew", padx=8, pady=(2, 8))

    def _build_rule_section(self, parent):
        MAX_RULES   = 8
        PBIT_VALUES = ["any", "0", "1", "2", "3", "4", "5", "6", "7"]
        sec = {
            "num_rules_var":       tk.StringVar(value="1"),
            "rule_type_vars":      [],
            "rule_vlan_vars":      [],
            "rule_untag_pbit_vars":[],
            "rule_pbit_vars":      [],
            "rule_rewrite_vars":   [],
            "rule_rw_vlan_vars":   [],
            "rule_rw_pbit_vars":   [],
            "rule_dhcp_v4_vars":   [],
            "rule_dhcp_v6_vars":   [],
            "rule_pppoe_vars":     [],
            "rule_widgets":        [],
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
            dhcp_v4_var    = tk.BooleanVar(value=False)
            dhcp_v6_var    = tk.BooleanVar(value=False)
            pppoe_var      = tk.BooleanVar(value=False)

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

            ttk.Checkbutton(sub, text="DHCP Option 82", variable=dhcp_v4_var).grid(row=0, column=10, padx=(6, 0))
            ttk.Checkbutton(sub, text="DHCPv6 Option18", variable=dhcp_v6_var).grid(row=0, column=11, padx=(2, 0))
            ttk.Checkbutton(sub, text="PPPoE-IA", variable=pppoe_var).grid(row=0, column=12, padx=(6, 0))

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

            sec["rule_type_vars"].append(type_var)
            sec["rule_vlan_vars"].append(vlan_var)
            sec["rule_untag_pbit_vars"].append(untag_pbit_var)
            sec["rule_pbit_vars"].append(pbit_var)
            sec["rule_rewrite_vars"].append(rewrite_var)
            sec["rule_rw_vlan_vars"].append(rw_vlan_var)
            sec["rule_rw_pbit_vars"].append(rw_pbit_var)
            sec["rule_dhcp_v4_vars"].append(dhcp_v4_var)
            sec["rule_dhcp_v6_vars"].append(dhcp_v6_var)
            sec["rule_pppoe_vars"].append(pppoe_var)
            sec["rule_widgets"].append((lbl, sub))

        self._update_rule_rows_for(sec)
        return sec

    def _sep(self, parent, text, row):
        ttk.Label(parent, text=text, style="RpcSection.TLabel").grid(
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

    def _toggle_uplink_section(self, *_):
        state = "normal" if self.v["include_uplink"].get() else "disabled"
        self._vlan_entry.configure(state=state)
        self._uplink_entry.configure(state=state)

    def _toggle_uni_port(self, *_):
        if self.v["mode"].get() == "PPTP":
            self._uni_lbl.grid()
            self._uni_frame.grid()
        else:
            self._uni_lbl.grid_remove()
            self._uni_frame.grid_remove()
        self._update_uni_groups()
        self._update_uni_maxhost_states()

    def _on_uni_toggle(self, *_):
        self._update_uni_groups()
        self._update_uni_maxhost_states()

    def _update_uni_maxhost_states(self, *_):
        # Max-host is configurable only for a ticked UNI; the value entry is
        # active only when its Max-host box is also enabled.
        for u in range(len(self.uni_check_vars)):
            selected = self.uni_check_vars[u].get()
            self.uni_maxhost_en_widgets[u].configure(
                state=("normal" if selected else "disabled"))
            val_on = selected and self.uni_maxhost_en_vars[u].get()
            self.uni_maxhost_val_widgets[u].configure(
                state=("normal" if val_on else "disabled"))

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
            ports = [i + 1 for i, var in enumerate(self.uni_check_vars) if var.get()]
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

    def _refresh_dba_in_cb(self, event):
        try:
            n = max(1, int(self.v["num_dba"].get()))
        except (ValueError, KeyError):
            n = 1
        names = [self.dba_name_vars[i].get() for i in range(n)]
        event.widget["values"] = names

    def _make_xml_preview_widget(self, parent):
        text = tk.Text(
            parent, font=("Consolas", 9), wrap=tk.NONE,
            bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", borderwidth=1,
        )
        vsb = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=text.xview)
        text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        text.pack(fill="both", expand=True)

        text.tag_configure("tag",  foreground="#569cd6")
        text.tag_configure("attr", foreground="#9cdcfe")
        return text

    def _build_preview_panel(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        preview_tab = ttk.Frame(notebook)
        remove_preview_tab = ttk.Frame(notebook)
        log_tab = ttk.Frame(notebook)
        notebook.add(preview_tab, text="Generated XML RPC Preview")
        notebook.add(remove_preview_tab, text="Remove Service Preview")
        notebook.add(log_tab, text="Response Log")

        self.preview = self._make_xml_preview_widget(preview_tab)
        self.remove_preview = self._make_xml_preview_widget(remove_preview_tab)

        # ── Response Log (from the OLT, via Send RPC) ───────────────────────
        log_header = ttk.Frame(log_tab)
        log_header.pack(fill="x", pady=(0, 4))
        ttk.Button(log_header, text="Clear Log", command=self._clear_log).pack(side="right")

        self.log_text = tk.Text(
            log_tab, font=("Consolas", 9), wrap=tk.WORD,
            bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="white", selectbackground="#264f78",
            relief="flat", borderwidth=1, state="disabled",
        )
        log_vsb = ttk.Scrollbar(log_tab, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)

        self.log_text.tag_configure("info",    foreground="#9cdcfe")
        self.log_text.tag_configure("success", foreground="#4ec9b0")
        self.log_text.tag_configure("error",   foreground="#f14c4c")
        self.log_text.tag_configure("reply",   foreground="#d4d4d4")

        self._notebook = notebook
        self._log_tab = log_tab

    def _log(self, message, tag="info"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"[{timestamp}] ", "info")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def _pretty_xml(self, xml_str):
        try:
            from lxml import etree
            parser = etree.XMLParser(remove_blank_text=True)
            root = etree.fromstring(xml_str.encode("utf-8"), parser=parser)
            return etree.tostring(root, pretty_print=True, encoding="unicode").rstrip()
        except Exception:
            return xml_str

    # ─── Actions ──────────────────────────────────────────────────────────────

    def generate(self):
        params = self._parse_inputs()
        if params is None:
            return
        self._last_config = self._build_xml_config(params)
        self._show_preview(self._last_config)

    def save_file(self):
        if not self._last_config:
            self.generate()
        if not self._last_config:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="GPON_NSO_RPC.xml",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_config)
            messagebox.showinfo("Saved", f"RPC saved to:\n{path}")

    def copy_to_clipboard(self):
        if not self._last_config:
            self.generate()
        if self._last_config:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._last_config)
            messagebox.showinfo("Copied", "RPC copied to clipboard.")

    def generate_remove(self):
        params = self._parse_inputs()
        if params is None:
            return
        self._last_remove_config = self._build_remove_xml_config(params)
        self._show_preview(self._last_remove_config, widget=self.remove_preview)
        self._notebook.select(self.remove_preview.master)

    def save_remove_file(self):
        if not self._last_remove_config:
            self.generate_remove()
        if not self._last_remove_config:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="GPON_NSO_Remove_RPC.xml",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._last_remove_config)
            messagebox.showinfo("Saved", f"Remove RPC saved to:\n{path}")

    def copy_remove_to_clipboard(self):
        if not self._last_remove_config:
            self.generate_remove()
        if self._last_remove_config:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._last_remove_config)
            messagebox.showinfo("Copied", "Remove RPC copied to clipboard.")

    def _toggle_password_visibility(self):
        shown = self._ssh_pass_entry.cget("show") == ""
        self._ssh_pass_entry.configure(show="*" if shown else "")

    def send_rpc(self):
        if not self._last_config:
            self.generate()
        if not self._last_config:
            return
        self._connect_and_send(self._last_config, "Add", self.send_btn)

    def send_remove_rpc(self):
        if not self._last_remove_config:
            self.generate_remove()
        if not self._last_remove_config:
            return
        if not messagebox.askyesno(
            "Confirm Remove",
            "This will DELETE this ONT's configuration from the device "
            "(hardware, interfaces, TCONT/GEM, forwarding ports) and commit "
            "it immediately. This cannot be undone from this tool.\n\nContinue?",
            icon="warning",
        ):
            return
        self._connect_and_send(self._last_remove_config, "Remove", self.send_remove_btn)

    def _connect_and_send(self, xml_str, label, button):
        host = self.v["ssh_host"].get().strip()
        if not host:
            messagebox.showerror("Connection Error", "Please enter the OLT host/IP.")
            return
        try:
            port = int(self.v["ssh_port"].get())
            timeout = int(self.v["ssh_timeout"].get())
        except ValueError:
            messagebox.showerror("Connection Error", "Port and Timeout must be numeric.")
            return
        username = self.v["ssh_user"].get().strip()
        password = self.v["ssh_pass"].get()

        try:
            from ncclient import manager
            from lxml import etree
        except ImportError:
            messagebox.showerror(
                "Missing Dependency",
                "Sending RPCs requires the 'ncclient' package.\n\n"
                "Install it with:\n\n    pip install ncclient",
            )
            return

        try:
            elem = etree.fromstring(xml_str.encode("utf-8"))
        except Exception as exc:
            messagebox.showerror("XML Error", f"Generated RPC is not valid XML:\n{exc}")
            return

        button.configure(state="disabled", text="Sending...")
        self._notebook.select(self._log_tab)
        self._log(f"[{label}] Connecting to {host}:{port} as '{username}' ...")

        def worker():
            try:
                with manager.connect(
                    host=host, port=port, username=username, password=password,
                    hostkey_verify=False, timeout=timeout,
                    look_for_keys=False, allow_agent=False,
                    device_params={"name": "default"},
                ) as m:
                    edit_reply = m.rpc(elem)
                    self.root.after(0, lambda: self._log(
                        f"[{label}] edit-config reply:\n{self._pretty_xml(edit_reply.xml)}", "reply"))
                    # target is always "candidate" -- it only takes effect once committed.
                    commit_reply = m.commit()
                    self.root.after(0, lambda: self._log(
                        f"[{label}] commit reply:\n{self._pretty_xml(commit_reply.xml)}", "reply"))
                self.root.after(0, lambda: self._on_send_done(True, host, label, button))
            except Exception as exc:
                self.root.after(0, lambda exc=exc: self._on_send_done(False, str(exc), label, button))

        threading.Thread(target=worker, daemon=True).start()

    def _on_send_done(self, ok, message, label, button):
        button.configure(state="normal", text=f"Send {label} RPC to OLT")
        if ok:
            self._log(f"[{label}] RPC and commit sent successfully to {message}.", "success")
        else:
            self._log(f"[{label}] Failed: {message}", "error")
            messagebox.showerror("RPC Failed", message)

    # ─── Input parsing ─────────────────────────────────────────────────────────

    def _parse_rules(self, section):
        n = max(1, int(section["num_rules_var"].get()))
        rules = []
        for i in range(n):
            rule = {
                "type": section["rule_type_vars"][i].get(),
                "vlan": int(section["rule_vlan_vars"][i].get()),
                "dhcp_v4": section["rule_dhcp_v4_vars"][i].get(),
                "dhcp_v6": section["rule_dhcp_v6_vars"][i].get(),
                "pppoe":   section["rule_pppoe_vars"][i].get(),
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
            uni_ports = ([i + 1 for i, var in enumerate(self.uni_check_vars) if var.get()]
                         if mode == "PPTP" else [])
            n_uni = len(uni_ports) if mode == "PPTP" else 1
            n_dba   = max(1, int(self.v["num_dba"].get()))
            n_tcont = max(1, int(self.v["num_tcont"].get()))

            # Max-host per UNI (only for ticked ports that also enable Max-host)
            uni_max_host = {}
            for u in uni_ports:
                if self.uni_maxhost_en_vars[u - 1].get():
                    raw = self.uni_maxhost_val_vars[u - 1].get().strip()
                    if raw == "":
                        raise ValueError(f"UNI {u}: Max-host is enabled but no value entered")
                    uni_max_host[u] = int(raw)
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
                "include_uplink": self.v["include_uplink"].get(),
                "vlan_ids":     [int(v) for v in self.v["vlan_id"].get().split()],
                "uplink_eth":   self.v["uplink_eth"].get().strip(),
                "pon_type":     self.v["pon_type"].get(),
                "pon_slot":     int(self.v["pon_slot"].get()),
                "pon_port":     int(self.v["pon_port"].get()),
                "onu_id":       int(self.v["onu_id"].get()),
                "ont_serial":   self.v["ont_serial"].get().strip().upper(),
                "mode":         mode,
                "uni_ports":    uni_ports,
                "uni_max_host": uni_max_host,
                "tconts": [
                    {
                        "alloc_id": int(self.tcont_alloc_vars[i].get()),
                        "dba":      self.tcont_dba_vars[i].get().strip(),
                        "gem_id":   int(self.tcont_gem_vars[i].get()),
                        "vlan":     int(self.tcont_vlan_vars[i].get()),
                        "ds_aes":   self.tcont_ds_aes_vars[i].get(),
                        "us_aes":   self.tcont_us_aes_vars[i].get(),
                    }
                    for i in range(n_tcont)
                ],
                "rules_per_uni": [self._parse_rules(self.uni_sections[i]) for i in range(n_uni)],
            }
        except ValueError as exc:
            messagebox.showerror("Input Error", f"Invalid value: {exc}\n\nPlease check numeric fields.")
            return None
        if result["mode"] == "PPTP" and not result["uni_ports"]:
            messagebox.showerror("Input Error", "Please tick at least one UNI Port.")
            return None
        if result["include_uplink"] and not result["vlan_ids"]:
            messagebox.showerror("Input Error",
                                  "Please enter at least one VLAN ID, or uncheck "
                                  "'Include VLAN & Uplink section'.")
            return None
        if result["include_uplink"] and not result["uplink_eth"]:
            messagebox.showerror("Input Error", "Please enter an Uplink Interface.")
            return None
        return result

    # ─── XML RPC builder ────────────────────────────────────────────────────────

    def _build_xml_config(self, p):
        vlans          = p["vlan_ids"]
        uplink         = p["uplink_eth"]
        pon_type       = p["pon_type"]
        include_uplink = p["include_uplink"]

        if pon_type == "GPON":
            pon_if = f"gpon{p['pon_slot']}/{p['pon_port']}"
            cg     = f"CG_{p['pon_port']:02d}_gpon"
            pt_str = "gpon"
        else:  # XGSPON
            pon_if = f"xgspon{p['pon_slot']}/{p['pon_port']}"
            cg     = f"CG_{p['pon_port']:02d}_xgs"
            pt_str = "xgs"

        onu_str = f"onu{p['onu_id']:03d}"
        pfx     = f"{pon_if}_{onu_str}"
        onu_id  = p["onu_id"]
        serial  = p["ont_serial"]
        mode    = p["mode"]
        uni_ports = p["uni_ports"]
        rules_per_uni = p["rules_per_uni"]

        if mode == "PPTP":
            uni_configs = [(u, f"{pfx}_eth1_{u}", f"{pfx}_venet1_{u}", f"o_venet1_{u}")
                           for u in uni_ports]
        else:  # VEIP
            uni_configs = [(1, f"{pfx}_veip_1", f"{pfx}_venet1_1", "o_venet1_1")]

        cpart = f"{cg}.CPart"
        cpair = f"{cg}.CPart.CPair"
        vani  = f"{pfx}_vani1_1"
        ani   = f"{pfx}_ani1_1"

        # ── Hardware components ─────────────────────────────────────────────
        hw = [
            _hw_component(f"{pon_if}_cage", "bbf-hwt", NS_HWT, "cage"),
            _hw_component(pfx, "ianahw", NS_IANAHW, "chassis", parent_rel_pos=1),
            _hw_component(f"{pfx}_aniport1_1", "bbf-hwt", NS_HWT, "transceiver-link",
                          parent=f"{pfx}_sfp1_1"),
            _hw_component(f"{pfx}_cage1_1", "bbf-hwt", NS_HWT, "cage", parent=f"{pfx}_card1"),
            _hw_component(f"{pfx}_card1", "bbf-hwt", NS_HWT, "board", parent=pfx),
            _hw_component(f"{pfx}_sfp1_1", "bbf-hwt", NS_HWT, "transceiver",
                          parent=f"{pfx}_cage1_1"),
            _hw_component(f"{pon_if}_port", "bbf-hwt", NS_HWT, "transceiver-link"),
            _hw_component(f"{pon_if}_sfp", "bbf-hwt", NS_HWT, "transceiver"),
        ]
        if mode == "PPTP":
            for u in uni_ports:
                hw.append(_hw_component(f"{pfx}_uniport1_{u}", "bbf-hwt", NS_HWT, "rj45",
                                        parent_rel_pos=u, parent=f"{pfx}_card1"))
        hw.sort(key=lambda item: item[0])
        hw_nodes = [node for _, node in hw]

        # ── Interfaces + effective-VLAN → VP-interface map ─────────────────
        ifaces = [
            (cg, _iface_cg(cg, pon_if)),
            (cpart, _iface_cpart(cpart, cg)),
            (cpair, _iface_cpair(cpair, cg, cpart, pt_str)),
            (pon_if, _iface_ct(pon_if, f"{pon_if}_port", cpair)),
            (ani, _iface_ani(ani, f"{pfx}_aniport1_1", onu_id)),
            (vani, _iface_vani(vani, cpart, cpair, serial, onu_id)),
        ]
        if mode == "PPTP":
            uni_max_host = p.get("uni_max_host", {})
            for u in uni_ports:
                ifaces.append((f"{pfx}_eth1_{u}",
                               _iface_eth(f"{pfx}_eth1_{u}", f"{pfx}_uniport1_{u}",
                                          uni_max_host.get(u))))
        else:
            ifaces.append((f"{pfx}_veip_1", _iface_veip(f"{pfx}_veip_1", ani)))
        for _u, _ont_uni_if, olt_lower, _vp_base in uni_configs:
            ifaces.append((olt_lower, _iface_venet_olt(olt_lower, vani)))
        if include_uplink:
            for vlan in vlans:
                name = f"uplink_{uplink}.{vlan}"
                ifaces.append((name, _iface_uplink(name, uplink, vlan)))

        vp_entries = []  # (effective_vlan, vp_if)
        need_dhcp_v4 = False
        need_dhcp_v6 = False
        need_pppoe = False
        for idx_u, (_u, ont_uni_if, olt_lower, vp_base) in enumerate(uni_configs):
            for rule in rules_per_uni[idx_u]:
                rtype = rule["type"]
                rvlan = rule["vlan"]
                dhcp_v4 = rule.get("dhcp_v4", False)
                dhcp_v6 = rule.get("dhcp_v6", False)
                pppoe   = rule.get("pppoe", False)
                need_dhcp_v4 = need_dhcp_v4 or dhcp_v4
                need_dhcp_v6 = need_dhcp_v6 or dhcp_v6
                need_pppoe = need_pppoe or pppoe
                if rtype == "Untag":
                    subif = f"{ont_uni_if}_c{rvlan:04d}_untag"
                    untag_pbit = rule.get("untag_pbit", "0")
                    ifaces.append((subif, _iface_subif_untag(subif, ont_uni_if, rvlan, untag_pbit)))
                    eff_vlan = rvlan
                else:  # Single Tag
                    rewrite = rule.get("rewrite")
                    eff_vlan = rule["rw_vlan"] if rewrite else rvlan
                    subif = f"{ont_uni_if}_c{eff_vlan:04d}_any"
                    filter_pbit = rule.get("filter_pbit", "any")
                    rw = (rule["rw_vlan"], rule["rw_pbit"]) if rewrite else None
                    ifaces.append((subif, _iface_subif_tag(subif, ont_uni_if, rvlan, filter_pbit, rw)))
                vp_if = f"{pfx}_{vp_base}_c{eff_vlan:04d}_any"
                ifaces.append((vp_if, _iface_vp(vp_if, olt_lower, eff_vlan, dhcp_v4, dhcp_v6, pppoe)))
                vp_entries.append((eff_vlan, vp_if))

        ifaces.sort(key=lambda item: item[0])
        iface_nodes = [node for _, node in ifaces]

        # ── Forwarding: uplink ports first, then ONT-side VP ports ─────────
        # mac-learning/forwarding-database is only bound for VLANs that went
        # through the VLAN & Uplink section — an ONT-only RPC into a VLAN
        # provisioned by an earlier message must not redeclare it.
        forwarder_ports = {}
        mac_learning_vlans = set(vlans) if include_uplink else set()
        if include_uplink:
            for vlan in vlans:
                forwarder_ports.setdefault(vlan, []).append(
                    (f"fwd.uplink_{uplink}.{vlan}", f"uplink_{uplink}.{vlan}"))
        for eff_vlan, vp_if in vp_entries:
            forwarder_ports.setdefault(eff_vlan, []).append((f"fwd_{vp_if}", vp_if))

        fwd_vlans = sorted(forwarder_ports.keys())
        forwarder_nodes = []
        for vlan in fwd_vlans:
            port_nodes = [
                E("port", None, children=[
                    E("name", None, text=esc(pname)),
                    E("sub-interface", None, text=esc(sub)),
                ])
                for pname, sub in forwarder_ports[vlan]
            ]
            forwarder_children = [
                E("name", None, text=f"fwd.vlan{vlan}.cli.attach"),
                E("ports", None, children=port_nodes),
            ]
            if vlan in mac_learning_vlans:
                forwarder_children.append(E("mac-learning", None, children=[
                    E("forwarding-database", None, text=f"fwd.db.vlan{vlan}.cli.attach"),
                ]))
            forwarder_nodes.append(E("forwarder", None, children=forwarder_children))
        fdb_nodes = [
            E("forwarding-database", None, children=[E("name", None, text=f"fwd.db.vlan{v}.cli.attach")])
            for v in sorted(mac_learning_vlans)
        ]

        # ── Link table ───────────────────────────────────────────────────────
        link_entries = [(ani, vani)]
        link_entries += [(ont_uni_if, olt_lower) for _u, ont_uni_if, olt_lower, _vp_base in uni_configs]
        link_entries.sort(key=lambda item: item[0])
        link_nodes = [
            E("link-table", None, children=[
                E("from-interface", None, text=esc(frm)),
                E("to-interface", None, text=esc(to)),
            ])
            for frm, to in link_entries
        ]

        # ── TCONT / GEM / DBA ────────────────────────────────────────────────
        vlan_to_vp = {}
        for eff_vlan, vp_if in vp_entries:
            vlan_to_vp.setdefault(eff_vlan, vp_if)
        default_vp_base = uni_configs[0][3]

        gemport_nodes, tcont_nodes = [], []
        for i, tcont in enumerate(p["tconts"]):
            vlan = tcont["vlan"]
            vp_if = vlan_to_vp.get(vlan, f"{pfx}_{default_vp_base}_c{vlan:04d}_any")
            tcont_name = f"{pfx}_tcont1_{i + 1}"
            gem_name   = f"{pfx}_gem1_{i + 1}"
            gemport_children = [
                E("name", None, text=esc(gem_name)),
                E("tcont-ref", None, text=esc(tcont_name)),
                E("interface", None, text=esc(vp_if)),
                E("gemport-id", None, text=str(tcont["gem_id"])),
            ]
            if tcont.get("ds_aes"):
                gemport_children.append(E("downstream-aes-indicator", None, text="true"))
            if tcont.get("us_aes"):
                gemport_children.append(E("upstream-aes-indicator", None, text="true"))
            gemport_nodes.append(E("gemport", None, children=gemport_children))
            tcont_nodes.append(E("tcont", None, children=[
                E("name", None, text=esc(tcont_name)),
                E("interface-reference", None, text=esc(vani)),
                E("traffic-descriptor-profile-ref", None, text=esc(tcont["dba"])),
                E("alloc-id", None, text=str(tcont["alloc_id"])),
            ]))
        tdp_nodes = [
            E("traffic-descriptor-profile", None, children=[
                E("name", None, text=esc(dba["name"])),
                E("maximum-bandwidth", None, text=str(dba["max_bw"])),
                E("fixed-bandwidth", None, text=str(dba["fixed_bw"])),
                E("assured-bandwidth", None, text=str(dba["assured_bw"])),
            ])
            for dba in p["dba_profiles"]
        ]

        # ── Assemble the edit-config tree ────────────────────────────────────
        forwarding_children = [E("forwarders", None, children=forwarder_nodes)]
        if mac_learning_vlans:
            forwarding_children.append(E("forwarding-databases", None, children=fdb_nodes))

        config_children = [
            E("hardware", f'xmlns="{NS_HW}"', children=hw_nodes),
            E("forwarding", f'xmlns="{NS_FWD}"', children=forwarding_children),
            E("link-table", f'xmlns="{NS_LINKTABLE}"', children=link_nodes),
            E("interfaces", f'xmlns="{NS_IF}"', children=iface_nodes),
            E("xpongemtcont", f'xmlns="{NS_XPONGEMTCONT}"', children=[
                E("gemports", None, children=gemport_nodes),
                E("tconts", None, children=tcont_nodes),
                E("traffic-descriptor-profiles", None, children=tdp_nodes),
            ]),
        ]
        # DHCP relay profiles — only emitted when a rule references them.
        if need_dhcp_v4:
            config_children.append(_l2_dhcpv4_relay_profiles())
        if need_dhcp_v6:
            config_children.append(_dhcpv6_ldra_profiles())
        if need_pppoe:
            config_children.append(_pppoe_profiles())

        root = E("edit-config", f'xmlns="{NS_NETCONF}" xmlns:nc="{NS_NETCONF}"', children=[
            E("target", None, children=[E("candidate", None, children=[])]),
            E("test-option", None, text="test-then-set"),
            E("error-option", None, text="rollback-on-error"),
            E("config", None, children=config_children),
        ])

        out = []
        render(root, 0, out)
        return "\n".join(out)

    # ─── Remove-service XML RPC builder ─────────────────────────────────────────

    def _build_remove_xml_config(self, p):
        """Deletes only this ONT's own components/interfaces -- shared PON-port
        hardware (cage/port/sfp), the CG/CPart/CPair channel stack, DBA profiles,
        and the VLAN & Uplink infrastructure are left untouched since other ONTs
        may still depend on them."""
        pon_type = p["pon_type"]
        if pon_type == "GPON":
            pon_if = f"gpon{p['pon_slot']}/{p['pon_port']}"
        else:  # XGSPON
            pon_if = f"xgspon{p['pon_slot']}/{p['pon_port']}"

        onu_str = f"onu{p['onu_id']:03d}"
        pfx     = f"{pon_if}_{onu_str}"
        mode    = p["mode"]
        uni_ports = p["uni_ports"]
        rules_per_uni = p["rules_per_uni"]

        if mode == "PPTP":
            uni_configs = [(u, f"{pfx}_eth1_{u}", f"{pfx}_venet1_{u}", f"o_venet1_{u}")
                           for u in uni_ports]
        else:  # VEIP
            uni_configs = [(1, f"{pfx}_veip_1", f"{pfx}_venet1_1", "o_venet1_1")]

        vani = f"{pfx}_vani1_1"
        ani  = f"{pfx}_ani1_1"

        delete_attrs = f'xmlns:nc="{NS_NETCONF}" nc:operation="delete"'

        def deleted(tag, key_tag, name):
            return E(tag, delete_attrs, children=[E(key_tag, None, text=esc(name))])

        # ── Hardware components ─────────────────────────────────────────────
        hw_names = [pfx, f"{pfx}_aniport1_1", f"{pfx}_cage1_1", f"{pfx}_card1", f"{pfx}_sfp1_1"]
        if mode == "PPTP":
            hw_names += [f"{pfx}_uniport1_{u}" for u in uni_ports]
        hw_names.sort()
        hw_nodes = [deleted("component", "name", n) for n in hw_names]

        # ── Interfaces + effective-VLAN → VP-interface names ────────────────
        iface_names = [ani, vani]
        if mode == "PPTP":
            iface_names += [f"{pfx}_eth1_{u}" for u in uni_ports]
        else:
            iface_names.append(f"{pfx}_veip_1")
        iface_names += [olt_lower for _u, _ont_uni_if, olt_lower, _vp_base in uni_configs]

        vp_entries = []  # (effective_vlan, vp_if)
        for idx_u, (_u, ont_uni_if, olt_lower, vp_base) in enumerate(uni_configs):
            for rule in rules_per_uni[idx_u]:
                rvlan = rule["vlan"]
                if rule["type"] == "Untag":
                    subif = f"{ont_uni_if}_c{rvlan:04d}_untag"
                    eff_vlan = rvlan
                else:  # Single Tag
                    rewrite = rule.get("rewrite")
                    eff_vlan = rule["rw_vlan"] if rewrite else rvlan
                    subif = f"{ont_uni_if}_c{eff_vlan:04d}_any"
                iface_names.append(subif)
                vp_if = f"{pfx}_{vp_base}_c{eff_vlan:04d}_any"
                iface_names.append(vp_if)
                vp_entries.append((eff_vlan, vp_if))

        iface_names = sorted(set(iface_names))
        iface_nodes = [deleted("interface", "name", n) for n in iface_names]

        # ── Forwarding: drop only this ONT's port from each VLAN's forwarder ─
        fwd_ports_by_vlan = {}
        for eff_vlan, vp_if in vp_entries:
            fwd_ports_by_vlan.setdefault(eff_vlan, []).append(vp_if)

        forwarder_nodes = []
        for vlan in sorted(fwd_ports_by_vlan):
            port_nodes = [deleted("port", "name", f"fwd_{vp_if}") for vp_if in fwd_ports_by_vlan[vlan]]
            forwarder_nodes.append(E("forwarder", None, children=[
                E("name", None, text=f"fwd.vlan{vlan}.cli.attach"),
                E("ports", None, children=port_nodes),
            ]))

        # ── Link table ───────────────────────────────────────────────────────
        link_from = sorted({ani} | {ont_uni_if for _u, ont_uni_if, _olt_lower, _vp_base in uni_configs})
        link_nodes = [
            E("link-table", delete_attrs, children=[E("from-interface", None, text=esc(f))])
            for f in link_from
        ]

        # ── TCONT / GEM (index-based names; not tied to alloc-id/DBA values) ─
        n_tcont = len(p["tconts"])
        gemport_nodes = [deleted("gemport", "name", f"{pfx}_gem1_{i + 1}") for i in range(n_tcont)]
        tcont_nodes   = [deleted("tcont", "name", f"{pfx}_tcont1_{i + 1}") for i in range(n_tcont)]

        root = E("edit-config", f'xmlns="{NS_NETCONF}" xmlns:nc="{NS_NETCONF}"', children=[
            E("target", None, children=[E("candidate", None, children=[])]),
            E("test-option", None, text="test-then-set"),
            E("error-option", None, text="rollback-on-error"),
            E("config", None, children=[
                E("hardware", f'xmlns="{NS_HW}"', children=hw_nodes),
                E("forwarding", f'xmlns="{NS_FWD}"', children=[
                    E("forwarders", None, children=forwarder_nodes),
                ]),
                E("link-table", f'xmlns="{NS_LINKTABLE}"', children=link_nodes),
                E("interfaces", f'xmlns="{NS_IF}"', children=iface_nodes),
                E("xpongemtcont", f'xmlns="{NS_XPONGEMTCONT}"', children=[
                    E("gemports", None, children=gemport_nodes),
                    E("tconts", None, children=tcont_nodes),
                ]),
            ]),
        ])

        out = []
        render(root, 0, out)
        return "\n".join(out)

    # ─── Preview with basic XML highlighting ───────────────────────────────────

    def _show_preview(self, text, widget=None):
        widget = widget or self.preview
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)

        for i, line in enumerate(text.splitlines(), start=1):
            for m in re.finditer(r"</?[A-Za-z0-9:_-]+", line):
                widget.tag_add("tag", f"{i}.{m.start()}", f"{i}.{m.end()}")
            for m in re.finditer(r'[A-Za-z0-9:_-]+(?==")', line):
                widget.tag_add("attr", f"{i}.{m.start()}", f"{i}.{m.end()}")

        widget.configure(state="disabled")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    GPONRPCGenerator(root)
    root.mainloop()
