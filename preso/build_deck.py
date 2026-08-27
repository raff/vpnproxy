#!/usr/bin/env python3
"""Generates vpnproxy_overview.pptx (requires: pip install python-pptx)."""

import os

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vpnproxy_overview.pptx")

# ---- palette ----
INK = RGBColor(0x16, 0x1B, 0x22)      # near-black
SLATE = RGBColor(0x4A, 0x55, 0x63)    # muted body gray-blue
PAPER = RGBColor(0xFF, 0xFF, 0xFF)
BG = RGBColor(0xF7, 0xF8, 0xFA)
ACCENT = RGBColor(0x2E, 0x6B, 0x5E)   # tunnel green (WireGuard-ish, calm teal-green)
ACCENT_DK = RGBColor(0x1E, 0x47, 0x3F)
WARN = RGBColor(0xB0, 0x45, 0x2E)     # terracotta for "system VPN" contrast column
LINE = RGBColor(0xDD, 0xE1, 0xE6)
CODE_BG = RGBColor(0x16, 0x1B, 0x22)
CODE_FG = RGBColor(0xE3, 0xE8, 0xEE)

SW, SH = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width = SW
prs.slide_height = SH
blank = prs.slide_layouts[6]

FONT_HEAD = "Georgia"
FONT_BODY = "Avenir Next"
FONT_MONO = "Menlo"


def add_slide():
    return prs.slides.add_slide(blank)


def fill_bg(slide, color=BG):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, SH)
    bg.fill.solid()
    bg.fill.fore_color.rgb = color
    bg.line.fill.background()
    bg.shadow.inherit = False
    # send to back
    sp = bg._element
    sp.getparent().remove(sp)
    slide.shapes._spTree.insert(2, sp)
    return bg


def add_rect(slide, x, y, w, h, color, line_color=None, line_w=None):
    r = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    r.fill.solid()
    r.fill.fore_color.rgb = color
    if line_color is None:
        r.line.fill.background()
    else:
        r.line.color.rgb = line_color
        r.line.width = line_w or Pt(0.75)
    r.shadow.inherit = False
    return r


def add_text(slide, x, y, w, h, text, size=18, color=INK, bold=False, italic=False,
             font=FONT_BODY, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, line_spacing=1.0,
             space_after=0):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = 0
    tf.margin_right = 0
    tf.margin_top = 0
    tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = align
    p.line_spacing = line_spacing
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.bold = bold
    run.font.italic = italic
    run.font.name = font
    return tb


def add_bullets(slide, x, y, w, h, items, size=15, color=SLATE, font=FONT_BODY,
                 line_spacing=1.15, space_after=10, bullet_color=ACCENT, bold_lead=True):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = 0
    tf.margin_right = 0
    tf.margin_top = 0
    tf.margin_bottom = 0
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.line_spacing = line_spacing
        p.space_after = Pt(space_after)
        lead, _, rest = item.partition("|")
        r0 = p.add_run()
        r0.text = "―  "
        r0.font.size = Pt(size)
        r0.font.color.rgb = bullet_color
        r0.font.name = font
        r0.font.bold = True
        if rest:
            r1 = p.add_run()
            r1.text = lead
            r1.font.size = Pt(size)
            r1.font.color.rgb = INK
            r1.font.name = font
            r1.font.bold = bold_lead
            r2 = p.add_run()
            r2.text = " — " + rest.strip()
            r2.font.size = Pt(size)
            r2.font.color.rgb = color
            r2.font.name = font
        else:
            r1 = p.add_run()
            r1.text = lead
            r1.font.size = Pt(size)
            r1.font.color.rgb = color
            r1.font.name = font
    return tb


def add_kicker(slide, text, x=Inches(0.7), y=Inches(0.5)):
    add_text(slide, x, y, Inches(6), Inches(0.35), text.upper(), size=13, color=ACCENT,
              bold=True, font=FONT_BODY)


def add_footer(slide, n):
    add_text(slide, Inches(0.7), Inches(7.08), Inches(6), Inches(0.3), "vpnproxy",
              size=10, color=SLATE, font=FONT_BODY)
    add_text(slide, Inches(12.0), Inches(7.08), Inches(0.63), Inches(0.3), str(n),
              size=10, color=SLATE, font=FONT_BODY, align=PP_ALIGN.RIGHT)


def code_block(slide, x, y, w, h, lines, size=13):
    box = add_rect(slide, x, y, w, h, CODE_BG)
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.25)
    tf.margin_right = Inches(0.2)
    tf.margin_top = Inches(0.18)
    tf.margin_bottom = Inches(0.18)
    for i, ln in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.line_spacing = 1.25
        r = p.add_run()
        r.text = ln
        r.font.size = Pt(size)
        r.font.name = FONT_MONO
        r.font.color.rgb = CODE_FG
    return box


def accent_bar(slide, y=Inches(1.0)):
    add_rect(slide, Inches(0.7), y, Inches(0.6), Pt(4), ACCENT)


# =====================================================================
# Slide 1 — Title
# =====================================================================
s = add_slide()
fill_bg(s, INK)
add_rect(s, 0, 0, Inches(0.22), SH, ACCENT)
add_text(s, Inches(0.95), Inches(2.55), Inches(11.5), Inches(0.4), "PROXY ARCHITECTURE",
          size=14, color=RGBColor(0x9C, 0xC7, 0xBC), bold=True, font=FONT_BODY)
add_text(s, Inches(0.9), Inches(2.95), Inches(11.6), Inches(1.5), "vpnproxy",
          size=64, color=PAPER, bold=True, font=FONT_HEAD)
add_text(s, Inches(0.95), Inches(4.15), Inches(10.8), Inches(1.0),
          "Scoping a WireGuard tunnel to a single hostname, without a system VPN",
          size=20, color=RGBColor(0xC8, 0xCE, 0xD6), font=FONT_BODY, italic=True)
add_text(s, Inches(0.95), Inches(6.7), Inches(8), Inches(0.4),
          "macOS  ·  single static Go binary  ·  no helper process",
          size=13, color=RGBColor(0x7C, 0x8A, 0x99), font=FONT_MONO)

# =====================================================================
# Slide 2 — The problem
# =====================================================================
s = add_slide()
fill_bg(s)
add_kicker(s, "The Problem")
add_text(s, Inches(0.7), Inches(0.85), Inches(11.5), Inches(0.9),
          "Testing a region-gated service means you’d need a VPN", size=30, bold=True, font=FONT_HEAD)
accent_bar(s, Inches(1.75))

add_bullets(s, Inches(0.7), Inches(2.1), Inches(5.7), Inches(4.5), [
    "The scenario|You need to reach one internal or region-gated service (e.g. an “Italy only” endpoint) as if you were there.",
    "The obvious fix|Connect a full VPN client and let it take over routing.",
    "The catch|A system VPN redirects every connection on the machine — internal tools that expect to see you as a local, trusted user now see a foreign IP instead.",
], size=16, space_after=16)

add_rect(s, Inches(6.9), Inches(2.1), Inches(5.7), Inches(4.5), PAPER, LINE, Pt(1))
add_text(s, Inches(7.2), Inches(2.35), Inches(5.1), Inches(0.4), "SYSTEM VPN, ALL TRAFFIC", size=13,
          color=WARN, bold=True)
rows = [
    "Browser → region-gated service",
    "curl → internal staging API",
    "Slack, email, package managers…",
]
yy = Inches(3.0)
for label in rows:
    add_rect(s, Inches(7.2), yy, Inches(0.16), Inches(0.16), WARN)
    add_text(s, Inches(7.5), yy - Inches(0.03), Inches(4.4), Inches(0.35), label, size=14, color=SLATE)
    yy += Inches(0.55)
add_text(s, Inches(7.2), Inches(5.0), Inches(5.1), Inches(1.3),
          "Every one of these now exits through the VPN — including the internal tools that need to see you as local.",
          size=13.5, color=SLATE, italic=True, line_spacing=1.2)
add_footer(s, 2)

# =====================================================================
# Slide 3 — What vpnproxy does instead
# =====================================================================
s = add_slide()
fill_bg(s)
add_kicker(s, "The Idea")
add_text(s, Inches(0.7), Inches(0.85), Inches(11.5), Inches(0.9),
          "Scope the tunnel to exactly one hostname", size=30, bold=True, font=FONT_HEAD)
accent_bar(s, Inches(1.75))

steps = [
    ("1", "/etc/hosts override", "The masqueraded hostname is pointed at 127.0.0.1 — only that name's traffic ever reaches vpnproxy."),
    ("2", "Sniff the real hostname", "vpnproxy reads the TLS ClientHello SNI (port 443) or the HTTP Host: header (port 80) — exactly what the client put on the wire."),
    ("3", "Resolve and relay through the tunnel", "The hostname is resolved via the WireGuard peer's own DNS, then the TCP connection is relayed through the tunnel to the real origin."),
]
x = Inches(0.7)
w = Inches(3.8)
gap = Inches(0.15)
for i, (num, title, desc) in enumerate(steps):
    cx = x + i * (w + gap)
    add_rect(s, cx, Inches(2.15), w, Inches(3.9), PAPER, LINE, Pt(1))
    add_rect(s, cx + Inches(0.3), Inches(2.5), Inches(0.55), Inches(0.55), ACCENT)
    add_text(s, cx + Inches(0.3), Inches(2.5), Inches(0.55), Inches(0.55), num, size=22, color=PAPER,
              bold=True, align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    add_text(s, cx + Inches(0.3), Inches(3.3), w - Inches(0.6), Inches(0.7), title, size=17, bold=True,
              font=FONT_HEAD)
    add_text(s, cx + Inches(0.3), Inches(4.05), w - Inches(0.6), Inches(1.9), desc, size=13.5, color=SLATE,
              line_spacing=1.25)
    if i < 2:
        add_text(s, cx + w, Inches(3.9), gap, Inches(0.5), "→", size=20, color=ACCENT,
                  align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)

add_text(s, Inches(0.7), Inches(6.25), Inches(11.9), Inches(0.7),
          "Nothing else on the machine ever touches the tunnel — every other connection routes normally.",
          size=14.5, color=ACCENT_DK, italic=True, bold=True)
add_footer(s, 3)

# =====================================================================
# Slide 4 — Implementation details
# =====================================================================
s = add_slide()
fill_bg(s)
add_kicker(s, "Implementation")
add_text(s, Inches(0.7), Inches(0.85), Inches(11.5), Inches(0.9),
          "Raising the tunnel without becoming a system VPN", size=30, bold=True, font=FONT_HEAD)
accent_bar(s, Inches(1.75))

add_bullets(s, Inches(0.7), Inches(2.15), Inches(6.0), Inches(4.8), [
    "Real kernel interface|a utun(4) device — the same primitive wg-quick uses on macOS — plus a userspace wireguard-go process.",
    "Interface-scoped route|route -ifscope, not a default route: invisible to route get default and to every other process.",
    "Per-socket pinning|every relay and DNS socket is explicitly bound via IP_BOUND_IF / IPV6_BOUND_IF — this, plus the scoped route, is what actually forces traffic through the tunnel.",
    "Handshake gate|polls the WireGuard UAPI (last_handshake_time_sec) until a peer actually answers before relaying or resolving anything.",
    "Hand-rolled DNS|queries built with dns/dnsmessage and sent over a UDP socket bound to the tunnel — bypassing net.Resolver, which checks /etc/hosts before dialing and would just loop back to 127.0.0.1.",
], size=14, space_after=13)

code_block(s, Inches(7.05), Inches(2.15), Inches(5.55), Inches(4.85), [
    "$ sudo vpnproxy FR",
    "",
    "raising wireguard tunnel for FR",
    "  from FR.conf",
    "wireguard: handshake completed",
    "  with 198.51.100.7:51820",
    "  (allowed ips: [0.0.0.0/0 ::/0])",
    "relaying 127.0.0.1:443 -> sniffed",
    "  SNI/Host (via tunnel)",
    "",
    "127.0.0.1:54321",
    "  (sniffed=adobeid-na1-stg1",
    "   .services.adobe.com)",
    "  -> 10.2.0.5:443:",
    "  connected through tunnel",
], size=12.5)
add_footer(s, 4)

# =====================================================================
# Slide 5 — Dumb relay, not a proxy
# =====================================================================
s = add_slide()
fill_bg(s)
add_kicker(s, "The Relay")
add_text(s, Inches(0.7), Inches(0.85), Inches(11.5), Inches(0.9),
          "A dumb TCP byte copy — not an HTTP or TLS proxy", size=30, bold=True, font=FONT_HEAD)
accent_bar(s, Inches(1.75))

add_bullets(s, Inches(0.7), Inches(2.15), Inches(11.9), Inches(3.6), [
    "No rewriting|the client already sent the real hostname on the wire (SNI or Host:), so the origin sees exactly what it would see without /etc/hosts in the picture.",
    "TLS passes through untouched|vpnproxy never terminates or decrypts it — it flows end to end between client and real origin.",
    "DNS answers are cached|clamped to the record's TTL (5s–5min), so sniffing a hostname on every connection doesn't mean a DNS round trip through the tunnel each time.",
], size=16, space_after=16)

add_rect(s, Inches(0.7), Inches(6.0), Inches(11.9), Pt(1.2), LINE)
add_text(s, Inches(0.7), Inches(6.2), Inches(11.9), Inches(0.9),
          "Because privileges are never split — the whole process already runs under sudo — there's no separate helper: the interface is created and configured directly, in-process.",
          size=13.5, color=SLATE, italic=True, line_spacing=1.2)
add_footer(s, 5)

# =====================================================================
# Slide 6 — vpnproxy vs system VPN
# =====================================================================
s = add_slide()
fill_bg(s)
add_kicker(s, "Comparison")
add_text(s, Inches(0.7), Inches(0.85), Inches(11.5), Inches(0.9),
          "vpnproxy vs. a full system VPN", size=30, bold=True, font=FONT_HEAD)
accent_bar(s, Inches(1.75))

col_x = Inches(0.7)
row_h = Inches(0.62)
top = Inches(2.05)
LBL_W = Inches(3.0)
MINE_W = Inches(4.15)
SYS_W = Inches(4.75)

# header row
add_rect(s, col_x, top, LBL_W, row_h, BG)
add_rect(s, col_x + LBL_W, top, MINE_W, row_h, INK)
add_text(s, col_x + LBL_W + Inches(0.25), top, MINE_W - Inches(0.4), row_h, "vpnproxy", size=16, bold=True,
          color=PAPER, anchor=MSO_ANCHOR.MIDDLE, font=FONT_HEAD)
add_rect(s, col_x + LBL_W + MINE_W, top, SYS_W, row_h, WARN)
add_text(s, col_x + LBL_W + MINE_W + Inches(0.25), top, SYS_W - Inches(0.4), row_h, "System VPN (wg-quick, etc.)",
          size=16, bold=True, color=PAPER, anchor=MSO_ANCHOR.MIDDLE, font=FONT_HEAD)

rows = [
    ("Scope of traffic redirected", "Exactly one hostname", "Every connection on the machine"),
    ("Default route", "Untouched — interface-scoped route only", "Replaced with the tunnel as default"),
    ("DNS", "Only the sniffed hostname resolves via tunnel", "Usually rewritten to the VPN's resolver"),
    ("Socket binding", "Explicit IP_BOUND_IF per relay/DNS socket", "Kernel-wide routing change"),
    ("Other apps / internal tools", "See your real network, unaffected", "See the VPN exit IP too — breaks internal checks"),
    ("Moving parts", "Single static binary, no helper process", "Client + system network config changes"),
]

y = top + row_h
for i, (feature, mine, sysvpn) in enumerate(rows):
    rowbg = PAPER if i % 2 == 0 else RGBColor(0xF0, 0xF2, 0xF4)
    add_rect(s, col_x, y, LBL_W, row_h, BG, LINE, Pt(0.5))
    add_rect(s, col_x + LBL_W, y, MINE_W, row_h, rowbg, LINE, Pt(0.5))
    add_rect(s, col_x + LBL_W + MINE_W, y, SYS_W, row_h, rowbg, LINE, Pt(0.5))
    add_text(s, col_x + Inches(0.2), y, LBL_W - Inches(0.35), row_h, feature, size=12.5, bold=True, color=INK,
              anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.0)
    add_text(s, col_x + LBL_W + Inches(0.25), y, MINE_W - Inches(0.4), row_h, mine, size=12.5, color=ACCENT_DK,
              anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.0)
    add_text(s, col_x + LBL_W + MINE_W + Inches(0.25), y, SYS_W - Inches(0.4), row_h, sysvpn, size=12.5,
              color=RGBColor(0x7A, 0x30, 0x20), anchor=MSO_ANCHOR.MIDDLE, line_spacing=1.0)
    y += row_h

add_footer(s, 6)

prs.save(OUTPUT)
print(f"saved {OUTPUT}")
