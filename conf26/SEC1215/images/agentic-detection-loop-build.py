import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Rectangle, Wedge, Polygon, Ellipse, PathPatch
from matplotlib.path import Path
import numpy as np

FDIR = "/home/user/workspace/fonts"
F_LIGHT   = fm.FontProperties(fname=f"{FDIR}/Inter-Light.ttf")
F_REG     = fm.FontProperties(fname=f"{FDIR}/Inter-Regular.ttf")
F_MED     = fm.FontProperties(fname=f"{FDIR}/Inter-Medium.ttf")
F_SEMI    = fm.FontProperties(fname=f"{FDIR}/Inter-SemiBold.ttf")
F_BOLD    = fm.FontProperties(fname=f"{FDIR}/Inter-Bold.ttf")

# ---- Brand palette ----
SPLUNK_MAGENTA = "#FF007F"
SPLUNK_ORANGE  = "#FF9000"
CISCO_BLUE     = "#02C8FF"
CISCO_MEDBLUE  = "#0A60FF"
LIGHT_GREY     = "#D6D6D6"
MED_GREY       = "#6B6B6B"
MID30          = "#B4B9C0"
MID70          = "#525E6C"
WHITE          = "#FFFFFF"
INK            = "#1B1F26"
PAPER          = "#FCFCFD"

fig = plt.figure(figsize=(19.2, 10.8), dpi=200)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, 1920); ax.set_ylim(0, 1080)
ax.set_aspect("equal"); ax.axis("off")
ax.add_patch(Rectangle((0, 0), 1920, 1080, facecolor=PAPER, edgecolor="none", zorder=0))

# ---- Safe zones -----------------------------------------------------------
# No baked-in title / footer text: the PowerPoint slide's own Title placeholder
# sits roughly y=760-1080 (top ~30%) and the master's footer/logo row sits
# roughly y=0-90 (bottom ~8%) on top of this full-bleed picture. Keep all
# artwork clear of both bands so the real PPTX text never collides with it.
SAFE_TOP = 745
SAFE_BOTTOM = 95

# subtle background texture: faint dot grid for "engineered" depth, fully
# inside the safe drawing band only
for gx in range(80, 1921, 80):
    for gy in range(int(SAFE_BOTTOM) + 20, int(SAFE_TOP) - 10, 80):
        ax.add_patch(Circle((gx, gy), 2.0, facecolor=LIGHT_GREY, edgecolor="none", zorder=0.5, alpha=0.55))

# soft vignette ring behind the whole loop for depth (solid tones only, no gradients)
CX, CY = 960, (SAFE_TOP + SAFE_BOTTOM) / 2
for rr, alpha in [(430, 0.05), (400, 0.06), (370, 0.07)]:
    ax.add_patch(Circle((CX, CY), rr, facecolor=MID30, edgecolor="none", zorder=0.6, alpha=alpha))

RX, RY = 810, 233
N = 9
node_r = 84

# Two-color story matching the legend exactly: Cisco Medium Blue for every
# stage that runs natively on the Splunk platform, Splunk Magenta for the
# two stages that are the actual agentic-AI reasoning step (Phase 2).
stages = [
    dict(n=1, title="Detect",     color=CISCO_MEDBLUE,  icon="scan"),
    dict(n=2, title="Alert",      color=CISCO_MEDBLUE,  icon="bell"),
    dict(n=3, title="Invoke",     color=CISCO_MEDBLUE,  icon="bolt"),
    dict(n=4, title="Package",    color=CISCO_MEDBLUE,  icon="envelope"),
    dict(n=5, title="AI Reason",  color=SPLUNK_MAGENTA, icon="chip"),
    dict(n=6, title="Structure",  color=SPLUNK_MAGENTA, icon="braces"),
    dict(n=7, title="Deliver",    color=CISCO_MEDBLUE,  icon="tray"),
    dict(n=8, title="Risk Fmt",   color=CISCO_MEDBLUE,  icon="shield"),
    dict(n=9, title="KV+Analyst", color=CISCO_MEDBLUE,  icon="db"),
]

# Equal-arc-length placement around the ellipse (not equal-angle) so all 9
# nodes read as evenly spaced rings rather than bunching at the left/right
# poles of the wide ellipse. One sample point is pinned exactly to the top
# (90 deg) so node 1 sits dead-center under the title, matching the prior
# layout's visual anchor.
def _ring_positions():
    ts = np.linspace(0, 2 * np.pi, 400001)
    dtheta = ts[1] - ts[0]
    ds = np.sqrt((RX * np.sin(ts)) ** 2 + (RY * np.cos(ts)) ** 2)
    s = np.concatenate([[0], np.cumsum((ds[:-1] + ds[1:]) / 2 * dtheta)])
    total = s[-1]
    s_top = np.interp(np.pi / 2, ts, s)
    targets = (s_top + np.arange(N) * (total / N)) % total
    t_at = np.interp(targets, s, ts)
    raw = [(CX + RX * np.cos(t), CY + RY * np.sin(t)) for t in t_at]
    order = [0, 8, 7, 6, 5, 4, 3, 2, 1]  # clockwise from the top sample
    return [raw[o] for o in order]

positions = _ring_positions()

def shade(hexcolor, amt):
    """Lighten (amt>0) or darken (amt<0) a hex color by amt in [-1,1] — solid tone, not a gradient."""
    h = hexcolor.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    if amt >= 0:
        r = r + (255 - r) * amt; g = g + (255 - g) * amt; b = b + (255 - b) * amt
    else:
        r = r * (1 + amt); g = g * (1 + amt); b = b * (1 + amt)
    return f"#{int(r):02x}{int(g):02x}{int(b):02x}"

# ---------------------------------------------------------------- icons ----
# All icons rendered as bold, filled/solid silhouettes (white on the badge
# color) with a light inset highlight for a touch of dimensionality —
# "iconic" pictograms rather than thin outline glyphs.

def icon_scan(ax, x, y, s, c):
    # magnifying glass — solid ring + handle, filled lens highlight
    ax.add_patch(Circle((x - s*0.10, y + s*0.12), s*0.40, facecolor="none", edgecolor=c, linewidth=s*0.16, zorder=8))
    ax.add_patch(Circle((x - s*0.10, y + s*0.12), s*0.26, facecolor=c, edgecolor="none", zorder=8, alpha=0.28))
    handle = FancyArrowPatch((x + s*0.20, y - s*0.18), (x + s*0.52, y - s*0.50),
                              arrowstyle="-", linewidth=s*0.20, color=c, zorder=8, capstyle="round")
    ax.add_patch(handle)

def icon_bell(ax, x, y, s, c):
    # solid filled alert triangle with exclamation mark cut out in white
    h = s*0.80
    pts = [[x, y + h*0.54], [x - h*0.56, y - h*0.40], [x + h*0.56, y - h*0.40]]
    tri = Polygon(pts, closed=True, facecolor=c, edgecolor="none", joinstyle="round", zorder=8)
    ax.add_patch(tri)
    ax.add_patch(Rectangle((x - s*0.055, y - h*0.06), s*0.11, h*0.34, facecolor=WHITE, edgecolor="none", zorder=9))
    ax.add_patch(Circle((x, y - h*0.26), s*0.065, facecolor=WHITE, edgecolor="none", zorder=9))

def icon_bolt(ax, x, y, s, c):
    pts = np.array([
        [0.12, 0.46], [-0.24, 0.03], [-0.03, 0.03], [-0.16, -0.46],
        [0.26, -0.02], [0.05, -0.02]
    ]) * s
    ax.add_patch(Polygon(pts + [x, y], closed=True, facecolor=c, edgecolor="none", zorder=8))
    ax.add_patch(Polygon((pts * 0.55) + [x - s*0.02, y + s*0.02], closed=True, facecolor=WHITE, edgecolor="none", zorder=9, alpha=0.35))

def icon_envelope(ax, x, y, s, c):
    w, h = s*0.86, s*0.60
    ax.add_patch(FancyBboxPatch((x - w/2, y - h/2), w, h, boxstyle="round,pad=0,rounding_size=4",
                                 facecolor=c, edgecolor="none", zorder=8))
    ax.add_patch(Polygon([[x - w/2 + 3, y + h/2 - 2], [x, y - h*0.06], [x + w/2 - 3, y + h/2 - 2]],
                          closed=False, edgecolor=WHITE, facecolor="none", linewidth=s*0.07, zorder=9))

def icon_chip(ax, x, y, s, c):
    w = s*0.66
    ax.add_patch(FancyBboxPatch((x - w/2, y - w/2), w, w, boxstyle="round,pad=0,rounding_size=6",
                                 facecolor=c, edgecolor="none", zorder=8))
    ax.add_patch(FancyBboxPatch((x - w*0.30, y - w*0.30), w*0.60, w*0.60, boxstyle="round,pad=0,rounding_size=3",
                                 facecolor=WHITE, edgecolor="none", zorder=9, alpha=0.9))
    for dx in (-1, 1):
        for k in (-0.20, 0, 0.20):
            xx = x + dx * (w/2)
            ax.plot([xx, xx + dx*s*0.16], [y + k*s, y + k*s], color=c, linewidth=s*0.075, zorder=8, solid_capstyle="round")
            yy = y + dx * (w/2)
            ax.plot([x + k*s, x + k*s], [yy, yy + dx*s*0.16], color=c, linewidth=s*0.075, zorder=8, solid_capstyle="round")

def icon_braces(ax, x, y, s, c):
    ax.text(x, y, "{ }", fontproperties=F_BOLD, fontsize=s*0.66, color=c, ha="center", va="center", zorder=8)

def icon_tray(ax, x, y, s, c):
    ax.add_patch(FancyArrowPatch((x, y + s*0.48), (x, y - s*0.02),
                                  arrowstyle="-|>", mutation_scale=s*0.42, linewidth=s*0.16, color=c, zorder=8))
    tray = Polygon([[x - s*0.46, y - s*0.30], [x - s*0.32, y - s*0.46], [x + s*0.32, y - s*0.46], [x + s*0.46, y - s*0.30],
                    [x + s*0.46, y - s*0.10], [x - s*0.46, y - s*0.10]],
                   closed=True, facecolor=c, edgecolor="none", zorder=7)
    ax.add_patch(tray)
    ax.add_patch(Rectangle((x - s*0.36, y - s*0.24), s*0.72, s*0.09, facecolor=WHITE, edgecolor="none", zorder=8, alpha=0.5))

def icon_shield(ax, x, y, s, c):
    w, h = s*0.66, s*0.86
    pts = [[x - w/2, y + h*0.42], [x, y + h*0.5], [x + w/2, y + h*0.42],
           [x + w/2, y - h*0.10], [x, y - h*0.5], [x - w/2, y - h*0.10]]
    ax.add_patch(Polygon(pts, closed=True, facecolor=c, edgecolor="none", zorder=8))
    ax.plot([x - w*0.20, x - w*0.03, x + w*0.26], [y - h*0.03, y - h*0.20, y + h*0.18],
            color=WHITE, linewidth=s*0.10, zorder=9, solid_capstyle="round", solid_joinstyle="round")

def icon_db(ax, x, y, s, c):
    w, h = s*0.68, s*0.68
    ax.add_patch(Ellipse((x, y + h*0.30), w, h*0.34, facecolor=c, edgecolor="none", zorder=9))
    ax.add_patch(Rectangle((x - w/2, y - h*0.30), w, h*0.60, facecolor=c, edgecolor="none", zorder=7))
    for dy in (0.06, -0.22):
        ax.add_patch(Ellipse((x, y + h*dy), w, h*0.20, facecolor="none", edgecolor=WHITE, linewidth=s*0.05, zorder=8, alpha=0.6))
    ax.add_patch(Ellipse((x, y - h*0.30), w, h*0.34, facecolor=shade(c, -0.25), edgecolor="none", zorder=8))

ICONS = {"scan": icon_scan, "bell": icon_bell, "bolt": icon_bolt, "envelope": icon_envelope,
         "chip": icon_chip, "braces": icon_braces, "tray": icon_tray, "shield": icon_shield, "db": icon_db}

# ---- central hub: bold filled cycle glyph ----------------------------------
hub_r = 100
ax.add_patch(Circle((CX, CY + 3), hub_r + 14, facecolor=MID30, edgecolor="none", zorder=3, alpha=0.20))
ax.add_patch(Circle((CX, CY), hub_r + 8, facecolor=WHITE, edgecolor=LIGHT_GREY, linewidth=1.25, zorder=4))
ax.add_patch(Circle((CX, CY), hub_r, facecolor=MID70, edgecolor="none", zorder=4))
loop_r = hub_r * 0.52
for start, end in [(15, 165), (195, 345)]:
    arc = Wedge((CX, CY), loop_r, start, end, width=hub_r*0.16, facecolor=WHITE, edgecolor="none", zorder=5)
    ax.add_patch(arc)
    tip_ang = np.radians(end)
    r_mid = loop_r - hub_r*0.08
    tipx, tipy = CX + r_mid*np.cos(tip_ang), CY + r_mid*np.sin(tip_ang)
    ax.plot([tipx], [tipy], marker=(3, 0, end - 90), markersize=13, color=WHITE, zorder=6)

# ---- ring connectors (double-tone for depth, one consistent style all the
# way round so the loop reads as a single continuous cycle) -----------------
for i in range(N):
    x0, y0 = positions[i]; x1, y1 = positions[(i + 1) % N]
    shadow = FancyArrowPatch((x0, y0), (x1, y1), connectionstyle="arc3,rad=0.16",
                              arrowstyle="-", lw=4.6, color=MID30, alpha=0.18,
                              zorder=1.5, shrinkA=node_r + 4, shrinkB=node_r + 4)
    ax.add_patch(shadow)
    arr = FancyArrowPatch((x0, y0), (x1, y1), connectionstyle="arc3,rad=0.16",
                           arrowstyle="-|>", mutation_scale=22, lw=2.2, color=MID30,
                           zorder=2, shrinkA=node_r + 8, shrinkB=node_r + 8)
    ax.add_patch(arr)

# ---- nodes: solid badge, icon + one-word caption + sequence number ---------
for i, st in enumerate(stages):
    x, y = positions[i]
    c = st["color"]
    # drop shadow
    ax.add_patch(Circle((x + 4, y - 6), node_r, facecolor=INK, edgecolor="none", zorder=5.5, alpha=0.13))
    # outer ring (light halo) + solid filled badge
    ax.add_patch(Circle((x, y), node_r + 7, facecolor=WHITE, edgecolor="none", zorder=6))
    ax.add_patch(Circle((x, y), node_r, facecolor=c, edgecolor=shade(c, -0.22), linewidth=1.6, zorder=6.2))
    # subtle inner highlight (upper-left) for dimensional feel — solid tone, not a gradient
    ax.add_patch(Circle((x - node_r*0.30, y + node_r*0.32), node_r*0.62, facecolor=WHITE, edgecolor="none", zorder=6.4, alpha=0.10))
    ICONS[st["icon"]](ax, x, y + node_r*0.22, node_r * 0.58, WHITE)
    ax.text(x, y - node_r*0.52, st["title"], fontproperties=F_SEMI, fontsize=14.5, color=WHITE, ha="center", va="center", zorder=8)
    # sequence badge
    bx, by = x - node_r*0.86, y + node_r*0.80
    ax.add_patch(Circle((bx, by), 16, facecolor=INK, edgecolor=WHITE, linewidth=2, zorder=7))
    ax.text(bx, by, str(st["n"]), fontproperties=F_BOLD, fontsize=13, color=WHITE, ha="center", va="center", zorder=8)

# ---- legend (kept — encodes real meaning, not decoration) ------------------
leg_x, leg_y = 1660, SAFE_TOP - 34
ax.add_patch(Circle((leg_x, leg_y), 8, facecolor=CISCO_MEDBLUE, edgecolor="none", zorder=9))
ax.text(leg_x + 18, leg_y, "Splunk platform", fontproperties=F_REG, fontsize=13.5, color=MED_GREY, ha="left", va="center", zorder=9)
ax.add_patch(Circle((leg_x, leg_y - 30), 8, facecolor=SPLUNK_MAGENTA, edgecolor="none", zorder=9))
ax.text(leg_x + 18, leg_y - 30, "Agentic AI", fontproperties=F_REG, fontsize=13.5, color=MED_GREY, ha="left", va="center", zorder=9)

fig.savefig("/home/user/workspace/diagram/agentic_loop_slide.png", facecolor=PAPER)
print("done")
