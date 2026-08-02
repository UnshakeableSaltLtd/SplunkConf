import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Rectangle, Wedge, Polygon, Ellipse
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

fig = plt.figure(figsize=(19.2, 10.8), dpi=200)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, 1920); ax.set_ylim(0, 1080)
ax.set_aspect("equal"); ax.axis("off")
ax.add_patch(Rectangle((0, 0), 1920, 1080, facecolor=WHITE, edgecolor="none", zorder=0))

# ---- Title (minimal) ----
ax.text(120, 1005, "The Agentic Detection Loop", fontproperties=F_SEMI, fontsize=36, color=INK, ha="left", va="center")
ax.add_patch(Rectangle((122, 968), 70, 5, facecolor=CISCO_MEDBLUE, edgecolor="none", zorder=3))
ax.add_patch(Rectangle((196, 968), 70, 5, facecolor=SPLUNK_MAGENTA, edgecolor="none", zorder=3))
ax.add_patch(Rectangle((270, 968), 70, 5, facecolor=SPLUNK_ORANGE, edgecolor="none", zorder=3))

leg_y = 995
ax.add_patch(Circle((1610, leg_y), 8, facecolor=CISCO_MEDBLUE, edgecolor="none", zorder=3))
ax.text(1628, leg_y, "Splunk platform", fontproperties=F_REG, fontsize=14, color=MED_GREY, ha="left", va="center")
ax.add_patch(Circle((1610, leg_y - 30), 8, facecolor=SPLUNK_MAGENTA, edgecolor="none", zorder=3))
ax.text(1628, leg_y - 30, "Agentic AI", fontproperties=F_REG, fontsize=14, color=MED_GREY, ha="left", va="center")

CX, CY = 960, 450
RX, RY = 740, 355
N = 9
node_r = 104  # circular icon nodes now, not boxes

stages = [
    dict(n=1, title="Detect",   color=CISCO_MEDBLUE, icon="scan"),
    dict(n=2, title="Alert",    color=CISCO_BLUE,    icon="bell"),
    dict(n=3, title="Invoke",   color=SPLUNK_MAGENTA,icon="bolt"),
    dict(n=4, title="Package",  color=SPLUNK_MAGENTA,icon="envelope"),
    dict(n=5, title="AI Reason",color=SPLUNK_ORANGE, icon="chip"),
    dict(n=6, title="Structure",color=SPLUNK_ORANGE, icon="braces"),
    dict(n=7, title="Deliver",  color=CISCO_BLUE,    icon="tray"),
    dict(n=8, title="Risk Fmt", color=CISCO_MEDBLUE, icon="shield"),
    dict(n=9, title="KV+Analyst",color=CISCO_MEDBLUE,icon="db"),
]

def node_pos(i):
    ang = 90 - i * (360 / N)
    rad = np.radians(ang)
    return CX + RX * np.cos(rad), CY + RY * np.sin(rad)

positions = [node_pos(i) for i in range(N)]

# ---------------------------------------------------------------- icons ----
def icon_scan(ax, x, y, s, c):
    ax.add_patch(Circle((x - s*0.12, y + s*0.12), s*0.34, facecolor="none", edgecolor=c, linewidth=s*0.055, zorder=8))
    ax.add_patch(FancyArrowPatch((x + s*0.14, y - s*0.14), (x + s*0.42, y - s*0.42),
                                  arrowstyle="-", linewidth=s*0.075, color=c, zorder=8))
    ax.add_patch(Circle((x - s*0.12, y + s*0.12), s*0.08, facecolor=c, edgecolor="none", zorder=8))

def icon_bell(ax, x, y, s, c):
    # triangle alert glyph (more universally read as "alert" than a bell silhouette)
    h = s*0.78
    pts = [[x, y + h*0.52], [x - h*0.52, y - h*0.40], [x + h*0.52, y - h*0.40]]
    tri = Polygon(pts, closed=True, facecolor="none", edgecolor=c, linewidth=s*0.075,
                  joinstyle="round", zorder=8)
    ax.add_patch(tri)
    ax.add_patch(Rectangle((x - s*0.045, y - h*0.05), s*0.09, h*0.36, facecolor=c, edgecolor="none", zorder=8))
    ax.add_patch(Circle((x, y - h*0.24), s*0.055, facecolor=c, edgecolor="none", zorder=8))

def icon_bolt(ax, x, y, s, c):
    pts = np.array([
        [0.10, 0.42], [-0.22, 0.02], [-0.02, 0.02], [-0.14, -0.42],
        [0.24, -0.02], [0.04, -0.02]
    ]) * s
    ax.add_patch(Polygon(pts + [x, y], closed=True, facecolor=c, edgecolor="none", zorder=8))

def icon_envelope(ax, x, y, s, c):
    w, h = s*0.78, s*0.52
    ax.add_patch(Rectangle((x - w/2, y - h/2), w, h, facecolor="none", edgecolor=c, linewidth=s*0.06, zorder=8))
    ax.add_patch(Polygon([[x - w/2, y + h/2], [x, y - h*0.05], [x + w/2, y + h/2]],
                          closed=False, edgecolor=c, facecolor="none", linewidth=s*0.06, zorder=8))

def icon_chip(ax, x, y, s, c):
    w = s*0.6
    ax.add_patch(FancyBboxPatch((x - w/2, y - w/2), w, w, boxstyle="round,pad=0,rounding_size=6",
                                 facecolor="none", edgecolor=c, linewidth=s*0.06, zorder=8))
    for dx in (-1, 1):
        for k in (-0.18, 0.18):
            xx = x + dx * (w/2)
            ax.plot([xx, xx + dx*s*0.14], [y + k*s, y + k*s], color=c, linewidth=s*0.05, zorder=8)
            yy = y + dx * (w/2)
            ax.plot([x + k*s, x + k*s], [yy, yy + dx*s*0.14], color=c, linewidth=s*0.05, zorder=8)
    ax.add_patch(Circle((x, y), s*0.07, facecolor=c, edgecolor="none", zorder=8))

def icon_braces(ax, x, y, s, c):
    ax.text(x, y, "{ }", fontproperties=F_BOLD, fontsize=s*0.62, color=c, ha="center", va="center", zorder=8)

def icon_tray(ax, x, y, s, c):
    ax.add_patch(FancyArrowPatch((x, y + s*0.44), (x, y - s*0.02),
                                  arrowstyle="-|>", mutation_scale=s*0.32, linewidth=s*0.07, color=c, zorder=8))
    ax.add_patch(Polygon([[x - s*0.42, y - s*0.30], [x - s*0.30, y - s*0.44], [x + s*0.30, y - s*0.44], [x + s*0.42, y - s*0.30],
                          [x + s*0.42, y - s*0.12], [x - s*0.42, y - s*0.12]],
                          closed=True, facecolor="none", edgecolor=c, linewidth=s*0.06, zorder=8))

def icon_shield(ax, x, y, s, c):
    w, h = s*0.62, s*0.82
    pts = [[x - w/2, y + h*0.42], [x, y + h*0.5], [x + w/2, y + h*0.42],
           [x + w/2, y - h*0.10], [x, y - h*0.5], [x - w/2, y - h*0.10]]
    ax.add_patch(Polygon(pts, closed=True, facecolor="none", edgecolor=c, linewidth=s*0.065, zorder=8))
    ax.plot([x - w*0.18, x - w*0.02, x + w*0.24], [y - h*0.02, y - h*0.18, y + h*0.16],
            color=c, linewidth=s*0.06, zorder=8, solid_capstyle="round")

def icon_db(ax, x, y, s, c):
    w, h = s*0.62, s*0.62
    for dy in (h*0.28, 0, -h*0.28):
        ax.add_patch(Ellipse((x, y + dy), w, h*0.30, facecolor="none", edgecolor=c, linewidth=s*0.055, zorder=8))
    ax.plot([x - w/2, x - w/2], [y - h*0.28, y + h*0.28], color=c, linewidth=s*0.055, zorder=8)
    ax.plot([x + w/2, x + w/2], [y - h*0.28, y + h*0.28], color=c, linewidth=s*0.055, zorder=8)

ICONS = {"scan": icon_scan, "bell": icon_bell, "bolt": icon_bolt, "envelope": icon_envelope,
         "chip": icon_chip, "braces": icon_braces, "tray": icon_tray, "shield": icon_shield, "db": icon_db}

# ---- central hub: simple closed-loop glyph, no body text ----
hub_r = 108
ax.add_patch(Circle((CX, CY), hub_r + 10, facecolor=WHITE, edgecolor=LIGHT_GREY, linewidth=1.25, zorder=4))
ax.add_patch(Circle((CX, CY), hub_r, facecolor="#F7F8FA", edgecolor=MID30, linewidth=1.25, zorder=4))
# classic two-arrow refresh/cycle glyph
loop_r = hub_r * 0.5
for start, end in [(15, 165), (195, 345)]:
    arc = Wedge((CX, CY), loop_r, start, end, width=hub_r*0.13, facecolor=MID70, edgecolor="none", zorder=5)
    ax.add_patch(arc)
    tip_ang = np.radians(end)
    r_mid = loop_r - hub_r*0.065
    tipx, tipy = CX + r_mid*np.cos(tip_ang), CY + r_mid*np.sin(tip_ang)
    ax.plot([tipx], [tipy], marker=(3, 0, end - 90), markersize=11, color=MID70, zorder=6)

# ---- ring connectors ----
for i in range(N):
    x0, y0 = positions[i]; x1, y1 = positions[(i + 1) % N]
    closing = (i == N - 1)
    arr = FancyArrowPatch((x0, y0), (x1, y1), connectionstyle="arc3,rad=0.18",
                           arrowstyle="-|>", mutation_scale=20,
                           lw=2.6 if closing else 2.1,
                           color=MID70 if closing else MID30,
                           linestyle=(0, (7, 5)) if closing else "solid",
                           zorder=2, shrinkA=node_r + 6, shrinkB=node_r + 6)
    ax.add_patch(arr)

x9, y9 = positions[N - 1]; x1n, y1n = positions[0]
mx, my = (x9 + x1n) / 2, (y9 + y1n) / 2
ax.add_patch(Circle((mx, my + 26), 15, facecolor=WHITE, edgecolor=MID70, linewidth=1.4, zorder=7))
ax.text(mx, my + 26, "+", fontproperties=F_BOLD, fontsize=17, color=MID70, ha="center", va="center", zorder=8)

# ---- nodes: circular icon badge + one-word label ----
for i, st in enumerate(stages):
    x, y = positions[i]
    ax.add_patch(Circle((x, y), node_r, facecolor=WHITE, edgecolor=st["color"], linewidth=2.2, zorder=6))
    ICONS[st["icon"]](ax, x, y - 4, node_r * 0.66, st["color"])
    bx, by = x - node_r*0.86, y + node_r*0.80
    ax.add_patch(Circle((bx, by), 15, facecolor=st["color"], edgecolor="none", zorder=7))
    ax.text(bx, by, str(st["n"]), fontproperties=F_BOLD, fontsize=12.5, color=WHITE, ha="center", va="center", zorder=8)
    ax.text(x, y - node_r - 26, st["title"], fontproperties=F_SEMI, fontsize=15.5, color=INK, ha="center", va="center", zorder=8)

# ---- footer ----
ax.text(120, 40, "\u00a9 2026 Cisco and/or its affiliates. All rights reserved.", fontproperties=F_REG,
        fontsize=12, color=MID30, ha="left", va="center")
ax.text(1800, 40, "SEC1215", fontproperties=F_SEMI, fontsize=12, color=MID30, ha="right", va="center")

fig.savefig("/home/user/workspace/diagram/agentic_loop_slide.png", facecolor=WHITE)
print("done")
