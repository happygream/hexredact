"""Builds hexredact brand SVGs with all text converted to paths (JetBrains Mono).

Usage: pip install fonttools brotli && npm pack @fontsource/jetbrains-mono && tar xzf fontsource-*.tgz
       python assets/build_brand.py assets package/files
"""
import sys
from pathlib import Path

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

FONTS = Path(sys.argv[2] if len(sys.argv) > 2 else "fonts")  # dir with @fontsource/jetbrains-mono woff2 files
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

_fonts = {}


def font(weight):
    if weight not in _fonts:
        f = TTFont(FONTS / f"jetbrains-mono-latin-{weight}-normal.woff2")
        _fonts[weight] = (f, f.getGlyphSet(), f.getBestCmap(), f["head"].unitsPerEm)
    return _fonts[weight]


def text_width(s, size, weight=400):
    f, gs, cmap, upm = font(weight)
    return sum(gs[cmap[ord(c)]].width for c in s) * size / upm


def text_path(s, x, y, size, weight=400, anchor="start"):
    """Path data for s with baseline at y."""
    f, gs, cmap, upm = font(weight)
    k = size / upm
    if anchor == "end":
        x -= text_width(s, size, weight)
    elif anchor == "middle":
        x -= text_width(s, size, weight) / 2
    pen = SVGPathPen(gs)
    cx = x
    for c in s:
        g = gs[cmap[ord(c)]]
        g.draw(TransformPen(pen, (k, 0, 0, -k, cx, y)))
        cx += g.width * k
    return pen.getCommands()


def runs(parts, x, y, size, weight=400):
    """parts: [(text, cls)] laid out consecutively -> list of (cls, d)."""
    out = []
    for s, cls in parts:
        if s.strip():
            out.append((cls, text_path(s, x, y, size, weight)))
        x += text_width(s, size, weight)
    return out


# ---- the mark -------------------------------------------------------------
# A pointy-sided hexagon split vertically = "<" and ">" (the token brackets),
# around a solid redaction bar.  Unit box 120 x 104.
def mark(x, y, h, fg_cls="fg", bar_cls="ac"):
    s = h / 104.0
    w = 18  # horizontal stroke width -> ~15.6 perpendicular

    def P(pts):
        return "M" + " L".join(f"{x + px * s:.2f} {y + py * s:.2f}" for px, py in pts) + " Z"

    left = P([(30, 0), (0, 52), (30, 104), (30 + w, 104), (w, 52), (30 + w, 0)])
    right = P([(90, 0), (120, 52), (90, 104), (90 - w, 104), (120 - w, 52), (90 - w, 0)])
    bar = P([(35, 40), (85, 40), (85, 64), (35, 64)])
    return [(fg_cls, left), (fg_cls, right), (bar_cls, bar)]


def mark_width(h):
    return 120 * h / 104.0


# ---- themes ----------------------------------------------------------------
THEMES = {
    "dark": dict(bg="#0a0a0a", fg="#ededed", dim="#6e6e6e", faint="#3a3a3a", ac="#ff4f2e"),
    "light": dict(bg="#fafaf9", fg="#0a0a0a", dim="#76746f", faint="#b3b1ab", ac="#e5401f"),
}


def svg(w, h, shapes, theme, bg=True, title="hexredact"):
    t = THEMES[theme]
    css = " ".join(f".{k}{{fill:{v}}}" for k, v in t.items() if k != "bg")
    body = "\n".join(f'  <path class="{c}" d="{d}"/>' for c, d in shapes)
    rect = f'  <rect width="{w}" height="{h}" fill="{t["bg"]}"/>\n' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'role="img" aria-label="{title}">\n  <title>{title}</title>\n  <style>{css}</style>\n'
            f'{rect}{body}\n</svg>\n')


# ---- banner (README header) -----------------------------------------------
def banner(theme, W=1280, H=320):
    pad = 72
    shapes = []
    mh = 76
    my = 104
    shapes += mark(pad, my, mh)
    wx = pad + mark_width(mh) + 34
    shapes += runs([("hexredact", "fg")], wx, my + 60, 60, 700)
    shapes += runs([("heavy, reversible log redaction", "dim")], wx + 3, my + 106, 19, 400)

    # the transformation, as typography: original line, then hexredact's output
    size = 16
    right = W - pad
    l1 = [("- ", "faint"), ("from ", "dim"), ("10.26.190.67", "dim"), (" port 51234", "dim")]
    l2 = [("+ ", "faint"), ("from ", "dim"), ("<IPV4_PRIV_36d8cc39a6>", "ac"), (" port 51234", "dim")]
    width = max(text_width("".join(s for s, _ in l), size) for l in (l1, l2))
    x0 = right - width
    shapes += runs(l1, x0, my + 34, size)
    shapes += runs(l2, x0, my + 64, size)

    # footer meta
    shapes += runs([("v1.0.0", "faint")], pad, H - 34, 12, 500)
    meta = "MIT  /  stdlib only  /  python 3.9+"
    shapes.append(("faint", text_path(meta, right, H - 34, 12, 500, anchor="end")))
    return svg(W, H, shapes, theme)


# ---- social preview (GitHub repo card, 1280x640) ----------------------------
def social(theme="dark", W=1280, H=640):
    shapes = []
    mh = 120
    total = mark_width(mh) + 44 + text_width("hexredact", 96, 700)
    x = (W - total) / 2
    y = 190
    shapes += mark(x, y, mh)
    shapes += runs([("hexredact", "fg")], x + mark_width(mh) + 44, y + 95, 96, 700)
    shapes.append(("dim", text_path("heavy, reversible log redaction", W / 2, 400, 28, 400, anchor="middle")))
    line = [("from ", "dim"), ("<IPV4_PRIV_36d8cc39a6>", "ac"), (" port 51234", "dim")]
    lw = text_width("".join(s for s, _ in line), 22)
    shapes += runs(line, (W - lw) / 2, 470, 22)
    shapes.append(("faint", text_path("github.com/happygream/hexredact", W / 2, H - 56, 16, 500, anchor="middle")))
    return svg(W, H, shapes, theme)


# ---- standalone mark --------------------------------------------------------
def logo():
    h = 104
    shapes = mark(4, 4, h)
    t, d = THEMES["light"], THEMES["dark"]
    body = "\n".join(f'  <path class="{c}" d="{p}"/>' for c, p in shapes)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="128" height="112" viewBox="0 0 128 112" '
            f'role="img" aria-label="hexredact">\n  <title>hexredact</title>\n'
            f'  <style>.fg{{fill:{t["fg"]}}} .ac{{fill:{t["ac"]}}} '
            f'@media (prefers-color-scheme: dark){{.fg{{fill:{d["fg"]}}} .ac{{fill:{d["ac"]}}}}}</style>\n'
            f'{body}\n</svg>\n')


(OUT / "banner-dark.svg").write_text(banner("dark"))
(OUT / "banner-light.svg").write_text(banner("light"))
(OUT / "social-preview.svg").write_text(social("dark"))
(OUT / "logo.svg").write_text(logo())
print("written", sorted(p.name for p in OUT.iterdir()))
