"""Builds docs/FileVow_Project_Manual.pdf from the markdown-like source files in this folder.

Usage:  python docs/manual/build_manual.py
Source: docs/manual/0*.md, concatenated in filename order.

Supported markup
  # Title            chapter (new page, TOC level 0)
  ## Title           section (TOC level 1)
  ### Title          sub-section
  #### Title         small heading
  paragraph text     **bold**, *italic*, `code`
  - item / 1. item   bullet / numbered lists (indent 2 spaces for a nested bullet)
  | a | b |          pipe tables (second row of dashes is skipped)
  ```                fenced code block
  > text             callout box ("> NOTE:", "> WARNING:", "> KEY IDEA:" set the colour)
  [[DIAGRAM:name]]   a drawn diagram (architecture | layers | lifecycle)
  [[PAGEBREAK]]      force a new page
"""
import glob
import os
import re

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Flowable, Frame, KeepTogether,
                                NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer,
                                Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "FileVow_Project_Manual.pdf")
FONTS = r"C:\Windows\Fonts"

# ---------------------------------------------------------------- fonts
pdfmetrics.registerFont(TTFont("Body", os.path.join(FONTS, "segoeui.ttf")))
pdfmetrics.registerFont(TTFont("Body-B", os.path.join(FONTS, "segoeuib.ttf")))
pdfmetrics.registerFont(TTFont("Body-I", os.path.join(FONTS, "segoeuii.ttf")))
pdfmetrics.registerFont(TTFont("Body-BI", os.path.join(FONTS, "segoeuiz.ttf")))
pdfmetrics.registerFont(TTFont("Body-L", os.path.join(FONTS, "segoeuil.ttf")))
pdfmetrics.registerFont(TTFont("Mono", os.path.join(FONTS, "consola.ttf")))
pdfmetrics.registerFont(TTFont("Mono-B", os.path.join(FONTS, "consolab.ttf")))
pdfmetrics.registerFontFamily("Body", normal="Body", bold="Body-B", italic="Body-I", boldItalic="Body-BI")
pdfmetrics.registerFontFamily("Mono", normal="Mono", bold="Mono-B", italic="Mono", boldItalic="Mono-B")

# ---------------------------------------------------------------- palette
INK = colors.HexColor("#1F2328")
MUTED = colors.HexColor("#59636E")
ACCENT = colors.HexColor("#1F4E79")
ACCENT_LIGHT = colors.HexColor("#E8F0F8")
RULE = colors.HexColor("#D0D7DE")
CODE_BG = colors.HexColor("#F6F8FA")
CODE_INK = colors.HexColor("#24292F")
INLINE_CODE = colors.HexColor("#8B2252")
CALLOUTS = {
    "NOTE": (colors.HexColor("#E8F0F8"), colors.HexColor("#1F4E79")),
    "KEY IDEA": (colors.HexColor("#EAF5EA"), colors.HexColor("#2D6A2E")),
    "WARNING": (colors.HexColor("#FDF1E4"), colors.HexColor("#9A5B13")),
    "SECURITY": (colors.HexColor("#FBEAEA"), colors.HexColor("#8E2424")),
    "EXAMPLE": (colors.HexColor("#F2EEF9"), colors.HexColor("#4B3A8C")),
}

PAGE_W, PAGE_H = A4
MARGIN_X = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

# ---------------------------------------------------------------- styles
body = ParagraphStyle("body", fontName="Body", fontSize=10, leading=14.6, textColor=INK,
                      spaceAfter=6.5, alignment=TA_LEFT)
h1 = ParagraphStyle("h1", fontName="Body-B", fontSize=21, leading=26, textColor=ACCENT,
                    spaceBefore=0, spaceAfter=12)
h1num = ParagraphStyle("h1num", fontName="Body-L", fontSize=11, leading=14, textColor=MUTED,
                       spaceAfter=2)
h2 = ParagraphStyle("h2", fontName="Body-B", fontSize=14.5, leading=19, textColor=ACCENT,
                    spaceBefore=13, spaceAfter=6)
h3 = ParagraphStyle("h3", fontName="Body-B", fontSize=11.5, leading=15.5, textColor=INK,
                    spaceBefore=9, spaceAfter=4)
h4 = ParagraphStyle("h4", fontName="Body-B", fontSize=10, leading=14, textColor=MUTED,
                    spaceBefore=6, spaceAfter=3)
bullet = ParagraphStyle("bullet", parent=body, leftIndent=14, bulletIndent=3, spaceAfter=3)
bullet2 = ParagraphStyle("bullet2", parent=body, leftIndent=28, bulletIndent=17, spaceAfter=2.5)
cell = ParagraphStyle("cell", fontName="Body", fontSize=8.7, leading=11.6, textColor=INK)
cell_h = ParagraphStyle("cellh", parent=cell, fontName="Body-B", textColor=colors.white)
code = ParagraphStyle("code", fontName="Mono", fontSize=8.2, leading=10.6, textColor=CODE_INK)
callout = ParagraphStyle("callout", parent=body, fontSize=9.6, leading=13.8, spaceAfter=0)
toc0 = ParagraphStyle("toc0", fontName="Body-B", fontSize=11, leading=15, leftIndent=0,
                      textColor=ACCENT, spaceBefore=9, spaceAfter=1)
toc1 = ParagraphStyle("toc1", fontName="Body-B", fontSize=9.8, leading=13.5, leftIndent=12,
                      textColor=INK, spaceBefore=3)
toc2 = ParagraphStyle("toc2", fontName="Body", fontSize=8.8, leading=11.6, leftIndent=26,
                      textColor=MUTED)
part_style = ParagraphStyle("part", fontName="Body-B", fontSize=30, leading=36, textColor=ACCENT,
                            alignment=TA_CENTER)
part_sub = ParagraphStyle("partsub", fontName="Body-L", fontSize=13, leading=18, textColor=MUTED,
                          alignment=TA_CENTER)


# ---------------------------------------------------------------- inline markup
def inline(text):
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    parts = re.split(r"(`[^`]+`)", text)
    out = []
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append('<font name="Mono" size="8.8" color="#8B2252">%s</font>' % p[1:-1])
        else:
            p = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", p)
            p = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", p)
            out.append(p)
    return "".join(out)


# ---------------------------------------------------------------- custom flowables
class Heading(Paragraph):
    """Paragraph that registers itself in the TOC and PDF outline."""

    def __init__(self, text, style, level, key, toc_text=None):
        super().__init__(text, style)
        self.toc_level = level
        self.toc_key = key
        self.toc_text = toc_text or re.sub(r"<[^>]+>", "", text)


def code_block(lines):
    wrapped = []
    for ln in lines:
        ln = ln.rstrip("\n").replace("\t", "    ")
        while len(ln) > 100:
            wrapped.append(ln[:100])
            ln = "    " + ln[100:]
        wrapped.append(ln)
    chunks, size = [], 48
    for i in range(0, len(wrapped), size):
        chunks.append(wrapped[i:i + size])
    flows = []
    for ch in chunks:
        esc = "<br/>".join((l.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                            .replace(" ", "&nbsp;")) or "&nbsp;" for l in ch)
        t = Table([[Paragraph(esc, code)]], colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, RULE),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        flows.append(t)
    flows.append(Spacer(1, 7))
    return flows


def make_table(rows):
    ncols = max(len(r) for r in rows)
    rows = [r + [""] * (ncols - len(r)) for r in rows]
    weights = []
    for c in range(ncols):
        lens = [len(r[c]) for r in rows]
        longest = max(lens)
        avg = sum(lens) / len(lens)
        weights.append(max(7.0, min(48.0, 0.55 * longest + 0.45 * avg)))
    # minimum width = longest unbreakable word in the column (so words never split)
    mins = []
    for c in range(ncols):
        longest = 0.0
        for ri, r in enumerate(rows):
            font = "Body-B" if ri == 0 else "Body"
            for word in re.sub(r"[`*]", "", r[c]).split():
                longest = max(longest, pdfmetrics.stringWidth(word, font, 8.7) * 1.04)
        mins.append(min(longest + 11, CONTENT_W * 0.42))
    widths = [CONTENT_W * w / sum(weights) for w in weights]
    for _ in range(ncols):
        short = [c for c in range(ncols) if widths[c] < mins[c] - 0.1]
        if not short:
            break
        fixed = {c: mins[c] for c in short}
        for c in range(ncols):
            if widths[c] <= mins[c]:
                fixed[c] = mins[c]
        free = [c for c in range(ncols) if c not in fixed]
        room = CONTENT_W - sum(fixed.values())
        fw = sum(weights[c] for c in free) or 1
        widths = [fixed[c] if c in fixed else room * weights[c] / fw for c in range(ncols)]
    if sum(widths) > CONTENT_W:
        widths = [w * CONTENT_W / sum(widths) for w in widths]
    data = [[Paragraph(inline(x), cell_h) for x in rows[0]]]
    for r in rows[1:]:
        data.append([Paragraph(inline(x), cell) for x in r])
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F7F9FB")))
    t.setStyle(TableStyle(style))
    return [t, Spacer(1, 8)]


def make_callout(lines):
    text = " ".join(l.strip() for l in lines)
    kind = "NOTE"
    m = re.match(r"^(NOTE|KEY IDEA|WARNING|SECURITY|EXAMPLE):\s*(.*)$", text)
    if m:
        kind, text = m.group(1), m.group(2)
    bg, fg = CALLOUTS[kind]
    label = '<font name="Body-B" color="%s">%s</font>&nbsp;&nbsp;' % (fg.hexval().replace("0x", "#"), kind.title())
    p = Paragraph(label + inline(text), callout)
    t = Table([[p]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 3, fg),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return [t, Spacer(1, 9)]


# ---------------------------------------------------------------- diagrams
def _box(d, x, y, w, h, title, sub=None, fill="#E8F0F8", stroke="#1F4E79"):
    d.add(Rect(x, y, w, h, rx=4, ry=4, fillColor=colors.HexColor(fill),
               strokeColor=colors.HexColor(stroke), strokeWidth=0.8))
    ty = y + h / 2 + (3 if sub else -3)
    d.add(String(x + w / 2, ty, title, fontName="Body-B", fontSize=8.6, textAnchor="middle",
                 fillColor=colors.HexColor("#1F2328")))
    if sub:
        d.add(String(x + w / 2, ty - 11, sub, fontName="Body", fontSize=7.2, textAnchor="middle",
                     fillColor=colors.HexColor("#59636E")))


def _arrow(d, x1, y1, x2, y2, color="#59636E", label=None):
    c = colors.HexColor(color)
    d.add(Line(x1, y1, x2, y2, strokeColor=c, strokeWidth=0.9))
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    s = 5
    p1 = (x2 - s * math.cos(ang - 0.4), y2 - s * math.sin(ang - 0.4))
    p2 = (x2 - s * math.cos(ang + 0.4), y2 - s * math.sin(ang + 0.4))
    d.add(Polygon([x2, y2, p1[0], p1[1], p2[0], p2[1]], fillColor=c, strokeColor=c, strokeWidth=0.5))
    if label:
        d.add(String((x1 + x2) / 2 + 3, (y1 + y2) / 2 + 3, label, fontName="Body", fontSize=6.8,
                     fillColor=colors.HexColor("#59636E")))


def diagram_architecture():
    W, H = CONTENT_W, 332
    d = Drawing(W, H)
    c1, c2, c3, c4 = 8, 114, 240, 380            # column x positions
    w1, w2, w3, w4 = 86, 104, 118, 92            # column widths
    d.add(Rect(2, 100, W - 4, 224, rx=6, ry=6, fillColor=colors.HexColor("#FBFCFD"),
               strokeColor=colors.HexColor("#D0D7DE"), strokeWidth=0.8, strokeDashArray=[3, 2]))
    d.add(String(10, 311, "FileVow agent (Windows service)", fontName="Body-B", fontSize=8.5,
                 fillColor=colors.HexColor("#59636E")))
    _box(d, c1, 244, w1, 40, "Watched files", "disk", fill="#F1EFE8", stroke="#888780")
    _box(d, c2, 266, w2, 34, "Real-time watcher", "watchdog")
    _box(d, c2, 222, w2, 34, "15-min scheduler", "APScheduler")
    _box(d, c3, 240, w3, 44, "Verification engine", "SHA-256 + RSA + mirror")
    _box(d, c4, 240, w4, 44, "Alert manager", "routing, escalation", fill="#FDF1E4", stroke="#9A5B13")
    _box(d, c2, 126, w2, 40, "Mirror vault", "AES-256-GCM copies", fill="#EAF5EA", stroke="#2D6A2E")
    _box(d, c3, 126, w3, 40, "Database", "SQLite / PostgreSQL", fill="#EAF5EA", stroke="#2D6A2E")
    _box(d, c4, 126, w4, 40, "Channels", "email, desktop, chat", fill="#FDF1E4", stroke="#9A5B13")
    _arrow(d, c1 + w1, 270, c2, 283)
    _arrow(d, c1 + w1, 258, c2, 239)
    _arrow(d, c2 + w2, 283, c3, 270)
    _arrow(d, c2 + w2, 239, c3, 254)
    _arrow(d, c3 + w3, 262, c4, 262)
    _arrow(d, c4 + w4 / 2, 240, c4 + w4 / 2, 166)
    _arrow(d, c3 + 22, 240, c2 + w2 - 20, 166)
    _arrow(d, c3 + w3 / 2, 240, c3 + w3 / 2, 166)
    _box(d, c1, 30, w1, 40, "Admin", "browser + MFA", fill="#F1EFE8", stroke="#888780")
    _box(d, c2, 30, w2, 40, "Web dashboard", "review, accept, restore")
    _box(d, c3, 30, w3, 40, "FastAPI server", "REST + WebSocket")
    _arrow(d, c3 + w3 / 2, 126, c3 + w3 / 2, 70)
    _arrow(d, c1 + w1, 50, c2, 50)
    _arrow(d, c3, 50, c2 + w2, 50)
    return d


def diagram_layers():
    W, H = CONTENT_W, 200
    d = Drawing(W, H)
    _box(d, 4, 78, 96, 44, "Integrity record", "from database", fill="#F1EFE8", stroke="#888780")
    _box(d, 128, 140, 132, 44, "Layer 2: RSA check", "is the record genuine?")
    _box(d, 128, 80, 132, 44, "Layer 3: mirror check", "is the copy intact?", fill="#EAF5EA", stroke="#2D6A2E")
    _box(d, 128, 20, 132, 44, "Layer 1: SHA-256 check", "has the file changed?", fill="#FDF1E4", stroke="#9A5B13")
    _arrow(d, 100, 108, 128, 160)
    _arrow(d, 100, 100, 128, 102)
    _arrow(d, 100, 92, 128, 44)
    _box(d, 290, 78, 96, 44, "Decision table", "combine results")
    _arrow(d, 260, 162, 290, 112)
    _arrow(d, 260, 102, 290, 100)
    _arrow(d, 260, 42, 290, 88)
    _box(d, 404, 124, 74, 36, "OK", "all checks pass", fill="#EAF5EA", stroke="#2D6A2E")
    _box(d, 404, 40, 74, 36, "Pending review", "event + alert", fill="#FBEAEA", stroke="#8E2424")
    _arrow(d, 386, 108, 404, 142)
    _arrow(d, 386, 92, 404, 58)
    return d


def diagram_lifecycle():
    W, H = CONTENT_W, 178
    d = Drawing(W, H)
    _box(d, 4, 76, 84, 40, "Detected", "verification run", fill="#F1EFE8", stroke="#888780")
    _box(d, 110, 76, 106, 40, "PENDING_REVIEW", "alert sent", fill="#FDF1E4", stroke="#9A5B13")
    _arrow(d, 88, 96, 110, 96)
    states = [(138, "ACCEPTED", "new signed version", "#EAF5EA", "#2D6A2E"),
              (98, "RESTORED", "mirror copy put back", "#E8F0F8", "#1F4E79"),
              (58, "REJECTED", "false positive", "#F1EFE8", "#888780"),
              (18, "ESCALATED", "more people notified", "#FBEAEA", "#8E2424")]
    for y, t, s, f, st in states:
        _box(d, 250, y, 104, 30, t, s, fill=f, stroke=st)
        _arrow(d, 216, 96, 250, y + 15)
        _arrow(d, 354, y + 15, 388, 96)
    _box(d, 388, 76, 88, 40, "Audit log", "hash-chained entry", fill="#F2EEF9", stroke="#4B3A8C")
    return d


DIAGRAMS = {"architecture": diagram_architecture, "layers": diagram_layers,
            "lifecycle": diagram_lifecycle}


# ---------------------------------------------------------------- parser
def parse(text):
    story = []
    lines = text.split("\n")
    i, n = 0, len(lines)
    chap = 0
    key_seq = [0]

    def key():
        key_seq[0] += 1
        return "k%d" % key_seq[0]

    para_buf = []

    def flush_para():
        if para_buf:
            story.append(Paragraph(inline(" ".join(s.strip() for s in para_buf)), body))
            para_buf.clear()

    while i < n:
        ln = lines[i]
        s = ln.strip()
        if s.startswith("```"):
            flush_para()
            j = i + 1
            buf = []
            while j < n and not lines[j].strip().startswith("```"):
                buf.append(lines[j])
                j += 1
            story.extend(code_block(buf))
            i = j + 1
            continue
        if not s:
            flush_para()
            i += 1
            continue
        if s == "[[PAGEBREAK]]":
            flush_para()
            story.append(PageBreak())
            i += 1
            continue
        m = re.match(r"^\[\[DIAGRAM:(\w+)\]\]$", s)
        if m:
            flush_para()
            story.append(Spacer(1, 4))
            story.append(DIAGRAMS[m.group(1)]())
            story.append(Spacer(1, 10))
            i += 1
            continue
        m = re.match(r"^\[\[PART:(.+?)\|(.+?)\]\]$", s)
        if m:
            flush_para()
            story.append(PageBreak())
            story.append(Spacer(1, 230))
            story.append(Heading(inline(m.group(1)), part_style, 0, key(), toc_text=m.group(1)))
            story.append(Spacer(1, 10))
            story.append(Paragraph(inline(m.group(2)), part_sub))
            i += 1
            continue
        if s.startswith("#### "):
            flush_para()
            story.append(Paragraph(inline(s[5:]), h4))
            i += 1
            continue
        if s.startswith("### "):
            flush_para()
            story.append(CondPageBreak(110))
            story.append(Paragraph(inline(s[4:]), h3))
            i += 1
            continue
        if s.startswith("## "):
            flush_para()
            story.append(CondPageBreak(140))
            story.append(Heading(inline(s[3:]), h2, 2, key()))
            i += 1
            continue
        if s.startswith("# "):
            flush_para()
            chap += 1
            story.append(PageBreak())
            title = s[2:]
            story.append(Paragraph("CHAPTER %d" % chap if not title.startswith("Appendix")
                                   else "APPENDIX", h1num))
            label = title if title.startswith("Appendix") else "%d. %s" % (chap, title)
            if title.startswith("Appendix"):
                chap -= 1
            story.append(Heading(inline(title), h1, 1, key(), toc_text=label))
            story.append(HRule())
            i += 1
            continue
        if s.startswith("|"):
            flush_para()
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in row if c):
                    rows.append(row)
                i += 1
            story.extend(make_table(rows))
            continue
        if s.startswith(">"):
            flush_para()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            story.extend(make_callout(buf))
            continue
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", ln)
        if m and (m.group(2) in "-*" or re.match(r"\d+\.", m.group(2))):
            flush_para()
            indent = len(m.group(1))
            marker = m.group(2)
            txt = m.group(3)
            j = i + 1
            while j < n and lines[j].strip() and not re.match(r"^\s*([-*]|\d+\.)\s+", lines[j]) \
                    and lines[j].startswith("   "):
                txt += " " + lines[j].strip()
                j += 1
            st = bullet2 if indent >= 2 else bullet
            btxt = "\u2022" if marker in "-*" else marker
            story.append(Paragraph(inline(txt), st, bulletText=btxt))
            i = j
            if j < n and not lines[j].strip():
                story.append(Spacer(1, 3))
            continue
        if s.startswith("**") and para_buf:
            flush_para()
        para_buf.append(ln)
        i += 1
    flush_para()
    return story


class HRule(Flowable):
    def __init__(self, width=CONTENT_W, color=RULE):
        super().__init__()
        self.width, self.color = width, color

    def wrap(self, aw, ah):
        return self.width, 10

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(0.8)
        self.canv.line(0, 6, self.width, 6)


# ---------------------------------------------------------------- document
class ManualDoc(BaseDocTemplate):
    def __init__(self, path, **kw):
        super().__init__(path, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X,
                         topMargin=20 * mm, bottomMargin=20 * mm,
                         title="FileVow - File Integrity Monitoring System - Project Manual",
                         author="FileVow Project", subject="Design and implementation manual", **kw)
        frame = Frame(MARGIN_X, 20 * mm, CONTENT_W, PAGE_H - 40 * mm, id="f", leftPadding=0,
                      rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([PageTemplate("cover", [frame], onPage=draw_cover),
                               PageTemplate("normal", [frame], onPage=draw_page)])

    def afterFlowable(self, f):
        if isinstance(f, Heading):
            lvl = f.toc_level
            self.canv.bookmarkPage(f.toc_key)
            self.canv.addOutlineEntry(f.toc_text, f.toc_key, level=lvl, closed=lvl >= 1)
            self.notify("TOCEntry", (lvl, f.toc_text, self.page, f.toc_key))


def draw_cover(c, doc):
    c.saveState()
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - 95 * mm, PAGE_W, 95 * mm, stroke=0, fill=1)
    c.setFillColor(colors.white)
    c.setFont("Body-L", 13)
    c.drawString(MARGIN_X, PAGE_H - 33 * mm, "PROJECT MANUAL")
    c.setFont("Body-B", 44)
    c.drawString(MARGIN_X, PAGE_H - 53 * mm, "FileVow")
    c.setFont("Body-L", 17)
    c.drawString(MARGIN_X, PAGE_H - 65 * mm, "File Integrity Monitoring System")
    c.setFont("Body", 12)
    c.drawString(MARGIN_X, PAGE_H - 78 * mm,
                 "Three-layer verification: SHA-256  \u2022  RSA-PSS signatures  \u2022  Encrypted mirror")
    c.setFillColor(INK)
    c.setFont("Body-B", 12)
    y = PAGE_H - 115 * mm
    c.drawString(MARGIN_X, y, "What this manual covers")
    c.setFont("Body", 10.5)
    items = [
        "Every feature of the system and the reason it exists",
        "How each algorithm works: SHA-256, RSA-PSS, AES-256-GCM, Argon2id, TOTP, JWT",
        "The 15-minute verification engine and its decision table",
        "The mirror vault, the review workflow and the hash-chained audit log",
        "Security hardening and a full threat-model walkthrough",
        "Complete database design, API, dashboard and CLI",
        "Project structure, build roadmap, testing, deployment and viva questions",
    ]
    for it in items:
        y -= 7 * mm
        c.drawString(MARGIN_X + 4 * mm, y, "\u2022  " + it)
    c.setFillColor(MUTED)
    c.setFont("Body", 9)
    c.drawString(MARGIN_X, 22 * mm, "Version 1.0  \u2022  Reference design for implementation in Python 3.11+")
    c.restoreState()


def draw_page(c, doc):
    c.saveState()
    c.setStrokeColor(RULE)
    c.setLineWidth(0.6)
    c.line(MARGIN_X, 14 * mm, PAGE_W - MARGIN_X, 14 * mm)
    c.setFont("Body", 8)
    c.setFillColor(MUTED)
    c.drawString(MARGIN_X, 9.5 * mm, "FileVow \u2014 File Integrity Monitoring System \u2014 Project Manual")
    c.drawRightString(PAGE_W - MARGIN_X, 9.5 * mm, str(doc.page))
    c.restoreState()


def build():
    files = sorted(glob.glob(os.path.join(HERE, "0*.md")))
    text = "\n".join(open(f, encoding="utf-8").read() for f in files)
    toc = TableOfContents()
    toc.levelStyles = [toc0, toc1, toc2]
    toc.dotsMinLevel = 1
    story = [NextPageTemplate("normal"), Spacer(1, 1), PageBreak(),
             Paragraph("Contents", h1), HRule(), Spacer(1, 4), toc]
    story += parse(text)
    doc = ManualDoc(OUT)
    doc.multiBuild(story)
    print("wrote", OUT)


if __name__ == "__main__":
    build()
