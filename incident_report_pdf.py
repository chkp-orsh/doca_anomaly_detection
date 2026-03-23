"""
incident_report_generator.py
Generates a native PDF incident report from an IncidentAnalyzer JSON output.

Dependencies:
    pip install reportlab

Usage:
    python incident_report_generator.py incident_xyz.json --out report.pdf --tenant "Acme Corp"
    python incident_report_generator.py ./results_dir/ --out ./reports/ --tenant "Acme Corp"
"""

from __future__ import annotations
import argparse
import json
import math
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from reportlab.lib import colors
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, PageBreak, KeepTogether, Flowable
    )
    from reportlab.graphics.shapes import Drawing, Rect, Line, String, Circle, Polygon
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
except ImportError:
    print("reportlab not installed. Run: pip install reportlab")
    sys.exit(1)


# =============================================================================
# Colour palette
# =============================================================================

C = {
    "dark":       HexColor("#2c3e50"),
    "mid":        HexColor("#495057"),
    "light":      HexColor("#6c757d"),
    "lighter":    HexColor("#adb5bd"),
    "bg":         HexColor("#f8f9fa"),
    "border":     HexColor("#dee2e6"),
    "blue":       HexColor("#3498db"),
    "blue_light": HexColor("#eaf2ff"),
    "green":      HexColor("#27ae60"),
    "orange":     HexColor("#e67e22"),
    "red":        HexColor("#c0392b"),
    "yellow":     HexColor("#f1c40f"),
    "grey":       HexColor("#95a5a6"),
    "white":      white,
    "black":      black,
}

VERDICT_C = {
    "MALICIOUS":      C["red"],
    "SUSPICIOUS":     C["orange"],
    "BENIGN":         C["green"],
    "FALSE_POSITIVE": C["grey"],
    "UNKNOWN":        C["grey"],
}
SEVERITY_C = {
    "CRITICAL": C["red"],
    "HIGH":     C["orange"],
    "MEDIUM":   C["yellow"],
    "LOW":      C["green"],
    "INFO":     C["blue"],
    "UNKNOWN":  C["grey"],
}
STATUS_C = {
    "ESCALATE": C["red"],
    "OPEN":     C["orange"],
    "MONITOR":  HexColor("#f39c12"),
    "CLOSED":   C["green"],
    "UNKNOWN":  C["grey"],
}
DEPLOY_C = {
    "shadow_ai":     C["red"],
    "enterprise_ai": C["green"],
    "dev_tool":      C["orange"],
    "unknown":       C["grey"],
}

PRIORITY_C = {
    "IMMEDIATE":    C["red"],
    "SHORT_TERM":   C["orange"],
    "INFORMATIONAL": C["blue"],
}
PRIORITY_BG = {
    "IMMEDIATE":    HexColor("#fde8e8"),
    "SHORT_TERM":   HexColor("#fef3e2"),
    "INFORMATIONAL": HexColor("#eaf2ff"),
}


# =============================================================================
# Helpers
# =============================================================================

def _c(mapping: Dict, key: str) -> Any:
    return mapping.get(str(key).upper(), C["grey"])

def _confidence_pct(val) -> int:
    if val is None:
        return 0
    try:
        f = float(val)
        return int(f * 100) if f <= 1.0 else int(f)
    except (TypeError, ValueError):
        return 0

def _fmt_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:,.0f} {unit}"
        n //= 1024
    return f"{n:,.0f} TB"

def _fmt_ts(ts) -> str:
    if not ts:
        return "—"
    try:
        t = int(ts)
        if t > 1e12:
            t //= 1000
        return datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)

def _first_alert_date(report: Dict) -> str:
    anomalies = report.get("anomalies") or []
    timestamps = [
        int(a.get("row_fields", {}).get("timestamp", 0) or 0)
        for a in anomalies
    ]
    ts = min((t for t in timestamps if t > 0), default=0)
    return _fmt_ts(ts) if ts else _fmt_ts(report.get("created_at"))

def _jdump(obj) -> str:
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)

def _trunc(s: str, n: int = 80) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n - 1] + "…"


# =============================================================================
# Custom Flowables
# =============================================================================

class ColorBar(Flowable):
    """A thin full-width coloured rule."""
    def __init__(self, color, height=3, width=None):
        super().__init__()
        self._color  = color
        self._height = height
        self._width  = width

    def wrap(self, aW, aH):
        self._w = self._width or aW
        return self._w, self._height

    def draw(self):
        self.canv.setFillColor(self._color)
        self.canv.rect(0, 0, self._w, self._height, fill=1, stroke=0)


class BadgeFlowable(Flowable):
    """Coloured pill badge."""
    def __init__(self, text: str, bg_color, text_color=white, font_size=9):
        super().__init__()
        self._text  = text
        self._bg    = bg_color
        self._fg    = text_color
        self._fs    = font_size
        self._pad_x = 8
        self._pad_y = 3

    def wrap(self, aW, aH):
        from reportlab.pdfbase.pdfmetrics import stringWidth
        w = stringWidth(self._text, "Helvetica-Bold", self._fs) + self._pad_x * 2
        h = self._fs + self._pad_y * 2
        self._w, self._h = w, h
        return w, h

    def draw(self):
        c = self.canv
        c.setFillColor(self._bg)
        c.roundRect(0, 0, self._w, self._h, radius=4, fill=1, stroke=0)
        c.setFillColor(self._fg)
        c.setFont("Helvetica-Bold", self._fs)
        c.drawCentredString(self._w / 2, self._pad_y + 1, self._text)


class SummaryCardRow(Flowable):
    """
    Row of coloured summary cards: Verdict / Severity / Status / Alert Count.
    """
    def __init__(self, verdict, severity, status, alert_count, width):
        super().__init__()
        self._data   = [
            ("VERDICT",        str(verdict),     _c(VERDICT_C, verdict)),
            ("SEVERITY",       str(severity),    _c(SEVERITY_C, severity)),
            ("STATUS",         str(status),      _c(STATUS_C, status)),
            ("GROUPED ALERTS", str(alert_count), C["dark"]),
        ]
        self._width  = width
        self._height = 60

    def wrap(self, aW, aH):
        return self._width, self._height

    def draw(self):
        c    = self.canv
        n    = len(self._data)
        gap  = 6
        w    = (self._width - gap * (n - 1)) / n
        h    = self._height

        for i, (label, value, color) in enumerate(self._data):
            x = i * (w + gap)
            # Card background
            c.setFillColor(C["bg"])
            c.setStrokeColor(C["border"])
            c.roundRect(x, 0, w, h, radius=6, fill=1, stroke=1)
            # Left accent bar
            c.setFillColor(color)
            c.roundRect(x, 0, 4, h, radius=2, fill=1, stroke=0)
            # Label
            c.setFillColor(C["light"])
            c.setFont("Helvetica", 7)
            c.drawString(x + 10, h - 14, label)
            # Value
            c.setFillColor(color)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(x + 10, 12, value)


class ConfidenceRing(Flowable):
    """SVG-style confidence donut ring."""
    def __init__(self, pct: int, color, size=80):
        super().__init__()
        self._pct   = pct
        self._color = color
        self._size  = size

    def wrap(self, aW, aH):
        return self._size, self._size

    def draw(self):
        c    = self.canv
        cx   = self._size / 2
        cy   = self._size / 2
        r    = self._size * 0.38
        sw   = self._size * 0.10

        # Background ring
        c.setStrokeColor(C["border"])
        c.setLineWidth(sw)
        c.circle(cx, cy, r, fill=0, stroke=1)

        # Filled arc — approximate with many small lines
        if self._pct > 0:
            c.setStrokeColor(self._color)
            c.setLineWidth(sw)
            from math import pi, cos, sin
            steps  = max(int(self._pct * 1.2), 4)
            angle0 = pi / 2                          # start top
            angle1 = pi / 2 - 2 * pi * self._pct / 100
            c.setLineCap(1)
            p = c.beginPath()
            for i in range(steps + 1):
                a   = angle0 + (angle1 - angle0) * i / steps
                px  = cx + r * cos(a)
                py  = cy + r * sin(a)
                if i == 0:
                    p.moveTo(px, py)
                else:
                    p.lineTo(px, py)
            c.drawPath(p, fill=0, stroke=1)

        # Centre text
        c.setFillColor(self._color)
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(cx, cy - 5, f"{self._pct}%")
        c.setFillColor(C["light"])
        c.setFont("Helvetica", 7)
        c.drawCentredString(cx, cy - 16, "confidence")


class NetworkBar(Flowable):
    """Horizontal bar showing sent / received bytes."""
    def __init__(self, sent: int, recv: int, width: float):
        super().__init__()
        self._sent  = sent
        self._recv  = recv
        self._width = width
        self._height = 36

    def wrap(self, aW, aH):
        return self._width, self._height

    def draw(self):
        c    = self.canv
        bar_w = self._width - 80
        mx   = max(self._sent, self._recv, 1)

        # Sent
        c.setFillColor(C["light"])
        c.setFont("Helvetica", 8)
        c.drawString(0, 26, f"↑ Sent: {_fmt_bytes(self._sent)}")
        c.setFillColor(C["border"])
        c.rect(80, 24, bar_w, 8, fill=1, stroke=0)
        c.setFillColor(C["red"])
        c.rect(80, 24, bar_w * self._sent / mx, 8, fill=1, stroke=0)

        # Received
        c.setFillColor(C["light"])
        c.drawString(0, 8, f"↓ Recv: {_fmt_bytes(self._recv)}")
        c.setFillColor(C["border"])
        c.rect(80, 6, bar_w, 8, fill=1, stroke=0)
        c.setFillColor(C["blue"])
        c.rect(80, 6, bar_w * self._recv / mx, 8, fill=1, stroke=0)


class ChainDiagram(Flowable):
    """
    Execution chain: Parent → AI Process → Children → Impact
    Drawn natively with reportlab shapes.
    """
    NODE_W = 130
    NODE_H = 36
    COL_GAP = 50
    ROW_GAP = 52

    def __init__(self, report: Dict, width: float):
        super().__init__()
        self._report = report
        self._width  = width
        self._build()

    def _build(self):
        pc       = self._report.get("process_context") or {}
        parent   = pc.get("parent") or {}
        impact   = self._report.get("impact") or {}
        anomalies = self._report.get("anomalies") or []

        self._parent_name  = _trunc(parent.get("name") or "Unknown Parent", 20)
        self._process_name = _trunc(pc.get("name") or "AI Process", 20)
        self._process_sub  = f"PID {pc.get('pid') or '?'}"

        children: List[str] = []
        for a in anomalies:
            at = str(a.get("anomaly_type") or a.get("type") or "")
            if "SPAWNED" in at:
                cp = a.get("child_process") or (a.get("anomalous_item") or {}).get("process")
                if cp and _trunc(cp, 20) not in children:
                    children.append(_trunc(cp, 20))
        self._children = children[:5]

        impact_nodes: List[str] = []
        if impact.get("data_exfiltration"):
            impact_nodes.append("Data Exfiltration")
        if impact.get("system_modification"):
            impact_nodes.append("File Modification")
        if impact.get("possible_credentials_compromised"):
            impact_nodes.append("Credential Risk")
        net = self._report.get("network_volume") or {}
        bs  = int(net.get("bytes_sent") or 0)
        if bs > 0:
            impact_nodes.append(f"↑ {_fmt_bytes(bs)} sent")
        if not impact_nodes:
            impact_nodes.append("No confirmed impact")
        self._impacts = impact_nodes[:5]

        rows = max(len(self._children), len(self._impacts), 1)
        self._rows = rows
        self._height = max(rows * self.ROW_GAP + 20, self.NODE_H + 20)

    def wrap(self, aW, aH):
        return self._width, self._height

    def _node(self, c, x, y, label, sublabel="",
              fill=None, stroke_color=None, bold=False):
        fill        = fill        or C["bg"]
        stroke_color = stroke_color or C["border"]
        c.setFillColor(fill)
        c.setStrokeColor(stroke_color)
        c.setLineWidth(1.2)
        c.roundRect(x, y, self.NODE_W, self.NODE_H, radius=5, fill=1, stroke=1)
        c.setFillColor(C["dark"] if not bold else stroke_color)
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 8)
        ty = y + self.NODE_H / 2 + (4 if sublabel else 2)
        c.drawCentredString(x + self.NODE_W / 2, ty, label)
        if sublabel:
            c.setFillColor(C["light"])
            c.setFont("Helvetica", 7)
            c.drawCentredString(x + self.NODE_W / 2, y + 5, sublabel)

    def _arrow(self, c, x1, y1, x2, y2):
        c.setStrokeColor(C["lighter"])
        c.setLineWidth(1)
        c.line(x1, y1, x2, y2)
        import math
        angle = math.atan2(y2 - y1, x2 - x1)
        size  = 5
        c.setFillColor(C["lighter"])
        pts = [
            x2, y2,
            x2 - size * math.cos(angle - 0.4), y2 - size * math.sin(angle - 0.4),
            x2 - size * math.cos(angle + 0.4), y2 - size * math.sin(angle + 0.4),
        ]
        p = c.beginPath()
        p.moveTo(pts[0], pts[1])
        p.lineTo(pts[2], pts[3])
        p.lineTo(pts[4], pts[5])
        p.close()
        c.drawPath(p, fill=1, stroke=0)

    def _col_label(self, c, x, y, text):
        c.setFillColor(C["lighter"])
        c.setFont("Helvetica-Oblique", 7)
        c.drawCentredString(x + self.NODE_W / 2, y, text)

    def draw(self):
        c = self.canv
        H = self._height
        NW, NH = self.NODE_W, self.NODE_H
        rows = self._rows

        total_w = self._width
        n_cols  = 4
        col_gap = (total_w - n_cols * NW) / (n_cols - 1)
        cols    = [i * (NW + col_gap) for i in range(n_cols)]

        mid_y  = H / 2 - NH / 2

        def spread(count):
            if count == 1:
                return [H / 2 - NH / 2]
            total = (count - 1) * self.ROW_GAP
            top   = H / 2 + total / 2 - NH / 2
            return [top - i * self.ROW_GAP for i in range(count)]

        label_y = H - 10
        for i, lbl in enumerate(["Parent Process", "AI Agent", "Spawned Children", "Impact"]):
            self._col_label(c, cols[i], label_y, lbl)

        self._node(c, cols[0], mid_y, self._parent_name,
                   fill=HexColor("#e8f4fd"), stroke_color=C["blue"])

        self._arrow(c,
                    cols[0] + NW,   mid_y + NH / 2,
                    cols[1],        mid_y + NH / 2)

        verdict = str(self._report.get("verdict") or "UNKNOWN").upper()
        proc_fill = {
            "MALICIOUS":     HexColor("#fde8e8"),
            "SUSPICIOUS":    HexColor("#fef3e2"),
            "BENIGN":        HexColor("#eafaf1"),
            "FALSE_POSITIVE":C["bg"],
        }.get(verdict, C["bg"])
        self._node(c, cols[1], mid_y,
                   self._process_name, self._process_sub,
                   fill=proc_fill, stroke_color=_c(VERDICT_C, verdict), bold=True)

        child_ys = spread(len(self._children)) if self._children else [mid_y]
        for ch, cy in zip(self._children, child_ys):
            self._arrow(c,
                        cols[1] + NW, mid_y + NH / 2,
                        cols[2],      cy + NH / 2)
            self._node(c, cols[2], cy, ch,
                       fill=HexColor("#fff8e1"), stroke_color=C["orange"])

        if not self._children:
            self._node(c, cols[2], mid_y, "No children",
                       fill=C["bg"], stroke_color=C["border"])

        imp_ys = spread(len(self._impacts))
        ref_ys = child_ys if self._children else [mid_y]
        for ii, (imp, iy) in enumerate(zip(self._impacts, imp_ys)):
            src_y = ref_ys[min(ii, len(ref_ys) - 1)]
            is_bad = any(w in imp for w in ("Exfil", "Cred", "↑"))
            self._arrow(c,
                        cols[2] + NW, src_y + NH / 2,
                        cols[3],      iy + NH / 2)
            self._node(c, cols[3], iy, _trunc(imp, 18),
                       fill=HexColor("#fde8e8") if is_bad else HexColor("#eafaf1"),
                       stroke_color=C["red"] if is_bad else C["green"])


# =============================================================================
# Style helpers
# =============================================================================

def _styles():
    base = getSampleStyleSheet()
    def S(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "h1":           S("h1", fontSize=18, fontName="Helvetica-Bold",
                           textColor=C["dark"], spaceAfter=4),
        "h2":           S("h2", fontSize=12, fontName="Helvetica-Bold",
                           textColor=C["dark"], spaceBefore=14, spaceAfter=6,
                           borderPadding=(0,0,4,0)),
        "h3":           S("h3", fontSize=10, fontName="Helvetica-Bold",
                           textColor=C["mid"], spaceBefore=8, spaceAfter=4),
        "body":         S("body", fontSize=9, leading=14, textColor=C["dark"]),
        "small":        S("small", fontSize=8, textColor=C["light"]),
        "headline":     S("headline", fontSize=11, fontName="Helvetica-Bold",
                           textColor=C["dark"], leading=16,
                           backColor=C["blue_light"],
                           borderPadding=8, spaceAfter=10),
        "mono":         S("mono", fontSize=8, fontName="Courier",
                           textColor=C["mid"], leading=11),
        "action_text":  S("action_text", fontSize=9, fontName="Helvetica-Bold",
                           leading=13, textColor=C["dark"]),
        "action_rationale": S("action_rationale", fontSize=8, fontName="Helvetica-Oblique",
                               leading=12, textColor=C["mid"]),
        "override":     S("override", fontSize=9, leading=13,
                           backColor=HexColor("#fff8e1"),
                           borderPadding=6, spaceAfter=6,
                           textColor=HexColor("#856404")),
    }


def _tbl_style(header_color=None) -> TableStyle:
    hc = header_color or C["dark"]
    return TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), hc),
        ("TEXTCOLOR",   (0, 0), (-1, 0), white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 8),
        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, C["bg"]]),
        ("GRID",        (0, 0), (-1, -1), 0.4, C["border"]),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ])


def _hr(color=None):
    return HRFlowable(width="100%", thickness=0.5,
                      color=color or C["border"], spaceAfter=6)


def _section_title(text: str, st: Dict) -> List:
    return [Paragraph(text, st["h2"]), _hr()]


def _render_actions(actions: List, st: Dict, W: float) -> List:
    """
    Renders recommended_actions as structured cards.
    Handles both new dict format {priority, action, rationale}
    and legacy plain-string format.
    """
    if not actions:
        return []

    PRIORITY_LABEL = {
        "IMMEDIATE":     "⚑  IMMEDIATE",
        "SHORT_TERM":    "●  SHORT TERM",
        "INFORMATIONAL": "ℹ  INFORMATIONAL",
    }

    flowables = []
    for i, a in enumerate(actions, 1):
        # Normalise: accept both dict and plain string
        if isinstance(a, dict):
            priority  = str(a.get("priority") or "IMMEDIATE").upper()
            action    = str(a.get("action") or "")
            rationale = str(a.get("rationale") or "")
        else:
            priority  = "IMMEDIATE"
            action    = str(a)
            rationale = ""

        pri_color  = PRIORITY_C.get(priority, C["grey"])
        pri_bg     = PRIORITY_BG.get(priority, C["bg"])
        pri_label  = PRIORITY_LABEL.get(priority, priority)

        # Badge cell
        badge_para = Paragraph(
            f"<font color='#{pri_color.hexval()[2:]}'><b>{pri_label}</b></font>",
            ParagraphStyle("pri", parent=st["small"], fontSize=7.5,
                           leading=10, textColor=pri_color),
        )

        # Number + action text
        action_para = Paragraph(
            f"<b>{i}.</b>  {action}",
            st["action_text"],
        )

        # Rationale (only if present)
        content_cells = [action_para]
        if rationale:
            content_cells.append(
                Paragraph(f"Why: {rationale}", st["action_rationale"])
            )

        # Inner layout: left accent bar (via colored cell) | content
        card_data = [[badge_para, content_cells]]
        card = Table(
            card_data,
            colWidths=[28*mm, W - 28*mm],
            spaceAfter=5,
        )
        card.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), pri_bg),
            ("BACKGROUND",    (1, 0), (1, 0), white),
            ("BOX",           (0, 0), (-1, -1), 0.8, pri_color),
            ("LINEAFTER",     (0, 0), (0, -1), 1.5, pri_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (0, 0), 6),
            ("RIGHTPADDING",  (0, 0), (0, 0), 6),
            ("LEFTPADDING",   (1, 0), (1, 0), 10),
            ("RIGHTPADDING",  (1, 0), (1, 0), 8),
            ("ROUNDEDCORNERS", [4]),
        ]))
        flowables.append(KeepTogether(card))

    return flowables


# =============================================================================
# Page templates (header / footer)
# =============================================================================

def _make_doc(out_path: str):
    doc = BaseDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title="AI Anomaly Incident Report",
    )
    W, H = A4
    frame = Frame(
        doc.leftMargin, doc.bottomMargin,
        W - doc.leftMargin - doc.rightMargin,
        H - doc.topMargin - doc.bottomMargin,
        id="main",
    )
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame],
                                       onPage=_draw_page_chrome)])
    return doc


_REPORT_META: Dict = {}

def _draw_page_chrome(canvas, doc):
    canvas.saveState()
    W, H = A4
    canvas.setFillColor(C["dark"])
    canvas.rect(0, H - 14*mm, W, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(20*mm, H - 9*mm, "🛡  AI Anomaly Incident Report")
    canvas.setFont("Helvetica", 8)
    tenant = _REPORT_META.get("tenant", "")
    inc_id = _REPORT_META.get("incident_id", "")
    canvas.drawRightString(W - 20*mm, H - 9*mm, f"{tenant}  |  {inc_id}")
    canvas.setFillColor(C["bg"])
    canvas.rect(0, 0, W, 10*mm, fill=1, stroke=0)
    canvas.setFillColor(C["light"])
    canvas.setFont("Helvetica", 7)
    canvas.drawString(20*mm, 4*mm, "Confidential — Security Operations Use Only")
    canvas.drawRightString(W - 20*mm, 4*mm, f"Page {doc.page}")
    canvas.restoreState()


# =============================================================================
# Report builder
# =============================================================================

def build_story(report: Dict, tenant_id: str) -> List:
    st   = _styles()
    W    = A4[0] - 40*mm   # usable width

    verdict  = str(report.get("verdict")  or "UNKNOWN").upper()
    severity = str(report.get("severity") or "UNKNOWN").upper()
    status   = str(report.get("recommended_status") or "OPEN").upper()
    conf_pct = _confidence_pct(report.get("confidence"))
    deploy   = report.get("ai_deployment_type") or {}
    dt       = str(deploy.get("type") or "unknown").lower()
    ai_ctx   = report.get("ai_agent_classification") or report.get("ai_agent_context") or {}
    matched  = ai_ctx.get("matched_artifacts") or []
    impact   = report.get("impact") or {}
    net      = report.get("network_volume") or {}
    bs, br   = int(net.get("bytes_sent") or 0), int(net.get("bytes_received") or 0)
    assets   = report.get("assets") or {}
    pc       = report.get("process_context") or {}
    parent   = pc.get("parent") or {}
    actions  = report.get("recommended_actions") or []
    findings = report.get("key_findings") or []
    mitre    = report.get("mitre_attack") or []
    grouped  = report.get("grouped_alerts") or []
    ga_count = report.get("grouped_alerts_count") or len(grouped)

    story: List = []

    # ── Cover metadata block ──────────────────────────────────────────────────
    meta_data = [
        ["Tenant / Company", tenant_id],
        ["Incident ID",      report.get("incident_id") or "—"],
        ["Alert Date",       _first_alert_date(report)],
        ["Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    mt = Table(meta_data, colWidths=[45*mm, W - 45*mm])
    mt.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",  (0,0), (-1,-1), 9),
        ("TEXTCOLOR", (0,0), (0,-1), C["mid"]),
        ("TEXTCOLOR", (1,0), (1,-1), C["dark"]),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("LINEBELOW", (0,-1), (-1,-1), 0.4, C["border"]),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))

    # ── Summary cards ─────────────────────────────────────────────────────────
    story.append(SummaryCardRow(verdict, severity, status, ga_count, W))
    story.append(Spacer(1, 10))

    # ── Confidence ring + override note ──────────────────────────────────────
    ring = ConfidenceRing(conf_pct, _c(VERDICT_C, verdict), size=70)
    conf_note = (
        "High confidence" if conf_pct >= 80 else
        "Medium confidence" if conf_pct >= 50 else
        "Low confidence / fallback"
    )
    override = report.get("status_override_reason") or ""
    override_para = Paragraph(f"⚠  Status override: {override}", st["override"]) if override else Spacer(1,1)
    conf_tbl = Table(
        [[ring, [
            Paragraph(f"<b>{conf_pct}% — {conf_note}</b>", st["body"]),
            Spacer(1, 4),
            override_para,
        ]]],
        colWidths=[80, W - 80],
    )
    conf_tbl.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (-1,-1), 0),
    ]))
    story.append(conf_tbl)
    story.append(Spacer(1, 10))

    # ── Headline ──────────────────────────────────────────────────────────────
    story += _section_title("Headline", st)
    story.append(Paragraph(report.get("headline") or "—", st["headline"]))

    # ── AI Agent Classification ───────────────────────────────────────────────
    story += _section_title("AI Agent Classification", st)
    dt_labels = {
        "shadow_ai":     "⚠  Shadow AI",
        "enterprise_ai": "✓  Enterprise AI",
        "dev_tool":      "⚙  Developer Tool",
        "unknown":       "?  Unknown",
    }
    badge_color = DEPLOY_C.get(dt, C["grey"])
    story.append(BadgeFlowable(dt_labels.get(dt, dt.title()), badge_color))
    story.append(Spacer(1, 4))
    if deploy.get("reason"):
        story.append(Paragraph(deploy["reason"], st["body"]))
    note = (ai_ctx.get("llm_note") or
            ((ai_ctx.get("classification_alert_details") or [{}])[0].get("details") or ""))
    if note:
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<i>{note}</i>", st["small"]))
    story.append(Spacer(1, 6))

    # ── What Happened ─────────────────────────────────────────────────────────
    story += _section_title("What Happened", st)
    story.append(Paragraph(report.get("story") or "—", st["body"]))
    story.append(Spacer(1, 6))

    # ── Key Findings ──────────────────────────────────────────────────────────
    if findings:
        story += _section_title("Key Findings", st)
        for f in findings:
            story.append(Paragraph(f"• {f}", st["body"]))
        story.append(Spacer(1, 6))

    # ── Impact Assessment ─────────────────────────────────────────────────────
    story += _section_title("Impact Assessment", st)
    lateral = str(impact.get("lateral_movement_risk") or "LOW").upper()
    lat_color = {"HIGH": C["red"], "MEDIUM": C["orange"], "LOW": C["green"]}.get(lateral, C["grey"])

    def imp_cell(label, value, is_bad):
        color = C["red"] if is_bad else C["green"]
        icon  = "⚠" if is_bad else "✓"
        return [
            Paragraph(f"<font size='7' color='grey'>{label}</font>", st["small"]),
            Paragraph(f"<font color='#{color.hexval()[2:]}'><b>{icon} {value}</b></font>", st["body"]),
        ]

    imp_data = [
        imp_cell("DATA EXFILTRATION",   "YES — outbound transfer detected" if impact.get("data_exfiltration") else "Not detected",  bool(impact.get("data_exfiltration"))),
        imp_cell("SYSTEM MODIFICATION", "YES — files modified"             if impact.get("system_modification") else "Not detected", bool(impact.get("system_modification"))),
        imp_cell("CREDENTIAL RISK",     "Possible"                         if impact.get("possible_credentials_compromised") else "Not detected", bool(impact.get("possible_credentials_compromised"))),
        [
            Paragraph("<font size='7' color='grey'>LATERAL MOVEMENT RISK</font>", st["small"]),
            Paragraph(f"<font color='#{lat_color.hexval()[2:]}'><b>{lateral}</b></font>", st["body"]),
        ],
    ]

    rows_2col = [imp_data[i:i+2] for i in range(0, len(imp_data), 2)]
    for row in rows_2col:
        cells = []
        for cell in row:
            inner = Table([[cell[0]], [cell[1]]], colWidths=[(W/2 - 6)])
            inner.setStyle(TableStyle([
                ("BOX", (0,0), (-1,-1), 0.5, C["border"]),
                ("BACKGROUND", (0,0), (-1,-1), C["bg"]),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("ROUNDEDCORNERS", [5]),
            ]))
            cells.append(inner)
        if len(cells) == 1:
            cells.append(Spacer(1,1))
        row_tbl = Table([cells], colWidths=[W/2 - 3, W/2 - 3], spaceAfter=4)
        row_tbl.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),0),
                                      ("RIGHTPADDING",(0,0),(-1,-1),0)]))
        story.append(row_tbl)

    if bs > 0 or br > 0:
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Network Volume</b>", st["h3"]))
        story.append(NetworkBar(bs, br, W))
    story.append(Spacer(1, 8))

    # ── Recommended Actions ───────────────────────────────────────────────────
    if actions:
        story += _section_title("Recommended Actions", st)
        story += _render_actions(actions, st, W)
        story.append(Spacer(1, 6))

    # ── Root Cause Analysis ───────────────────────────────────────────────────
    story += _section_title("Root Cause Analysis", st)
    story.append(Paragraph(report.get("root_cause_analysis") or "—", st["body"]))
    story.append(Spacer(1, 6))

    # ── Execution Chain ───────────────────────────────────────────────────────
    story += _section_title("Execution Chain", st)
    story.append(ChainDiagram(report, W))
    story.append(Spacer(1, 10))

    # ── Threat Intelligence ────────────────────────────────────────────────────
    story += _section_title("Threat Intelligence", st)
    story.append(Paragraph(report.get("threat_intel_summary") or "No threat intelligence hits.", st["body"]))

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    if mitre:
        story += _section_title("MITRE ATT&CK", st)
        for m in mitre:
            story.append(Paragraph(f"• {m}", st["body"]))
        story.append(Spacer(1, 6))

    # ── Verdict Reasoning ─────────────────────────────────────────────────────
    if report.get("verdict_reasoning"):
        story += _section_title("Verdict Reasoning", st)
        story.append(Paragraph(report["verdict_reasoning"], st["body"]))

    # ── Assets ────────────────────────────────────────────────────────────────
    story += _section_title("Assets", st)
    asset_rows = [
        ["Field", "Value"],
        ["Machine",        _trunc(assets.get("machine") or "—", 60)],
        ["User",           _trunc(assets.get("user") or "—", 60)],
        ["OS",             f"{assets.get('os','')} {assets.get('os_version','')}".strip() or "—"],
        ["Host Type",      assets.get("host_type") or "—"],
        ["Process",        pc.get("name") or "—"],
        ["PID",            str(pc.get("pid") or "—")],
        ["Process Hash",   _trunc(pc.get("hash") or "—", 50)],
        ["Signer",         pc.get("signer") or "—"],
        ["Process Dir",    _trunc(pc.get("dir") or "—", 60)],
        ["Parent Process", _trunc(parent.get("name") or "—", 40)],
    ]
    at = Table([[r[0], r[1]] for r in asset_rows],
               colWidths=[40*mm, W - 40*mm])
    at.setStyle(_tbl_style())
    story.append(at)

    # ══════════════════════════════════════════════════════════════════════════
    # APPENDIX
    # ══════════════════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(ColorBar(C["dark"], height=4))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Appendix — Detailed Data", st["h1"]))
    story.append(_hr(C["dark"]))

    # ── A1. Grouped Alerts ────────────────────────────────────────────────────
    story += _section_title(f"A1. Grouped Alerts ({ga_count})", st)
    if grouped:
        ga_hdr = ["#", "Alert Type", "Sev", "Conf", "Timestamp", "Reason"]
        ga_data = [ga_hdr] + [
            [
                str(i + 1),
                Paragraph(a.get("alert_type") or "—", st["mono"]),
                str(a.get("severity") or "—"),
                f"{_confidence_pct(a.get('confidence'))}%",
                _fmt_ts(a.get("timestamp")),
                Paragraph(_trunc(a.get("reason") or "—", 60), st["small"]),
            ]
            for i, a in enumerate(grouped)
        ]
        gt = Table(ga_data, colWidths=[8*mm, 55*mm, 14*mm, 12*mm, 38*mm, None])
        gt.setStyle(_tbl_style())
        story.append(gt)
    else:
        story.append(Paragraph("No grouped alerts data.", st["small"]))

    # ── A2. Matched AI Definition Lists ──────────────────────────────────────
    story += _section_title("A2. AI Agent — Matched Definition Lists", st)
    if matched:
        mhdr = ["Value", "Matched List", "Match Type"]
        mdata = [mhdr] + [
            [
                Paragraph(_trunc(m.get("value") or "—", 40), st["mono"]),
                m.get("matched_list") or "—",
                m.get("match_type") or "—",
            ]
            for m in matched
        ]
        mw = W / 3
        mt2 = Table(mdata, colWidths=[mw, mw, mw])
        mt2.setStyle(_tbl_style())
        story.append(mt2)
    else:
        story.append(Paragraph("No matched artifacts recorded.", st["small"]))

    # ── A3. Threat Intelligence Detail ───────────────────────────────────────
    story += _section_title("A3. Threat Intelligence Detail", st)
    story.append(Paragraph(
        _jdump(report.get("threat_intel") or {}).replace("\n", "<br/>"),
        st["mono"]
    ))

    # ── A4. New IOCs ──────────────────────────────────────────────────────────
    story += _section_title("A4. New IOCs", st)
    story.append(Paragraph(
        _jdump(report.get("new_iocs_for_ti") or {}).replace("\n", "<br/>"),
        st["mono"]
    ))

    # ── A5. Anomaly Detail ────────────────────────────────────────────────────
    story += _section_title("A5. Anomaly Detail", st)
    story.append(Paragraph(
        _jdump(report.get("anomalies") or []).replace("\n", "<br/>"),
        st["mono"]
    ))

    # ── A6. Validator Notes ───────────────────────────────────────────────────
    story += _section_title("A6. Validator Notes", st)
    story.append(Paragraph(
        _jdump(report.get("validator_notes") or []).replace("\n", "<br/>"),
        st["mono"]
    ))

    return story


# =============================================================================
# Entry point
# =============================================================================

def generate_pdf(report: Dict, out_path: str, tenant_id: str = "Unknown Tenant") -> None:
    global _REPORT_META
    _REPORT_META = {
        "tenant":      tenant_id,
        "incident_id": str(report.get("incident_id") or "—"),
    }
    doc   = _make_doc(out_path)
    story = build_story(report, tenant_id)
    doc.build(story)
    print(f"  📄 PDF written → {out_path}")


def main():
    ap = argparse.ArgumentParser(description="Generate PDF incident report from JSON")
    ap.add_argument("input",    help="Incident JSON file or directory of JSON files")
    ap.add_argument("--out",    default=None, help="Output PDF path or directory")
    ap.add_argument("--tenant", default="Unknown Tenant", help="Tenant / company name")
    args = ap.parse_args()

    if os.path.isdir(args.input):
        files = sorted(
            os.path.join(args.input, f)
            for f in os.listdir(args.input)
            if f.endswith(".json")
        )
    else:
        files = [args.input]

    if not files:
        print("No JSON files found.")
        sys.exit(1)

    out_is_dir = (args.out and os.path.isdir(args.out)) or len(files) > 1
    if out_is_dir and args.out:
        os.makedirs(args.out, exist_ok=True)

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8") as f:
                report = json.load(f)
        except Exception as e:
            print(f"  ⚠  Skipping {fpath}: {e}")
            continue

        base     = os.path.splitext(os.path.basename(fpath))[0]
        pdf_path = (
            os.path.join(args.out or os.path.dirname(fpath), f"{base}.pdf")
            if out_is_dir
            else (args.out or fpath.replace(".json", ".pdf"))
        )
        generate_pdf(report, pdf_path, tenant_id=args.tenant)


if __name__ == "__main__":
    main()
