"""
report_generator.py — Generates PDF security reports using ReportLab.

Creates a professional-looking PDF with:
  - Title and timestamp
  - Risk score and grade (color-coded)
  - Summary of findings by severity
  - Detailed listing of each finding with remediation steps
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from io import BytesIO
from datetime import datetime
from risk_engine import get_severity_counts


# Colors for severity levels
SEVERITY_COLORS = {
    'CRITICAL': HexColor('#DC2626'),
    'HIGH': HexColor('#F59E0B'),
    'MEDIUM': HexColor('#3B82F6'),
    'LOW': HexColor('#10B981'),
}

# Color for grades
GRADE_COLORS = {
    'A': HexColor('#10B981'),
    'B': HexColor('#3B82F6'),
    'C': HexColor('#F59E0B'),
    'D': HexColor('#F97316'),
    'F': HexColor('#DC2626'),
}


def generate_pdf_report(scan_data):
    """
    Generate a PDF report from scan data.

    Args:
        scan_data: dict with keys: score, grade, findings (list), timestamp

    Returns:
        BytesIO buffer containing the PDF (can be sent as a file download)
    """
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin = 50
    y = height - margin  # Start from the top

    # --- Title ---
    c.setFont("Helvetica-Bold", 22)
    c.setFillColor(HexColor('#1F2937'))
    c.drawString(margin, y, "Cloud Security Scan Report")
    y -= 30

    # Timestamp
    timestamp = scan_data.get('timestamp', datetime.now().isoformat())
    c.setFont("Helvetica", 10)
    c.setFillColor(HexColor('#6B7280'))
    c.drawString(margin, y, f"Generated: {timestamp}")
    y -= 15

    # Divider line
    c.setStrokeColor(HexColor('#E5E7EB'))
    c.setLineWidth(1)
    c.line(margin, y, width - margin, y)
    y -= 30

    # --- Score and Grade ---
    score = scan_data.get('score', 0)
    grade = scan_data.get('grade', 'F')
    grade_color = GRADE_COLORS.get(grade, HexColor('#DC2626'))

    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(HexColor('#1F2937'))
    c.drawString(margin, y, "Risk Assessment")
    y -= 30

    # Score
    c.setFont("Helvetica-Bold", 36)
    c.setFillColor(grade_color)
    c.drawString(margin, y, f"{score}/100")

    # Grade
    c.setFont("Helvetica-Bold", 36)
    c.drawString(margin + 180, y, f"Grade: {grade}")
    y -= 40

    # --- Severity Summary ---
    findings = scan_data.get('findings', [])
    counts = get_severity_counts(findings)

    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(HexColor('#1F2937'))
    c.drawString(margin, y, "Findings Summary")
    y -= 25

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        color = SEVERITY_COLORS[severity]
        count = counts[severity]

        # Colored dot
        c.setFillColor(color)
        c.circle(margin + 8, y + 4, 5, fill=1, stroke=0)

        # Label and count
        c.setFont("Helvetica", 12)
        c.setFillColor(HexColor('#374151'))
        c.drawString(margin + 20, y, f"{severity}: {count}")
        y -= 20

    y -= 15

    # Divider
    c.setStrokeColor(HexColor('#E5E7EB'))
    c.line(margin, y, width - margin, y)
    y -= 25

    # --- Detailed Findings ---
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(HexColor('#1F2937'))
    c.drawString(margin, y, "Detailed Findings")
    y -= 25

    for i, finding in enumerate(findings, 1):
        # Check if we need a new page
        if y < 120:
            c.showPage()
            y = height - margin

        severity = finding.get('severity', 'LOW')
        color = SEVERITY_COLORS.get(severity, HexColor('#6B7280'))

        # Finding number and severity badge
        c.setFont("Helvetica-Bold", 11)
        c.setFillColor(color)
        c.drawString(margin, y, f"[{severity}]")

        c.setFillColor(HexColor('#1F2937'))
        c.drawString(margin + 80, y, f"Finding #{i}")
        y -= 18

        # Service and Issue
        c.setFont("Helvetica", 10)
        c.setFillColor(HexColor('#374151'))
        c.drawString(margin + 10, y, f"Service: {finding.get('service', 'N/A')}")
        y -= 15

        c.drawString(margin + 10, y, f"Issue: {finding.get('issue', 'N/A')}")
        y -= 15

        c.drawString(margin + 10, y, f"Resource: {finding.get('resource', 'N/A')}")
        y -= 15

        # Impact (word-wrap long text)
        impact = finding.get('impact', '')
        if impact:
            c.setFillColor(HexColor('#DC2626'))
            c.drawString(margin + 10, y, "Impact:")
            y -= 15
            c.setFillColor(HexColor('#374151'))
            for line in _wrap_text(impact, 85):
                if y < 60:
                    c.showPage()
                    y = height - margin
                c.drawString(margin + 20, y, line)
                y -= 13

        # Remediation
        remediation = finding.get('remediation', '')
        if remediation:
            c.setFillColor(HexColor('#059669'))
            c.drawString(margin + 10, y, "Fix:")
            y -= 15
            c.setFillColor(HexColor('#374151'))
            for line in _wrap_text(remediation, 85):
                if y < 60:
                    c.showPage()
                    y = height - margin
                c.drawString(margin + 20, y, line)
                y -= 13

        y -= 10  # Space between findings

    # --- Footer ---
    c.setFont("Helvetica", 8)
    c.setFillColor(HexColor('#9CA3AF'))
    c.drawString(margin, 30, "Cloud Security Misconfiguration Detector — Automated Report")
    c.drawString(width - margin - 80, 30, f"Page {c.getPageNumber()}")

    c.save()
    buffer.seek(0)
    return buffer


def _wrap_text(text, max_chars):
    """
    Simple word-wrap: split text into lines of at most max_chars characters.
    """
    words = text.split()
    lines = []
    current_line = ""
    for word in words:
        if len(current_line) + len(word) + 1 <= max_chars:
            current_line += (" " + word) if current_line else word
        else:
            if current_line:
                lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)
    return lines
