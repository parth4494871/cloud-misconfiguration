from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

def generate_pdf_report(scan_data):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 50, f"Cloud Security Scan Report")
    
    # Score Summary
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Risk Score: {scan_data['score']}/100   |   Grade: {scan_data['grade']}")
    
    y = height - 120
    
    for finding in scan_data.get('findings', []):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"[{finding['severity']}] {finding['service']}")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Issue: {finding['issue']}")
        y -= 15
        
        # New Impact field
        if 'impact' in finding:
            c.drawString(50, y, f"Impact: {finding['impact'][:80]}...")  # Truncate if too long for PDF line
            y -= 15
            
        c.drawString(50, y, f"Resource: {finding['resource']}")
        y -= 15
        c.drawString(50, y, f"Remediation: {finding['remediation']}")
        y -= 30
        
        # New page if we run out of space
        if y < 100:
            c.showPage()
            y = height - 50
            
    c.save()
    buffer.seek(0)
    return buffer
