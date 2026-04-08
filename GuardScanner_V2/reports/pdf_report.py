from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import json
import os

def generate_pdf(mode_label="Security Audit"):
    # Ensure exports directory exists
    if not os.path.exists("exports"):
        os.makedirs("exports")

    try:
        with open("reports/intelligent_report.json", 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"exports/{mode_label.replace(' ', '_')}_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title Section
    elements.append(Paragraph(f"GuardScanner V2: {mode_label} Report", styles['Title']))
    elements.append(Paragraph(f"Audit Timestamp: {data.get('timestamp', 'Unknown')}", styles['Normal']))
    elements.append(Spacer(1, 15))
    
    # Phase 1: Recon
    elements.append(Paragraph("Phase 1: System Fingerprint (Reverse Engineering)", styles['Heading2']))
    elements.append(Paragraph(data.get("recon_summary", "No metadata found."), styles['Normal']))
    elements.append(Spacer(1, 20))

    # Phase 2: Vulnerabilities
    elements.append(Paragraph("Phase 2: Vulnerability Analysis", styles['Heading2']))
    
    if not data.get('findings'):
        elements.append(Paragraph("No vulnerabilities were identified in the selected modules.", styles['Normal']))
    else:
        for i, f in enumerate(data['findings'], 1):
            elements.append(Paragraph(f"Finding #{i}: {f['type']}", styles['Heading3']))
            table_data = [
                ["Severity", f['severity']],
                ["OWASP Category", f['owasp']],
                ["CVSS Score", str(f['cvss'])],
                ["Target URL", f['url']]
            ]
            t = Table(table_data, colWidths=[120, 330])
            t.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('BACKGROUND', (0,0), (0,-1), colors.whitesmoke),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold')
            ]))
            elements.append(t)
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(f"<b>Exploit Payload:</b> <code>{f['payload']}</code>", styles['Normal']))
            elements.append(Spacer(1, 15))

    doc.build(elements)
    
    # Write the latest file path for the UI
    with open("reports/latest_file.txt", "w") as f:
        f.write(filename)
        
    return filename
