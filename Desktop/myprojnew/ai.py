from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os

def generate_pdf(inp, tool, output, ai_report):

    os.makedirs("reports", exist_ok=True)
    file_path = f"reports/report_{tool}.pdf"

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph("<b>Cybersecurity Incident Report</b>", styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph(f"<b>Input:</b> {inp}", styles["Normal"]))
    content.append(Paragraph(f"<b>Tool:</b> {tool}", styles["Normal"]))
    content.append(Paragraph(f"<b>Output:</b> {output}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("<b>AI Analysis</b>", styles["Heading2"]))
    content.append(Spacer(1, 8))

    content.append(Paragraph(ai_report, styles["Normal"]))

    doc.build(content)

    return file_path

