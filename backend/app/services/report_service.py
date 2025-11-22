import os
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
from io import BytesIO
from app.models.models import Scan

from pathlib import Path

class ReportService:
    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = str(Path(__file__).resolve().parent.parent / "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_html_report(self, scan: Scan) -> str:
        template = self.env.get_template("report.html")
        return template.render(scan=scan)

    def generate_pdf_report(self, scan: Scan) -> BytesIO:
        html_content = self.generate_html_report(scan)
        pdf_buffer = BytesIO()
        pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)
        
        if pisa_status.err:
            raise Exception("PDF generation failed")
            
        pdf_buffer.seek(0)
        return pdf_buffer

report_service = ReportService()
