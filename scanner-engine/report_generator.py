from fpdf import FPDF
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(80)
        self.cell(30, 10, 'Scancrypt Vulnerability Report', 0, 0, 'C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 5, body)
        self.ln()

    def render_code_block(self, code):
        self.set_font('Courier', '', 9)
        self.set_fill_color(245, 245, 245) # Very Light Grey
        self.set_text_color(40, 40, 40) # Dark code text
        # border=1 (rect), align='L', fill=True
        self.multi_cell(0, 5, code, 1, 'L', True)
        self.set_text_color(0, 0, 0) # Reset
        self.ln(4)

    def generate(self, scan_data, filename="report.pdf"):
        self.add_page()
        
        # 1. Executive Summary
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, f"Scan Report for: {scan_data.get('target', 'Unknown')}", 0, 1)
        self.set_font('Arial', '', 12)
        self.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
        self.ln(10)

        findings = scan_data.get('findings', [])
        
        # Count Severities
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get('severity', 'Info')
            if sev in counts: counts[sev] += 1
            
        self.chapter_title("Executive Summary")
        self.set_font('Arial', '', 12)
        for sev, count in counts.items():
            self.cell(40, 10, f"{sev}: {count}", 0, 1)
        self.ln(10)

        # 2. Detailed Findings
        self.chapter_title("Detailed Findings")
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'Info')
            color = (0, 0, 0)
            if severity == 'Critical': color = (255, 0, 0)
            elif severity == 'High': color = (255, 100, 0)
            elif severity == 'Medium': color = (255, 165, 0)
            
            self.set_text_color(*color)
            self.set_font('Arial', 'B', 12)
            self.cell(0, 8, f"{i}. [{severity}] {finding.get('name', finding.get('type', 'Vulnerability'))}", 0, 1)
            self.set_text_color(0, 0, 0)
            
            self.set_font('Arial', 'B', 10)
            self.cell(20, 6, "URL:", 0, 0)
            self.set_font('Arial', '', 10)
            self.multi_cell(0, 6, finding.get('url', ''))
            
            if finding.get('parameter'):
                self.set_font('Arial', 'B', 10)
                self.cell(20, 6, "Param:", 0, 0)
                self.set_font('Arial', '', 10)
                self.cell(0, 6, finding.get('parameter', ''), 0, 1)

            if finding.get('payload'):
                self.set_font('Arial', 'B', 10)
                self.cell(20, 6, "Payload:", 0, 0)
                self.set_font('Arial', 'I', 10)
                self.multi_cell(0, 6, finding.get('payload', ''))

            self.ln(2)
            self.set_font('Arial', 'B', 10)
            self.cell(0, 6, "Description:", 0, 1)
            self.set_font('Arial', '', 10)
            self.multi_cell(0, 5, finding.get('description', ''))
            
            self.ln(2)
            self.set_font('Arial', 'B', 10)
            self.cell(0, 6, "Remediation:", 0, 1)
            self.set_font('Arial', '', 10)
            self.multi_cell(0, 5, finding.get('remediation', ''))
            
            if finding.get('remediation_code'):
                self.ln(2)
                self.set_font('Arial', 'B', 10)
                self.cell(0, 6, "Fix Snippet:", 0, 1)
                self.render_code_block(finding.get('remediation_code'))
            
            self.ln(5)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(5)

        self.output(filename, 'F')
        return filename
