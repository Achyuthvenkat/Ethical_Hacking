import os
from xml.sax.saxutils import escape as xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from config import Config

def safe_xml(text):
    """Escapes raw strings so they can be safely rendered within ReportLab XML paragraphs."""
    if text is None:
        return ""
    return xml_escape(str(text))

def generate_pdf_report(scan_id, scan_data, recon_data, vulnerabilities, output_path=None):
    """
    Generates a professional, publication-quality PDF Vulnerability Assessment Report
    using ReportLab.
    """
    if not output_path:
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(Config.REPORTS_DIR, f"scan_report_{scan_id}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Cyber Security Styling
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0d6efd')
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#6c757d')
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1f2937'),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#333333')
    )

    story = []

    # 1. Header & Title Banner
    story.append(Paragraph("Web Application Security Testing and Vulnerability Scanner", title_style))
    story.append(Paragraph("Automated Vulnerability Assessment &amp; Academic Capstone Audit Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0d6efd'), spaceBefore=8, spaceAfter=12))

    # 2. Executive Summary & Scan Metadata Table
    story.append(Paragraph("1. Executive Summary &amp; Assessment Metadata", section_heading))
    
    meta_table_data = [
        [Paragraph("<b>Target URL:</b>", body_style), Paragraph(safe_xml(scan_data.get('target_url')), body_style),
         Paragraph("<b>Scan Status:</b>", body_style), Paragraph(safe_xml(scan_data.get('scan_status')), body_style)],
        [Paragraph("<b>Scan Started:</b>", body_style), Paragraph(safe_xml(scan_data.get('started_at')), body_style),
         Paragraph("<b>Completed At:</b>", body_style), Paragraph(safe_xml(scan_data.get('completed_at', 'In Progress')), body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"<b>{scan_data.get('risk_score', 0.0)} / 10.0</b>", body_style),
         Paragraph("<b>Total Findings:</b>", body_style), Paragraph(str(scan_data.get('total_findings', 0)), body_style)]
    ]
    
    t_meta = Table(meta_table_data, colWidths=[110, 160, 110, 160])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Findings Breakdown by Severity Table
    sev_table_data = [
        [
            Paragraph("<b>Critical</b>", body_style),
            Paragraph("<b>High</b>", body_style),
            Paragraph("<b>Medium</b>", body_style),
            Paragraph("<b>Low</b>", body_style),
            Paragraph("<b>Informational</b>", body_style)
        ],
        [
            Paragraph(f"<font color='#dc3545'><b>{scan_data.get('critical_count', 0)}</b></font>", body_style),
            Paragraph(f"<font color='#fd7e14'><b>{scan_data.get('high_count', 0)}</b></font>", body_style),
            Paragraph(f"<font color='#ffc107'><b>{scan_data.get('medium_count', 0)}</b></font>", body_style),
            Paragraph(f"<font color='#0dcaf0'><b>{scan_data.get('low_count', 0)}</b></font>", body_style),
            Paragraph(f"<font color='#6c757d'><b>{scan_data.get('info_count', 0)}</b></font>", body_style),
        ]
    ]
    t_sev = Table(sev_table_data, colWidths=[108, 108, 108, 108, 108])
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9ecef')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ced4da')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 12))

    # 3. Reconnaissance Profile (Module 1 Results)
    story.append(Paragraph("2. Website Reconnaissance &amp; Infrastructure Profile", section_heading))
    if recon_data:
        tech_list = safe_xml(", ".join(recon_data.get('technologies', [])) or "None identified")
        ports_list = safe_xml(", ".join([f"{p['port']}/{p['service']}" for p in recon_data.get('open_ports', [])]) or "No web ports opened")
        
        recon_table_data = [
            [Paragraph("<b>Resolved IP:</b>", body_style), Paragraph(safe_xml(recon_data.get('ip_address')), body_style)],
            [Paragraph("<b>HTTP Status &amp; Banner:</b>", body_style), Paragraph(f"HTTP {recon_data.get('http_status')} | {safe_xml(recon_data.get('server_banner'))}", body_style)],
            [Paragraph("<b>SSL/TLS Validity:</b>", body_style), Paragraph(f"{'Valid' if recon_data.get('ssl_valid') else 'Insecure/Unverified'} | Issuer: {safe_xml(recon_data.get('ssl_issuer'))} | Expiry: {safe_xml(recon_data.get('ssl_expiry'))}", body_style)],
            [Paragraph("<b>Detected Technologies:</b>", body_style), Paragraph(tech_list, body_style)],
            [Paragraph("<b>Accessible Web Ports:</b>", body_style), Paragraph(ports_list, body_style)]
        ]
        t_recon = Table(recon_table_data, colWidths=[140, 400])
        t_recon.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_recon)
    story.append(Spacer(1, 12))

    # 4. Detailed Vulnerability Findings (Module 2 & Header Audit)
    story.append(Paragraph("3. Detailed Vulnerability Findings &amp; Remediation Guidance", section_heading))
    
    if not vulnerabilities:
        story.append(Paragraph("<i>No significant vulnerabilities identified for the tested parameters. Note: This automated assessment does not certify the target as completely secure.</i>", body_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            sev = str(vuln.get('severity', 'LOW')).upper()
            sev_colors = {
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14',
                'MEDIUM': '#ffc107',
                'LOW': '#0dcaf0',
                'INFORMATIONAL': '#6c757d'
            }
            color_hex = sev_colors.get(sev, '#6c757d')

            vuln_name_safe = safe_xml(vuln.get('vuln_name'))
            module_safe = safe_xml(vuln.get('module_source'))
            url_safe = safe_xml(vuln.get('affected_url'))
            param_safe = safe_xml(vuln.get('parameter') or 'N/A')
            evidence_safe = safe_xml(vuln.get('evidence'))
            impact_safe = safe_xml(vuln.get('impact'))
            remediation_safe = safe_xml(vuln.get('remediation'))

            vuln_box = [
                [
                    Paragraph(f"<b>#{idx} {vuln_name_safe}</b>", body_style),
                    Paragraph(f"<b><font color='{color_hex}'>[{sev}]</font></b>", body_style)
                ],
                [
                    Paragraph(f"<b>Module Source:</b> {module_safe}<br/>"
                              f"<b>Affected URL:</b> {url_safe}<br/>"
                              f"<b>Input Parameter:</b> {param_safe}", body_style),
                    Paragraph("", body_style)
                ],
                [
                    Paragraph(f"<b>Evidence:</b> {evidence_safe}", body_style),
                    Paragraph("", body_style)
                ],
                [
                    Paragraph(f"<b>Security Impact:</b> {impact_safe}", body_style),
                    Paragraph("", body_style)
                ],
                [
                    Paragraph(f"<b>Remediation Recommendation:</b><br/>{remediation_safe}", body_style),
                    Paragraph("", body_style)
                ]
            ]
            t_vuln = Table(vuln_box, colWidths=[460, 80])
            t_vuln.setStyle(TableStyle([
                ('SPAN', (0,1), (1,1)),
                ('SPAN', (0,2), (1,2)),
                ('SPAN', (0,3), (1,3)),
                ('SPAN', (0,4), (1,4)),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#eef2f7')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#ced4da')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_vuln)
            story.append(Spacer(1, 8))

    # 5. Ethical Statement & Disclaimer
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#ced4da'), spaceBefore=8, spaceAfter=8))
    story.append(Paragraph(
        "<b>Academic &amp; Ethical Disclaimer:</b> This report was automatically compiled by the Web Application Security Testing "
        "and Vulnerability Scanner. Testing methodologies adhered to non-destructive auditing principles. "
        "The findings are based strictly on observed indicators and do not guarantee the total absence of unexamined or logic-based vulnerabilities. "
        "Authorization confirmation was logged prior to assessment execution.",
        subtitle_style
    ))

    # Build the document
    doc.build(story)
    return output_path
