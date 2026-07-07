from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Device, ThreatEvent, ThreatLog
from app.schemas import DashboardSummary
from app.services.auth_service import get_current_user, get_current_user_optional_query
import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.status == "online").count()
    
    critical_threats = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.status == "active", ThreatEvent.severity == "critical")
        .count()
    )
    
    total_threats = db.query(ThreatEvent).filter(ThreatEvent.status == "active").count()
    
    # Calculate average trust score
    devices = db.query(Device).all()
    overall_trust_score = 100
    if devices:
        overall_trust_score = int(sum(d.trust_score for d in devices) / len(devices))
        
    recent_events = (
        db.query(ThreatEvent)
        .order_by(ThreatEvent.id.desc())
        .limit(5)
        .all()
    )
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "critical_threats": critical_threats,
        "total_threats": total_threats,
        "overall_trust_score": overall_trust_score,
        "recent_events": recent_events
    }

@router.get("/export-html", response_class=HTMLResponse)
def export_report_html(db: Session = Depends(get_db), current_user = Depends(get_current_user_optional_query)):
    # Fetch details to build a gorgeous printable executive report
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.status == "online").count()
    total_threats = db.query(ThreatEvent).count()
    critical_threats = db.query(ThreatEvent).filter(ThreatEvent.severity == "critical").count()
    devices = db.query(Device).all()
    avg_trust = int(sum(d.trust_score for d in devices) / len(devices)) if devices else 100
    
    all_threats = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc()).all()
    
    threats_rows = ""
    for t in all_threats:
        status_color = "red" if t.status == "active" else "green"
        threats_rows += f"""
        <tr>
            <td>{t.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
            <td>{t.device_id}</td>
            <td>{t.title}</td>
            <td><span style="text-transform:uppercase; font-weight:bold;">{t.category}</span></td>
            <td><span style="color:{status_color}; font-weight:bold;">{t.status}</span></td>
            <td>{t.severity.upper()}</td>
            <td>{t.confidence_score}%</td>
        </tr>
        """
        
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentinelCrypt EDR - Executive Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #333;
                background-color: #fff;
                margin: 40px;
                line-height: 1.6;
            }}
            .header {{
                border-bottom: 3px solid #1a365d;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            .title {{
                color: #1a365d;
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }}
            .subtitle {{
                color: #718096;
                margin: 5px 0 0 0;
                font-size: 14px;
            }}
            .meta-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }}
            .meta-card {{
                background-color: #f7fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }}
            .meta-card h3 {{
                margin: 0 0 10px 0;
                color: #4a5568;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .meta-card .value {{
                font-size: 28px;
                font-weight: 700;
                color: #2b6cb0;
                margin: 0;
            }}
            .meta-card .value.critical {{
                color: #c53030;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #e2e8f0;
            }}
            th {{
                background-color: #2b6cb0;
                color: #fff;
                font-weight: 600;
            }}
            tr:nth-child(even) {{
                background-color: #f8fafc;
            }}
            .footer {{
                margin-top: 50px;
                border-top: 1px solid #e2e8f0;
                padding-top: 20px;
                font-size: 12px;
                color: #a0aec0;
                text-align: center;
            }}
            @media print {{
                body {{ margin: 0; }}
                .no-print {{ display: none; }}
            }}
            .print-btn {{
                background-color: #2b6cb0;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
                cursor: pointer;
                float: right;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <button class="print-btn no-print" onclick="window.print()">Print/Save PDF</button>
        <div class="header">
            <h1 class="title">SentinelCrypt EDR</h1>
            <p class="subtitle">Executive Status & Threat Incident Report • Generated on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </div>
        
        <div class="meta-grid">
            <div class="meta-card">
                <h3>System Status Score</h3>
                <p class="value">{avg_trust}/100</p>
            </div>
            <div class="meta-card">
                <h3>Protected Devices</h3>
                <p class="value">{total_devices} ({active_devices} Online)</p>
            </div>
            <div class="meta-card">
                <h3>Total Incident Reports</h3>
                <p class="value">{total_threats}</p>
            </div>
            <div class="meta-card">
                <h3>Critical Security Alerts</h3>
                <p class="value critical">{critical_threats}</p>
            </div>
        </div>

        <h2>Security Threat Events & History</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Device Hostname</th>
                    <th>Threat Incident</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {threats_rows}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Confidential Internal Report • SentinelCrypt EDR Endpoint Monitoring</p>
        </div>
    </body>
    </html>
    """
    return html_content

@router.get("/export-csv")
def export_report_csv(db: Session = Depends(get_db), current_user = Depends(get_current_user_optional_query)):
    from fastapi.responses import PlainTextResponse
    
    all_threats = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc()).all()
    
    csv_content = "Timestamp,Device_ID,Title,Category,Status,Severity,Confidence\n"
    for t in all_threats:
        title = t.title.replace('"', '""')
        csv_content += f'"{t.timestamp.isoformat()}","{t.device_id}","{title}","{t.category}","{t.status}","{t.severity}",{t.confidence_score}\n'
        
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threat_report_{datetime.datetime.utcnow().strftime('%Y%m%d')}.csv"}
    )

@router.get("/export-pdf")
def export_report_pdf(db: Session = Depends(get_db), current_user = Depends(get_current_user_optional_query)):
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.status == "online").count()
    total_threats = db.query(ThreatEvent).count()
    critical_threats = db.query(ThreatEvent).filter(ThreatEvent.severity == "critical").count()
    devices = db.query(Device).all()
    avg_trust = int(sum(d.trust_score for d in devices) / len(devices)) if devices else 100
    
    all_threats = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc()).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#1a365d'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        textColor=colors.HexColor('#718096'),
        spaceAfter=20
    )
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1a365d'),
        spaceBefore=15,
        spaceAfter=10
    )
    normal_style = ParagraphStyle(
        'NormalText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#333333')
    )
    bold_style = ParagraphStyle(
        'BoldText',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#333333')
    )
    header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    story.append(Paragraph("SentinelCrypt EDR", title_style))
    story.append(Paragraph(f"Executive Status & Threat Incident Report • Generated on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(Spacer(1, 10))

    stats_data = [
        [
            Paragraph("<b>SYSTEM STATUS</b>", normal_style),
            Paragraph("<b>PROTECTED DEVICES</b>", normal_style),
            Paragraph("<b>TOTAL INCIDENTS</b>", normal_style),
            Paragraph("<b>CRITICAL ALERTS</b>", normal_style)
        ],
        [
            Paragraph(f"<font color='#2b6cb0'><b>{avg_trust}/100</b></font>", ParagraphStyle('StatVal', parent=normal_style, fontSize=16, leading=18)),
            Paragraph(f"<b>{total_devices}</b> ({active_devices} Online)", normal_style),
            Paragraph(f"<b>{total_threats}</b>", normal_style),
            Paragraph(f"<font color='#c53030'><b>{critical_threats}</b></font>", ParagraphStyle('StatValCrit', parent=normal_style, fontSize=16, leading=18))
        ]
    ]
    stats_table = Table(stats_data, colWidths=[130, 140, 120, 120])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f7fafc')),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f7fafc')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Security Threat Events & History", section_heading))
    
    headers = ["Timestamp", "Device ID", "Threat Incident", "Category", "Status", "Severity", "Conf."]
    table_data = [[Paragraph(h, header_style) for h in headers]]
    
    for t in all_threats:
        status_color = '#ef4444' if t.status == 'active' else '#10b981'
        sev_color = '#ef4444' if t.severity.lower() == 'critical' else '#f97316' if t.severity.lower() == 'high' else '#f59e0b' if t.severity.lower() == 'medium' else '#10b981'
        
        row = [
            Paragraph(t.timestamp.strftime('%Y-%m-%d %H:%M:%S'), normal_style),
            Paragraph(t.device_id, bold_style),
            Paragraph(t.title, normal_style),
            Paragraph(t.category.upper(), bold_style),
            Paragraph(f"<font color='{status_color}'><b>{t.status.upper()}</b></font>", normal_style),
            Paragraph(f"<font color='{sev_color}'><b>{t.severity.upper()}</b></font>", normal_style),
            Paragraph(f"{t.confidence_score}%", normal_style),
        ]
        table_data.append(row)
        
    threats_table = Table(table_data, colWidths=[95, 70, 150, 65, 55, 55, 40])
    threats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2b6cb0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0')),
    ]))
    story.append(threats_table)
    
    story.append(Spacer(1, 30))
    story.append(Paragraph("<font color='#a0aec0'>Confidential Internal Report • SentinelCrypt EDR Endpoint Monitoring</font>", ParagraphStyle('Footer', parent=normal_style, alignment=1)))

    doc.build(story)
    pdf_out = buffer.getvalue()
    buffer.close()
    
    return Response(
        content=pdf_out,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threat_report_{datetime.datetime.utcnow().strftime('%Y%m%d')}.pdf"}
    )
