"""Reporting reutilizable para consola, JSON y PDF opcional."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from .models import ScanResult, SEVERITIES


def export_json(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding='utf-8'
    )
    return path


def render_summary(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        'Security Assessment',
        f'Target: {result.target}',
        f'Scan time: {result.started_at}',
        '',
        'Findings:',
        ' | '.join(f'{severity}: {counts[severity]}' for severity in SEVERITIES),
    ]
    for finding in result.findings:
        lines.extend([
            '',
            f'[{finding.severity}] {finding.title}',
            f'  Confidence: {finding.confidence}',
            f'  Status: {finding.status}',
            f'  Evidence: {finding.evidence}',
            f'  Impact: {finding.impact}',
            f'  Recommendation: {finding.recommendation}',
        ])
    return '\n'.join(lines)


def export_pdf(
    result: ScanResult,
    destination: str | Path,
    executive_summary: str | None = None,
) -> Path:
    """Exporta un informe PDF legible, paginado y apto para compartir."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as error:
        raise RuntimeError(
            'PDF opcional: instala reportlab con "pip install reportlab"'
        ) from error

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title='Web Scanner - Informe defensivo', author='Web Scanner',
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle('ScannerTitle', parent=styles['Title'], fontName='Helvetica-Bold',
                           fontSize=24, leading=29, textColor=colors.HexColor('#0F172A'))
    subtitle = ParagraphStyle('ScannerSubtitle', parent=styles['Normal'], fontSize=10,
                              leading=14, textColor=colors.HexColor('#475569'))
    heading = ParagraphStyle('ScannerHeading', parent=styles['Heading2'], fontName='Helvetica-Bold',
                             fontSize=13, leading=18, textColor=colors.HexColor('#0F766E'), spaceBefore=12)
    body = ParagraphStyle('ScannerBody', parent=styles['BodyText'], fontSize=9.2, leading=13)
    small = ParagraphStyle('ScannerSmall', parent=body, fontSize=8.2, leading=11,
                           textColor=colors.HexColor('#475569'))
    centered = ParagraphStyle('ScannerCentered', parent=small, alignment=TA_CENTER)

    def paragraph(value: object, style: ParagraphStyle = body) -> Paragraph:
        return Paragraph(escape(str(value)).replace('\n', '<br/>'), style)

    severity_colors = {
        'CRITICAL': colors.HexColor('#991B1B'), 'HIGH': colors.HexColor('#C2410C'),
        'MEDIUM': colors.HexColor('#A16207'), 'LOW': colors.HexColor('#0369A1'),
        'INFO': colors.HexColor('#475569'),
    }
    story = [
        Paragraph('WEB SCANNER', title),
        Paragraph('Informe de auditoría defensiva y autorizada', subtitle),
        Spacer(1, 7 * mm),
    ]
    overview = [
        [paragraph('OBJETIVO', small), paragraph('RIESGO OBSERVADO', small), paragraph('INICIO', small)],
        [paragraph(result.target), paragraph(result.risk_level), paragraph(result.started_at, small)],
    ]
    overview_table = Table(overview, colWidths=[60 * mm, 50 * mm, 64 * mm])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#CBD5E1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'), ('PADDING', (0, 0), (-1, -1), 7),
    ]))
    story.extend([overview_table, Spacer(1, 6 * mm), Paragraph('Resumen de resultados', heading)])
    count_rows = [[paragraph(severity, small) for severity in SEVERITIES],
                  [paragraph(result.counts()[severity]) for severity in SEVERITIES]]
    count_table = Table(count_rows, colWidths=[34.8 * mm] * len(SEVERITIES))
    count_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#CBD5E1')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.extend([count_table, Spacer(1, 5 * mm)])
    if executive_summary:
        story.extend([Paragraph('Resumen ejecutivo local', heading), paragraph(executive_summary), Spacer(1, 3 * mm)])
    story.append(Paragraph('Hallazgos', heading))
    if not result.findings:
        story.append(paragraph('No se registraron hallazgos con evidencia suficiente.'))
    for finding in result.findings:
        color = severity_colors[finding.severity]
        header = Table([[paragraph(f'[{finding.severity}] {finding.title}', ParagraphStyle(
            'FindingTitle', parent=body, textColor=colors.white, fontName='Helvetica-Bold'))]], colWidths=[174 * mm])
        header.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), color), ('PADDING', (0, 0), (-1, -1), 7)]))
        detail = Table([
            [paragraph('Estado', small), paragraph(finding.status, body), paragraph('Confianza', small), paragraph(finding.confidence, body)],
            [paragraph('Evidencia', small), paragraph(finding.evidence, body), paragraph('Impacto', small), paragraph(finding.impact, body)],
            [paragraph('Recomendación', small), paragraph(finding.recommendation, body), '', ''],
        ], colWidths=[26 * mm, 61 * mm, 26 * mm, 61 * mm])
        detail.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F1F5F9')),
            ('BACKGROUND', (2, 0), (2, 1), colors.HexColor('#F1F5F9')),
            ('SPAN', (1, 2), (3, 2)), ('GRID', (0, 0), (-1, -1), 0.25, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.extend([KeepTogether([header, detail]), Spacer(1, 4 * mm)])
    disclaimer = 'Las ausencias de configuración y señales observadas no constituyen por sí solas una vulnerabilidad confirmada. Uso exclusivo con autorización explícita.'
    story.extend([Spacer(1, 4 * mm), Paragraph(disclaimer, centered)])

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor('#CBD5E1'))
        canvas.line(doc.leftMargin, 12 * mm, A4[0] - doc.rightMargin, 12 * mm)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(colors.HexColor('#64748B'))
        canvas.drawString(doc.leftMargin, 8 * mm, 'Web Scanner · Informe defensivo')
        canvas.drawRightString(A4[0] - doc.rightMargin, 8 * mm, f'Página {doc.page}')
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return path
