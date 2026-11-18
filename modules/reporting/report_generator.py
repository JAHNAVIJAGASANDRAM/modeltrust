"""
Module 11: Security Assessment Report Generator using ReportLab.

Generates a structured academic/enterprise PDF security assessment report
covering all security modules, policy violations, risk classification,
digital certification, and final approval decision.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from config import Config
from utils.logger import get_logger
from utils.validators import sanitize_filename

logger = get_logger("modeltrust.reporting")

MODULE_LABELS = {
    "provenance": "Repository Provenance Analysis",
    "static_analysis": "Static Code Security Analysis (Bandit)",
    "dependency_analysis": "Dependency Vulnerability Analysis (pip-audit & OSV)",
    "serialization_analysis": "Serialization Safety Analysis (PickleScan)",
    "integrity": "Integrity Verification (SHA-256)",
    "sbom": "SBOM Generation (Syft)",
}


def _decision_color(decision: str) -> colors.Color:
    return {
        "APPROVE": colors.HexColor("#198754"),
        "REVIEW": colors.HexColor("#d97706"),
        "REJECT": colors.HexColor("#dc3545"),
    }.get(decision.upper(), colors.HexColor("#475569"))


def _status_color(status: str) -> colors.Color:
    return {
        "PASS": colors.HexColor("#198754"),
        "WARNING": colors.HexColor("#d97706"),
        "FAIL": colors.HexColor("#dc3545"),
        "NOT SCANNED": colors.HexColor("#64748b"),
    }.get(status.upper(), colors.HexColor("#475569"))


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "N/A")), style)


def generate_pdf_report(assessment_bundle: dict[str, Any]) -> dict[str, str]:
    """Generate a comprehensive PDF report for the given full assessment bundle."""
    Config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    artifact = assessment_bundle["artifact"]
    scans = assessment_bundle["scans"]
    decision_obj = assessment_bundle.get("policy_decision") or {}
    certificate = assessment_bundle.get("certificate")

    assessment_id = artifact["assessment_id"]
    filename = f"ModelTrust_Report_{sanitize_filename(assessment_id)}.pdf"
    output_path = Config.REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ModelTrust Security Assessment Report - {assessment_id}",
        author="ModelTrust Security Framework",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "MTTitle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "MTSubtitle",
        parent=styles["Normal"],
        fontSize=9.5,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10,
    )
    h2_style = ParagraphStyle(
        "MTH2",
        parent=styles["Heading2"],
        fontSize=12.5,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=5,
    )
    body_style = ParagraphStyle(
        "MTBody",
        parent=styles["Normal"],
        fontSize=8.8,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
    )
    small_style = ParagraphStyle(
        "MTSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#334155"),
    )

    elements: list[Any] = []

    # Title Banner
    elements.append(_p("ModelTrust – Security Assessment Report", title_style))
    elements.append(_p(
        f"{Config.APP_SUBTITLE} | Assessment ID: {assessment_id} | "
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        subtitle_style,
    ))

    # Executive Decision Banner Table
    decision = decision_obj.get("decision", "PENDING")
    risk = decision_obj.get("risk_classification", "UNKNOWN")
    reason = decision_obj.get("reason", "Policy evaluation not completed.")

    banner_data = [
        [
            _p("FINAL POLICY DECISION", ParagraphStyle("lbl", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
            _p("RISK CLASSIFICATION", ParagraphStyle("lbl2", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
            _p("TRUSTED REGISTRY ELIGIBILITY", ParagraphStyle("lbl3", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
        ],
        [
            _p(decision, ParagraphStyle("val", parent=h2_style, textColor=colors.white, spaceBefore=0, spaceAfter=0)),
            _p(risk, ParagraphStyle("val2", parent=h2_style, textColor=colors.white, spaceBefore=0, spaceAfter=0)),
            _p("ADMITTED" if decision == "APPROVE" else "NOT ADMITTED", ParagraphStyle("val3", parent=h2_style, textColor=colors.white, spaceBefore=0, spaceAfter=0)),
        ],
    ]
    banner_table = Table(banner_data, colWidths=[58 * mm, 58 * mm, 62 * mm])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _decision_color(decision)),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.white),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 6))
    elements.append(_p(f"Decision Rationale: {reason}", body_style))
    elements.append(Spacer(1, 8))

    # 1. Repository Information
    elements.append(_p("1. Repository Information", h2_style))
    repo_rows = [
        [_p("Repository Name", small_style), _p(f"{artifact.get('owner')}/{artifact.get('repo_name')}", small_style)],
        [_p("Repository URL", small_style), _p(artifact.get("repository_url"), small_style)],
        [_p("Platform", small_style), _p(str(artifact.get("platform", "")).upper(), small_style)],
        [_p("Default Branch", small_style), _p(artifact.get("default_branch") or "N/A", small_style)],
        [_p("Created / Updated", small_style), _p(f"{artifact.get('repo_created_at') or 'N/A'} / {artifact.get('repo_updated_at') or 'N/A'}", small_style)],
        [_p("Files Acquired / Size", small_style), _p(f"{artifact.get('file_count', 0)} files ({(artifact.get('total_size_bytes') or 0) / 1024:.1f} KB)", small_style)],
        [_p("Composite SHA-256 Hash", small_style), _p(artifact.get("artifact_hash") or "Not computed", small_style)],
        [_p("Description", small_style), _p(artifact.get("description") or "No description provided.", small_style)],
    ]
    repo_table = Table(repo_rows, colWidths=[48 * mm, 130 * mm])
    repo_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(repo_table)
    elements.append(Spacer(1, 8))

    # 2. Security Module Summary Matrix
    elements.append(_p("2. Security Assessment Matrix", h2_style))
    matrix_rows = [[
        _p("Security Module", ParagraphStyle("th", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
        _p("Tool", ParagraphStyle("th2", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
        _p("Status", ParagraphStyle("th3", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
        _p("Severity", ParagraphStyle("th4", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
        _p("Findings", ParagraphStyle("th5", parent=small_style, textColor=colors.white, fontName="Helvetica-Bold")),
    ]]
    matrix_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    ordered_modules = [
        "provenance",
        "static_analysis",
        "dependency_analysis",
        "serialization_analysis",
        "integrity",
        "sbom",
    ]
    for row_idx, mod_key in enumerate(ordered_modules, start=1):
        mod = scans.get(mod_key) or {}
        st = mod.get("status", "NOT SCANNED")
        sev = mod.get("severity", "UNKNOWN")
        findings_cnt = len(mod.get("findings") or [])
        matrix_rows.append([
            _p(MODULE_LABELS.get(mod_key, mod_key), small_style),
            _p(mod.get("tool_name") or "N/A", small_style),
            _p(st, ParagraphStyle(f"st{row_idx}", parent=small_style, textColor=_status_color(st), fontName="Helvetica-Bold")),
            _p(sev, small_style),
            _p(str(findings_cnt), small_style),
        ])

    matrix_table = Table(matrix_rows, colWidths=[66 * mm, 36 * mm, 28 * mm, 24 * mm, 24 * mm])
    matrix_table.setStyle(TableStyle(matrix_style_cmds))
    elements.append(matrix_table)
    elements.append(Spacer(1, 8))

    # 3. Detailed Module Results
    elements.append(_p("3. Detailed Module Findings", h2_style))
    for idx, mod_key in enumerate(ordered_modules, start=1):
        mod = scans.get(mod_key) or {}
        label = MODULE_LABELS.get(mod_key, mod_key)
        st = mod.get("status", "NOT SCANNED")
        elements.append(_p(f"3.{idx} {label} [{st}]", ParagraphStyle("subh", parent=body_style, fontName="Helvetica-Bold", spaceBefore=5, spaceAfter=2)))
        elements.append(_p(mod.get("summary") or "No scan data available.", small_style))

        mod_findings = mod.get("findings") or []
        if mod_findings:
            f_rows = [[
                _p("Severity", ParagraphStyle("fth1", parent=small_style, fontName="Helvetica-Bold")),
                _p("Finding", ParagraphStyle("fth2", parent=small_style, fontName="Helvetica-Bold")),
                _p("Description", ParagraphStyle("fth3", parent=small_style, fontName="Helvetica-Bold")),
            ]]
            for f in mod_findings[:25]:
                loc = f" ({f['file']}:{f['line']})" if f.get("file") and f.get("line") else (f" ({f['file']})" if f.get("file") else "")
                f_rows.append([
                    _p(f.get("severity", "INFO"), small_style),
                    _p(f"{f.get('title', 'Finding')}{loc}", small_style),
                    _p(str(f.get("description") or "")[:280], small_style),
                ])
            ft = Table(f_rows, colWidths=[22 * mm, 58 * mm, 98 * mm])
            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(Spacer(1, 3))
            elements.append(ft)
        elements.append(Spacer(1, 5))

    # 4. Policy Violations
    elements.append(_p("4. Policy Enforcement Violations", h2_style))
    violations = decision_obj.get("violations") or []
    if violations:
        v_rows = [[
            _p("Rule ID", ParagraphStyle("vth1", parent=small_style, fontName="Helvetica-Bold")),
            _p("Module", ParagraphStyle("vth2", parent=small_style, fontName="Helvetica-Bold")),
            _p("Action", ParagraphStyle("vth3", parent=small_style, fontName="Helvetica-Bold")),
            _p("Details", ParagraphStyle("vth4", parent=small_style, fontName="Helvetica-Bold")),
        ]]
        for v in violations:
            v_rows.append([
                _p(v.get("rule_id"), small_style),
                _p(v.get("module"), small_style),
                _p(v.get("action"), small_style),
                _p(v.get("message"), small_style),
            ])
        vt = Table(v_rows, colWidths=[26 * mm, 34 * mm, 22 * mm, 96 * mm])
        vt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fee2e2")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(vt)
    else:
        elements.append(_p("No organizational security policy violations detected.", small_style))

    # 5. Digital Trust Certification
    elements.append(Spacer(1, 8))
    elements.append(_p("5. Organizational Trust Certification", h2_style))
    if certificate:
        cert_rows = [
            [_p("Certificate ID", small_style), _p(certificate.get("certificate_id"), small_style)],
            [_p("Issuer", small_style), _p(certificate.get("issuer"), small_style)],
            [_p("Algorithm", small_style), _p(certificate.get("algorithm"), small_style)],
            [_p("Issued At", small_style), _p(certificate.get("issued_at"), small_style)],
            [_p("Status", small_style), _p(certificate.get("status"), small_style)],
            [_p("Digital Signature (Base64)", small_style), _p(str(certificate.get("signature_b64") or "")[:96] + "...", small_style)],
        ]
        ct = Table(cert_rows, colWidths=[48 * mm, 130 * mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecfdf5")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#a7f3d0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(ct)
    else:
        elements.append(_p(
            "No digital trust certificate issued. Only APPROVED artifacts receive organizational signing and admission to the Trusted AI Artifact Registry.",
            small_style,
        ))

    doc.build(elements)
    logger.info("Generated PDF security report: %s", output_path)
    return {
        "report_filename": filename,
        "report_path": str(output_path),
    }
