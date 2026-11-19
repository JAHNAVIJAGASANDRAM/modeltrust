"""
ModelTrust – A Secure AI Artifact Trust and Supply Chain Framework
Main Flask Application & End-to-End Security Assessment Orchestrator.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user
from flask_wtf.csrf import generate_csrf
from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy import func

from config import Config
from app.config import config as auth_config
from app.extensions import db as auth_db, login_manager, migrate, csrf
from app.auth import auth_bp
from app.auth.permissions import roles_required
from app.models import User, ReportPermission
from app.reports.authorization import (
    grant_report_access,
    require_artifact_access,
    revoke_report_access,
    visible_artifact_ids,
    write_report_audit,
)
from database.db import (
    create_artifact_record,
    get_assessment_full,
    artifact_exists,
    get_dashboard_summary,
    init_db,
    save_certificate_record,
    save_policy_decision,
    save_report_record,
    save_scan_result,
    update_artifact_record,
    utc_now_iso,
)
from modules.certification.certificate_manager import ensure_org_keypair, issue_certificate
from modules.dependency_analysis.vulnerability_checker import (
    check_dependencies_vulnerabilities,
    is_pip_audit_available,
)
from modules.integrity.hash_generator import generate_integrity_report
from modules.policy_engine.policy_evaluator import evaluate_policy
from modules.provenance.provenance_analyzer import analyze_provenance
from modules.registry.artifact_registry import (
    admit_artifact_to_registry,
    list_trusted_artifacts,
    reverify_trusted_artifact,
)
from modules.reporting.report_generator import generate_pdf_report
from modules.repository_acquisition.repository_metadata import acquire_repository
from modules.sbom.sbom_generator import generate_sbom, is_syft_available
from modules.serialization_analysis.serialization_scanner import (
    is_picklescan_available,
    run_serialization_scan,
)
from modules.static_analysis.sast_scanner import is_bandit_available, run_sast_scan
from utils.logger import get_logger
from utils.validators import ValidationError, validate_repository_url

logger = get_logger("modeltrust.app")

app = Flask(
    __name__,
    template_folder=str(Config.TEMPLATE_DIR),
    static_folder=str(Config.STATIC_DIR),
)
if os.environ.get("FLASK_ENV") == "production" and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY must be set when running the production configuration.")
app.config.from_object(
    auth_config.get(os.environ.get("FLASK_ENV", "development"), auth_config["default"])
)
auth_db.init_app(app)
migrate.init_app(app, auth_db)
login_manager.init_app(app)
csrf.init_app(app)
app.jinja_loader = ChoiceLoader(
    [app.jinja_loader, FileSystemLoader(str(Config.BASE_DIR / "app" / "templates"))]
)
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf}

# Ensure storage folders, SQLite schema, and organizational signing keys exist on startup
Config.ensure_directories()
init_db()
ensure_org_keypair()


def get_scanner_tool_status() -> dict[str, dict[str, Any]]:
    """Inspect local availability of external security scanning tools."""
    return {
        "bandit": {
            "name": "Bandit (SAST)",
            "available": is_bandit_available(),
            "install": "pip install bandit",
        },
        "pip_audit": {
            "name": "pip-audit (SCA)",
            "available": is_pip_audit_available(),
            "install": "pip install pip-audit",
        },
        "picklescan": {
            "name": "PickleScan (Serialization)",
            "available": is_picklescan_available(),
            "install": "pip install picklescan",
        },
        "syft": {
            "name": "Syft (SBOM)",
            "available": is_syft_available(),
            "install": "winget install Anchore.Syft",
        },
    }


def _safe_run_module(module_name: str, tool_name: str, fn, *args, **kwargs) -> dict[str, Any]:
    """Execute a security analysis module safely, returning NOT SCANNED on unexpected errors."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        logger.exception("Unhandled error in module '%s': %s", module_name, exc)
        return {
            "module_name": module_name,
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Module execution failed unexpectedly: {exc}",
            "findings": [
                {
                    "title": f"{module_name} Execution Error",
                    "severity": "MEDIUM",
                    "description": str(exc),
                    "recommendation": "Inspect application logs and re-run the assessment.",
                }
            ],
            "raw_details": {"error": str(exc)},
            "tool_name": tool_name,
            "tool_available": False,
        }


def run_full_assessment(
    raw_url: str,
    policy_overrides: dict[str, Any] | None = None,
    auth_user_id: int | None = None,
) -> dict[str, Any]:
    """
    Execute the complete 16-step ModelTrust assessment pipeline for a submitted repository URL.
    Returns the full assessment dictionary loaded from SQLite.
    """
    # Step 1: Validate URL & prevent SSRF
    parsed = validate_repository_url(raw_url)
    assessment_id = f"MT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    artifact_id = create_artifact_record(
        assessment_id=assessment_id,
        repository_url=parsed["normalized_url"],
        platform=parsed["platform"],
        owner=parsed["owner"],
        repo_name=parsed["repo"],
        repo_type=parsed["repo_type"],
        auth_user_id=auth_user_id,
    )

    try:
        # Step 2: Acquire repository metadata and files safely (no code execution)
        acq = acquire_repository(parsed["normalized_url"], assessment_id=assessment_id)
        metadata = acq["metadata"]
        download = acq["download"]
        local_path: Path = acq["local_path"]

        update_artifact_record(
            artifact_id,
            {
                "description": metadata.get("description") or "",
                "default_branch": metadata.get("default_branch") or "main",
                "repo_created_at": metadata.get("created_at"),
                "repo_updated_at": metadata.get("updated_at"),
                "local_path": str(local_path),
                "file_count": download.get("file_count", 0),
                "total_size_bytes": download.get("total_size_bytes", 0),
                "metadata_json": json.dumps(metadata, default=str),
            },
        )

        # Steps 3–8: Run all 6 independent security analysis modules
        scan_outputs: dict[str, dict[str, Any]] = {}
        scan_outputs["provenance"] = _safe_run_module(
            "provenance", "ModelTrust Provenance Analyzer", analyze_provenance, metadata
        )
        scan_outputs["static_analysis"] = _safe_run_module(
            "static_analysis", "Bandit", run_sast_scan, local_path
        )
        scan_outputs["dependency_analysis"] = _safe_run_module(
            "dependency_analysis", "pip-audit + OSV API", check_dependencies_vulnerabilities, local_path
        )
        scan_outputs["serialization_analysis"] = _safe_run_module(
            "serialization_analysis",
            "PickleScan",
            run_serialization_scan,
            local_path,
            metadata.get("remote_files"),
        )
        scan_outputs["integrity"] = _safe_run_module(
            "integrity", "SHA-256 Cryptographic Hasher", generate_integrity_report, local_path
        )
        scan_outputs["sbom"] = _safe_run_module(
            "sbom", "Syft", generate_sbom, local_path, assessment_id
        )

        # Persist individual scan results
        for mod_name, res in scan_outputs.items():
            save_scan_result(
                artifact_id=artifact_id,
                module_name=mod_name,
                status=res.get("status", "NOT SCANNED"),
                severity=res.get("severity", "UNKNOWN"),
                summary=res.get("summary", ""),
                findings=res.get("findings") or [],
                raw_details=res.get("raw_details") or {},
                tool_name=res.get("tool_name"),
                tool_available=bool(res.get("tool_available", True)),
            )

        composite_hash = (scan_outputs["integrity"].get("raw_details") or {}).get("composite_hash")
        update_artifact_record(artifact_id, {"artifact_hash": composite_hash})

        # Step 9: Evaluate organizational security policies
        policy_result = evaluate_policy(scan_outputs, policy_overrides=policy_overrides)
        save_policy_decision(
            artifact_id=artifact_id,
            decision=policy_result["decision"],
            risk_classification=policy_result["risk_classification"],
            violations=policy_result["violations"],
            reason=policy_result["reason"],
            policy_snapshot=policy_result["policy_snapshot"],
        )

        # Steps 10–11: Digital certification & Trusted Registry admission ONLY for APPROVED artifacts
        if policy_result["decision"] == "APPROVE" and composite_hash:
            repo_display_name = metadata.get("full_name") or f"{parsed['owner']}/{parsed['repo']}"
            cert = issue_certificate(
                assessment_id=assessment_id,
                repository_url=parsed["normalized_url"],
                repository_name=repo_display_name,
                artifact_hash=composite_hash,
            )
            save_certificate_record(
                artifact_id=artifact_id,
                certificate_id=cert["certificate_id"],
                assessment_id=assessment_id,
                repository_url=parsed["normalized_url"],
                artifact_hash=composite_hash,
                issuer=cert["issuer"],
                algorithm=cert["algorithm"],
                payload=cert["payload"],
                signature_b64=cert["signature_b64"],
                certificate_path=cert["certificate_path"],
                status=cert["status"],
            )
            admit_artifact_to_registry(
                artifact_id=artifact_id,
                decision=policy_result["decision"],
                certificate_id=cert["certificate_id"],
                repository_name=repo_display_name,
                repository_url=parsed["normalized_url"],
                platform=parsed["platform"],
                artifact_hash=composite_hash,
            )

        update_artifact_record(
            artifact_id,
            {"status": "COMPLETED", "completed_at": utc_now_iso()},
        )

        # Step 12: Generate PDF assessment report
        bundle = get_assessment_full(artifact_id)
        if bundle:
            report_info = generate_pdf_report(bundle)
            save_report_record(
                artifact_id=artifact_id,
                assessment_id=assessment_id,
                report_filename=report_info["report_filename"],
                report_path=report_info["report_path"],
            )
            bundle = get_assessment_full(artifact_id)

        return bundle

    except Exception as exc:
        logger.exception("Assessment %s failed: %s", assessment_id, exc)
        update_artifact_record(
            artifact_id,
            {"status": "FAILED", "completed_at": utc_now_iso()},
        )
        save_policy_decision(
            artifact_id=artifact_id,
            decision="REJECT",
            risk_classification="HIGH",
            violations=[
                {
                    "rule_id": "ACQ-ERR",
                    "module": "repository_acquisition",
                    "action": "REJECT",
                    "severity": "HIGH",
                    "message": f"Repository acquisition failed: {exc}",
                }
            ],
            reason=f"Assessment could not be completed because repository acquisition failed: {exc}",
        )
        raise


# ---------------------------------------------------------------------------
# Web Routes (5 Required Pages + Downloads + Verification Actions)
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals() -> dict[str, Any]:
    return {
        "app_name": Config.APP_NAME,
        "app_subtitle": Config.APP_SUBTITLE,
        "app_version": Config.APP_VERSION,
    }


@app.route("/", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def index():
    """Page 1: Home / Repository Submission."""
    summary = get_dashboard_summary(artifact_ids=visible_artifact_ids())
    tools = get_scanner_tool_status()
    return render_template(
        "index.html",
        active_page="home",
        stats=summary["stats"],
        recent=summary["recent_assessments"][:5],
        tools=tools,
    )


@app.route("/analyze", methods=["POST"])
@roles_required("developer", "administrator")
def analyze():
    """Validate and execute security assessment for a submitted GitHub or Hugging Face repository."""
    is_json = request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    raw_url = (request.get_json(silent=True) or {}).get("repository_url", "") if request.is_json else request.form.get("repository_url", "")
    raw_url = str(raw_url or "").strip()

    try:
        validate_repository_url(raw_url)
    except ValidationError as exc:
        if is_json:
            return jsonify({"ok": False, "error": str(exc)}), 400
        flash(str(exc), "danger")
        return redirect(url_for("index"))

    try:
        bundle = run_full_assessment(raw_url, auth_user_id=current_user.id)
        artifact_id = bundle["artifact"]["id"]
        decision = (bundle.get("policy_decision") or {}).get("decision", "REVIEW")
        if is_json:
            return jsonify({
                "ok": True,
                "artifact_id": artifact_id,
                "assessment_id": bundle["artifact"]["assessment_id"],
                "decision": decision,
                "redirect_url": url_for("analysis_detail", artifact_id=artifact_id),
            })
        flash(
            f"Assessment {bundle['artifact']['assessment_id']} completed — Decision: {decision}.",
            "success" if decision == "APPROVE" else ("warning" if decision == "REVIEW" else "danger"),
        )
        return redirect(url_for("analysis_detail", artifact_id=artifact_id))
    except (ValidationError, ValueError, RuntimeError) as exc:
        if is_json:
            return jsonify({"ok": False, "error": str(exc)}), 400
        flash(f"Repository assessment failed: {exc}", "danger")
        return redirect(url_for("index"))
    except Exception as exc:
        logger.exception("Unexpected error during /analyze: %s", exc)
        if is_json:
            return jsonify({"ok": False, "error": f"Internal analysis error: {exc}"}), 500
        flash(f"Unexpected analysis error: {exc}", "danger")
        return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def dashboard():
    """Page 2: Security Assessment Dashboard."""
    summary = get_dashboard_summary(artifact_ids=visible_artifact_ids())
    tools = get_scanner_tool_status()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=summary["stats"],
        assessments=summary["recent_assessments"],
        module_stats=summary["module_stats"],
        tools=tools,
    )


@app.route("/analysis", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def analysis_latest():
    """Redirect to the most recent security analysis, or show empty state."""
    summary = get_dashboard_summary(artifact_ids=visible_artifact_ids())
    recent = summary["recent_assessments"]
    if recent:
        return redirect(url_for("analysis_detail", artifact_id=recent[0]["id"]))
    return render_template("analysis.html", active_page="analysis", bundle=None)


@app.route("/analysis/<int:artifact_id>", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def analysis_detail(artifact_id: int):
    """Page 3: Detailed Security Analysis per module."""
    if not require_artifact_access(artifact_id, "analysis_view"):
        abort(404)
    bundle = get_assessment_full(artifact_id)
    if not bundle:
        abort(404)
    return render_template("analysis.html", active_page="analysis", bundle=bundle)


@app.route("/report", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def report_latest():
    """Redirect to the most recent assessment report, or show empty state."""
    summary = get_dashboard_summary(artifact_ids=visible_artifact_ids())
    recent = summary["recent_assessments"]
    if recent:
        return redirect(url_for("report_detail", artifact_id=recent[0]["id"]))
    return render_template("report.html", active_page="report", bundle=None)


@app.route("/report/<int:artifact_id>", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def report_detail(artifact_id: int):
    """Page 4: Assessment Report overview and PDF download."""
    if not require_artifact_access(artifact_id, "report_view"):
        abort(404)
    bundle = get_assessment_full(artifact_id)
    if not bundle:
        abort(404)
    permissions = []
    users = []
    if current_user.has_role("administrator"):
        permissions = ReportPermission.query.filter_by(artifact_id=artifact_id).order_by(
            ReportPermission.created_at.desc()
        ).all()
        users = User.query.order_by(User.username.asc()).all()
    return render_template(
        "report.html", active_page="report", bundle=bundle,
        report_permissions=permissions, user_options=users,
    )


@app.route("/report/<int:artifact_id>/permissions", methods=["POST"])
@roles_required("administrator")
def manage_report_permission(artifact_id: int):
    """Administrators grant or revoke access to one report for a selected account."""
    if not artifact_exists(artifact_id):
        abort(404)
    action = request.form.get("action", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    target = User.query.filter(func.lower(User.email) == email).first() if email else None
    if target is None:
        abort(404)
    if action == "grant":
        changed = grant_report_access(artifact_id, target.id)
        flash("Report access granted." if changed else "That account already has report access.", "success")
    elif action == "revoke":
        changed = revoke_report_access(artifact_id, target.id)
        flash("Report access revoked." if changed else "That account had no report grant.", "info")
    else:
        abort(400)
    return redirect(url_for("report_detail", artifact_id=artifact_id))


@app.route("/report/<int:artifact_id>/download", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def download_report(artifact_id: int):
    """Download generated ReportLab PDF report (generates on-demand if missing)."""
    if not require_artifact_access(artifact_id):
        abort(404)
    bundle = get_assessment_full(artifact_id)
    if not bundle:
        abort(404)

    report = bundle.get("report")
    report_path = Path(report["report_path"]) if report and report.get("report_path") else None

    if not report_path or not report_path.exists():
        info = generate_pdf_report(bundle)
        save_report_record(
            artifact_id=artifact_id,
            assessment_id=bundle["artifact"]["assessment_id"],
            report_filename=info["report_filename"],
            report_path=info["report_path"],
        )
        report_path = Path(info["report_path"])

    write_report_audit("pdf_download", artifact_id)
    return send_file(
        str(report_path),
        as_attachment=True,
        download_name=report_path.name,
        mimetype="application/pdf",
    )


@app.route("/sbom/<int:artifact_id>/download", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def download_sbom(artifact_id: int):
    """Download generated CycloneDX JSON SBOM file if available."""
    if not require_artifact_access(artifact_id):
        abort(404)
    bundle = get_assessment_full(artifact_id)
    if not bundle:
        abort(404)

    sbom_scan = bundle["scans"].get("sbom") or {}
    sbom_path_str = (sbom_scan.get("raw_details") or {}).get("sbom_path")
    if not sbom_path_str or not Path(sbom_path_str).exists():
        flash("SBOM JSON file is not available for this assessment.", "warning")
        return redirect(url_for("analysis_detail", artifact_id=artifact_id))

    sbom_path = Path(sbom_path_str)
    write_report_audit("sbom_download", artifact_id)
    return send_file(
        str(sbom_path),
        as_attachment=True,
        download_name=sbom_path.name,
        mimetype="application/json",
    )


@app.route("/registry", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def registry():
    """Page 5: Trusted AI Artifact Registry."""
    query = request.args.get("q", "").strip()
    entries = list_trusted_artifacts(search_query=query)
    return render_template(
        "registry.html",
        active_page="registry",
        entries=entries,
        search_query=query,
    )


@app.route("/registry/<int:artifact_id>/verify", methods=["POST"])
@roles_required("developer", "administrator")
def verify_registry_artifact(artifact_id: int):
    """Re-verify SHA-256 hash integrity and RSA digital signature for a registered artifact."""
    is_json = request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    try:
        result = reverify_trusted_artifact(artifact_id)
        if is_json:
            return jsonify({"ok": True, "verification": result})
        if result["overall_verified"]:
            flash(
                f"Integrity & Signature VERIFIED for {result['repository_name']} ({result['assessment_id']}).",
                "success",
            )
        else:
            flash(
                f"VERIFICATION FAILED for {result['repository_name']}: "
                f"{result['integrity_result']['reason']} | {result['signature_result']['reason']}",
                "danger",
            )
        return redirect(url_for("registry"))
    except Exception as exc:
        if is_json:
            return jsonify({"ok": False, "error": str(exc)}), 400
        flash(f"Verification error: {exc}", "danger")
        return redirect(url_for("registry"))


# ---------------------------------------------------------------------------
# JSON API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok",
        "application": Config.APP_NAME,
        "version": Config.APP_VERSION,
        "tools": get_scanner_tool_status(),
    })


@app.route("/api/assessments/<int:artifact_id>", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def api_assessment_detail(artifact_id: int):
    if not require_artifact_access(artifact_id, "analysis_view"):
        return jsonify({"error": "Assessment not found"}), 404
    bundle = get_assessment_full(artifact_id)
    if not bundle:
        return jsonify({"error": "Assessment not found"}), 404
    return jsonify(bundle)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
