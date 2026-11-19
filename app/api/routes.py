"""REST API v1 routes."""
from flask import jsonify, request, abort
from flask_login import current_user
from app.api import api_bp
from app.models.submission import Submission
from app.models.scan_result import ScanResult
from app.extensions import db
from app.auth.permissions import roles_required


def _submission_to_dict(sub: Submission) -> dict:
    scan = sub.latest_scan
    return {
        "id": sub.id,
        "name": sub.name,
        "description": sub.description,
        "repo_url": sub.repo_url,
        "model_type": sub.model_type,
        "framework": sub.framework,
        "status": sub.status,
        "trust_grade": sub.trust_grade,
        "trust_score": scan.trust_score if scan else None,
        "created_at": sub.created_at.isoformat(),
    }


def _scan_to_dict(scan: ScanResult) -> dict:
    return {
        "id": scan.id,
        "submission_id": scan.submission_id,
        "trust_score": scan.trust_score,
        "grade": scan.grade,
        "scores": {
            "license": scan.license_score,
            "model_card": scan.model_card_score,
            "dependency": scan.dependency_score,
            "bias": scan.bias_score,
            "readme": scan.readme_score,
        },
        "details": {
            "license": scan.get_detail("license"),
            "model_card": scan.get_detail("model_card"),
            "dependency": scan.get_detail("dependency"),
            "bias": scan.get_detail("bias"),
            "readme": scan.get_detail("readme"),
        },
        "created_at": scan.created_at.isoformat(),
    }


@api_bp.route("/submissions", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def list_submissions():
    subs = (
        Submission.query.filter_by(user_id=current_user.id)
        .order_by(Submission.created_at.desc())
        .all()
    )
    return jsonify({"submissions": [_submission_to_dict(s) for s in subs]})


@api_bp.route("/submissions/<int:submission_id>", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def get_submission(submission_id: int):
    sub = db.session.get(Submission, submission_id)
    if sub is None or sub.user_id != current_user.id:
        abort(404)
    return jsonify(_submission_to_dict(sub))


@api_bp.route("/submissions/<int:submission_id>/scan", methods=["GET"])
@roles_required("developer", "authorized_user", "administrator")
def get_scan(submission_id: int):
    sub = db.session.get(Submission, submission_id)
    if sub is None or sub.user_id != current_user.id:
        abort(404)
    scan = sub.latest_scan
    if not scan:
        return jsonify({"error": "No scan results yet"}), 404
    return jsonify(_scan_to_dict(scan))


@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})
