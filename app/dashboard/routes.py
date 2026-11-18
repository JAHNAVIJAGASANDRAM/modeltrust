"""Dashboard routes."""
from flask import render_template, redirect, url_for
from flask_login import login_required, current_user
from app.dashboard import dashboard_bp
from app.models.submission import Submission
from app.models.scan_result import ScanResult
from app.extensions import db


@dashboard_bp.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    submissions = (
        Submission.query.filter_by(user_id=current_user.id)
        .order_by(Submission.created_at.desc())
        .all()
    )

    # Stats
    total = len(submissions)
    completed = sum(1 for s in submissions if s.status == "completed")
    avg_score = 0.0
    scores = []
    for s in submissions:
        scan = s.latest_scan
        if scan:
            scores.append(scan.trust_score)
    if scores:
        avg_score = sum(scores) / len(scores)

    return render_template(
        "dashboard/index.html",
        title="Dashboard",
        submissions=submissions,
        total=total,
        completed=completed,
        avg_score=round(avg_score, 1),
    )
