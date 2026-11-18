"""Submissions routes — create, view, delete, re-scan."""
from flask import render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app.submissions import submissions_bp
from app.submissions.forms import SubmissionForm
from app.models.submission import Submission
from app.models.scan_result import ScanResult
from app.scanner.engine import run_scan
from app.extensions import db


@submissions_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    form = SubmissionForm()
    if form.validate_on_submit():
        sub = Submission(
            user_id=current_user.id,
            name=form.name.data,
            description=form.description.data,
            repo_url=form.repo_url.data or None,
            model_type=form.model_type.data or None,
            framework=form.framework.data or None,
            status="scanning",
        )
        db.session.add(sub)
        db.session.commit()

        # Run the trust scan synchronously (async queue optional in future)
        try:
            result = run_scan(sub)
            db.session.add(result)
            sub.status = "completed"
        except Exception as exc:
            sub.status = "failed"
            flash(f"Scan error: {exc}", "danger")
        db.session.commit()

        flash(f"Submission '{sub.name}' scanned successfully!", "success")
        return redirect(url_for("submissions.detail", submission_id=sub.id))

    return render_template("submissions/new.html", form=form, title="New Submission")


@submissions_bp.route("/<int:submission_id>")
@login_required
def detail(submission_id: int):
    sub = db.session.get(Submission, submission_id)
    if sub is None or sub.user_id != current_user.id:
        abort(404)
    scan = sub.latest_scan
    return render_template(
        "submissions/detail.html",
        submission=sub,
        scan=scan,
        title=sub.name,
    )


@submissions_bp.route("/<int:submission_id>/rescan", methods=["POST"])
@login_required
def rescan(submission_id: int):
    sub = db.session.get(Submission, submission_id)
    if sub is None or sub.user_id != current_user.id:
        abort(404)
    sub.status = "scanning"
    db.session.commit()
    try:
        result = run_scan(sub)
        db.session.add(result)
        sub.status = "completed"
        flash("Re-scan completed.", "success")
    except Exception as exc:
        sub.status = "failed"
        flash(f"Re-scan error: {exc}", "danger")
    db.session.commit()
    return redirect(url_for("submissions.detail", submission_id=sub.id))


@submissions_bp.route("/<int:submission_id>/delete", methods=["POST"])
@login_required
def delete(submission_id: int):
    sub = db.session.get(Submission, submission_id)
    if sub is None or sub.user_id != current_user.id:
        abort(404)
    name = sub.name
    db.session.delete(sub)
    db.session.commit()
    flash(f"Submission '{name}' deleted.", "info")
    return redirect(url_for("dashboard.dashboard"))
