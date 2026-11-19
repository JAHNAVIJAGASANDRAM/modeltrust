"""Auth routes — register, login, logout."""
from urllib.parse import urlsplit

from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError
from app.auth import auth_bp
from app.auth.forms import RegistrationForm, LoginForm
from app.models.user import User
from app.extensions import db
from sqlalchemy import func


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role="developer",
        )
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That username or email is already registered.", "danger")
            return render_template("auth/register.html", form=form, title="Register"), 409
        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form, title="Register")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first()
        if user and user.check_password(form.password.data):
            session.clear()
            session.permanent = True
            login_user(user, remember=form.remember.data)
            next_page = _safe_next_url(request.args.get("next"))
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(next_page or url_for("dashboard.index"))
        flash("Invalid email or password.", "danger")
    return render_template("auth/login.html", form=form, title="Sign In")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


def _safe_next_url(target: str | None) -> str | None:
    """Allow only same-origin absolute paths as post-login destinations."""
    if not target or any(char in target for char in ("\\", "\r", "\n", "\x00")):
        return None
    try:
        parsed = urlsplit(target)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc:
        if parsed.scheme != request.scheme or parsed.netloc != request.host:
            return None
        return target
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target
