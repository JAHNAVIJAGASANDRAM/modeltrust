"""Flask application factory."""
import os
import click
from flask import Flask
from sqlalchemy import func
from app.config import config
from app.extensions import db, migrate, login_manager, csrf


def create_app(config_name: str | None = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")
    if config_name == "production" and not os.environ.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY must be set when running the production configuration.")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config.get(config_name, config["default"]))

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Import models so Migrate sees them
    from app.models import user, submission, scan_result, report_access  # noqa: F401

    # Register blueprints
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp
    from app.submissions import submissions_bp
    from app.api import api_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/")
    app.register_blueprint(submissions_bp, url_prefix="/submissions")
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    @app.cli.command("set-user-role")
    @click.argument("email")
    @click.argument("role", type=click.Choice(user.USER_ROLES, case_sensitive=False))
    def set_user_role(email: str, role: str) -> None:
        """Set an account role from the trusted server command line."""
        account = user.User.query.filter(
            func.lower(user.User.email) == email.strip().lower()
        ).first()
        if account is None:
            raise click.ClickException("No account exists for that email address.")
        account.role = role.lower()
        account.is_admin = account.role == "administrator"
        db.session.commit()
        click.echo(f"Updated account role to {account.role}.")

    # Inject csrf_token helper into all templates
    from flask_wtf.csrf import generate_csrf

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf()}

    return app
