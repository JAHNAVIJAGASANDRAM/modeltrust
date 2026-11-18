"""Flask application factory."""
import os
from flask import Flask
from app.config import config
from app.extensions import db, migrate, login_manager


def create_app(config_name: str | None = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config.get(config_name, config["default"]))

    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Import models so Migrate sees them
    from app.models import user, submission, scan_result  # noqa: F401

    # Register blueprints
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp
    from app.submissions import submissions_bp
    from app.api import api_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/")
    app.register_blueprint(submissions_bp, url_prefix="/submissions")
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    # Inject csrf_token helper into all templates
    from flask_wtf.csrf import generate_csrf

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf()}

    return app
