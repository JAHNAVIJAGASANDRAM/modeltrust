"""User model."""
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, login_manager

USER_ROLES = ("developer", "authorized_user", "administrator")


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(24), nullable=False, default="developer")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # Retained for compatibility with databases created before role based access.
    is_admin = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.CheckConstraint(
            "role IN ('developer', 'authorized_user', 'administrator')",
            name="ck_users_role",
        ),
    )

    submissions = db.relationship("Submission", backref="submitter", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles: str) -> bool:
        """Return whether the user has one of the named roles."""
        if self.role == "administrator" or self.is_admin:
            return "administrator" in roles
        return self.role in roles

    def __repr__(self) -> str:
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
