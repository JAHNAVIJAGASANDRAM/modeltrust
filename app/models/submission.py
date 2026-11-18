"""Submission model."""
from datetime import datetime, timezone
from sqlalchemy import text
from app.extensions import db


class Submission(db.Model):
    __tablename__ = "submissions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    repo_url = db.Column(db.String(512), nullable=True)
    model_type = db.Column(db.String(64), nullable=True)   # e.g. classification, NLP
    framework = db.Column(db.String(64), nullable=True)    # e.g. PyTorch, TensorFlow
    status = db.Column(
        db.String(32), default="pending", nullable=False
    )  # pending | scanning | completed | failed
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    scan_results = db.relationship(
        "ScanResult", backref="submission", lazy="dynamic", cascade="all, delete-orphan"
    )

    @property
    def latest_scan(self):
        return self.scan_results.order_by(
            text("created_at DESC")
        ).first()

    @property
    def trust_grade(self) -> str:
        scan = self.latest_scan
        if scan is None:
            return "N/A"
        score = scan.trust_score
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        return "F"

    def __repr__(self) -> str:
        return f"<Submission {self.name}>"
