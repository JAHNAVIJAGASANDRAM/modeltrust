"""ScanResult model — stores individual scanner outputs and aggregate trust score."""
from datetime import datetime, timezone
import json
from app.extensions import db


class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey("submissions.id"), nullable=False)

    # Aggregate
    trust_score = db.Column(db.Float, default=0.0)

    # Individual check scores (0-20 each)
    license_score = db.Column(db.Float, default=0.0)
    model_card_score = db.Column(db.Float, default=0.0)
    dependency_score = db.Column(db.Float, default=0.0)
    bias_score = db.Column(db.Float, default=0.0)
    readme_score = db.Column(db.Float, default=0.0)

    # Detailed findings stored as JSON text
    license_detail = db.Column(db.Text, default="{}")
    model_card_detail = db.Column(db.Text, default="{}")
    dependency_detail = db.Column(db.Text, default="{}")
    bias_detail = db.Column(db.Text, default="{}")
    readme_detail = db.Column(db.Text, default="{}")

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # ---- helpers ----
    def get_detail(self, field: str) -> dict:
        raw = getattr(self, f"{field}_detail", "{}")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_detail(self, field: str, data: dict) -> None:
        setattr(self, f"{field}_detail", json.dumps(data))

    @property
    def grade(self) -> str:
        if self.trust_score >= 90:
            return "A"
        elif self.trust_score >= 75:
            return "B"
        elif self.trust_score >= 60:
            return "C"
        elif self.trust_score >= 40:
            return "D"
        return "F"

    @property
    def grade_color(self) -> str:
        mapping = {"A": "success", "B": "info", "C": "warning", "D": "danger", "F": "dark"}
        return mapping.get(self.grade, "secondary")

    def __repr__(self) -> str:
        return f"<ScanResult submission={self.submission_id} score={self.trust_score}>"
