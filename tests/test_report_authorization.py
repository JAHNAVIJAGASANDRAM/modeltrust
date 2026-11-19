import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config as root_config
import database.db as artifact_db
from app.extensions import db as auth_db
from app.config import config as auth_config
from app.models import ReportAuditLog, ReportPermission, User


def load_monolith_app():
    """Import the full assessment app without running its local startup initializers."""
    spec = importlib.util.spec_from_file_location(
        "modeltrust_monolith_test_app", Path(__file__).resolve().parents[1] / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    with (
        patch.object(root_config.Config, "ensure_directories"),
        patch.object(artifact_db, "init_db"),
        patch.object(auth_config["development"], "SQLALCHEMY_DATABASE_URI", "sqlite://"),
        patch("modules.certification.certificate_manager.ensure_org_keypair"),
    ):
        spec.loader.exec_module(module)
    return module


class ReportAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_db_path = root_config.Config.DATABASE_PATH
        cls.temp_root = tempfile.TemporaryDirectory(prefix="modeltrust-report-auth-")
        root_config.Config.DATABASE_PATH = Path(cls.temp_root.name) / "artifacts.sqlite"
        cls.module = load_monolith_app()
        cls.app = cls.module.app
        cls.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            SQLALCHEMY_DATABASE_URI="sqlite://",
            SECRET_KEY="report-auth-test-key",
        )
        with patch.object(artifact_db.logger, "info"):
            artifact_db.init_db(root_config.Config.DATABASE_PATH)
        cls.clients = {}

    @classmethod
    def tearDownClass(cls):
        root_config.Config.DATABASE_PATH = cls.old_db_path
        cls.temp_root.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            auth_db.drop_all()
            auth_db.create_all()
            self.owner = self._add_user("report-owner", "owner@example.com", "developer")
            self.authorized = self._add_user("report-reader", "reader@example.com", "authorized_user")
            self.outsider = self._add_user("outsider", "outsider@example.com", "developer")
            self.admin = self._add_user("administrator", "admin@example.com", "administrator")
            self.owner_id = self.owner.id
            auth_db.session.commit()

        conn = artifact_db.get_db_connection()
        try:
            conn.execute("DELETE FROM artifacts")
            cur = conn.execute(
                """INSERT INTO artifacts
                   (assessment_id, user_id, repository_url, platform, owner, repo_name,
                    auth_user_id, repo_type, status, submitted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("TEST-1", None, "https://github.com/owner/repo", "github", "owner", "repo",
                 self.owner_id, "repository", "COMPLETED", "2026-11-19T00:00:00Z"),
            )
            self.artifact_id = int(cur.lastrowid)
            conn.commit()
        finally:
            conn.close()
        self._login("owner@example.com")

    def tearDown(self):
        with self.app.app_context():
            auth_db.session.remove()
            auth_db.drop_all()

    @staticmethod
    def _add_user(username, email, role):
        user = User(username=username, email=email, role=role, is_admin=(role == "administrator"))
        user.set_password("safe-test-password")
        auth_db.session.add(user)
        auth_db.session.flush()
        return user

    def _login(self, email):
        response = self.client.post(
            "/auth/login", data={"email": email, "password": "safe-test-password"}
        )
        self.assertIn(response.status_code, (302, 303))

    def _switch_user(self, email):
        self.client.post("/auth/logout")
        self._login(email)

    def _audit_actions(self):
        with self.app.app_context():
            return [row.action for row in ReportAuditLog.query.order_by(ReportAuditLog.id).all()]

    def test_owner_can_view_report_and_analysis(self):
        with patch.object(self.module, "render_template", return_value="private report"):
            self.assertEqual(self.client.get(f"/report/{self.artifact_id}").status_code, 200)
            self.assertEqual(self.client.get(f"/analysis/{self.artifact_id}").status_code, 200)
        self.assertEqual(self._audit_actions(), ["report_view", "analysis_view"])

    def test_manually_changed_id_is_hidden_from_unauthorized_user(self):
        self._switch_user("outsider@example.com")
        with patch.object(self.module, "get_assessment_full") as get_bundle:
            response = self.client.get(f"/report/{self.artifact_id}")
            self.assertEqual(response.status_code, 404)
            get_bundle.assert_not_called()
        self.assertEqual(self.client.get("/report/999999").status_code, 404)

    def test_administrator_can_view_any_report(self):
        self._switch_user("admin@example.com")
        with patch.object(self.module, "render_template", return_value="admin report"):
            self.assertEqual(self.client.get(f"/report/{self.artifact_id}").status_code, 200)

    def test_dashboard_data_is_limited_to_visible_assessments(self):
        owner_summary = artifact_db.get_dashboard_summary(
            artifact_ids=[self.artifact_id]
        )
        outsider_summary = artifact_db.get_dashboard_summary(artifact_ids=[])
        self.assertEqual(owner_summary["stats"]["total"], 1)
        self.assertEqual(outsider_summary["stats"]["total"], 0)
        self.assertEqual(outsider_summary["recent_assessments"], [])

    def test_administrator_grants_and_revokes_report_access(self):
        self._switch_user("admin@example.com")
        grant = self.client.post(
            f"/report/{self.artifact_id}/permissions",
            data={"action": "grant", "email": "reader@example.com"},
        )
        self.assertEqual(grant.status_code, 302)
        self._switch_user("reader@example.com")
        with patch.object(self.module, "render_template", return_value="shared report"):
            self.assertEqual(self.client.get(f"/report/{self.artifact_id}").status_code, 200)

        self._switch_user("admin@example.com")
        revoke = self.client.post(
            f"/report/{self.artifact_id}/permissions",
            data={"action": "revoke", "email": "reader@example.com"},
        )
        self.assertEqual(revoke.status_code, 302)
        self._switch_user("reader@example.com")
        self.assertEqual(self.client.get(f"/report/{self.artifact_id}").status_code, 404)
        self.assertEqual(self._audit_actions(), ["permission_granted", "report_view", "permission_revoked"])

    def test_non_admin_cannot_change_report_permissions(self):
        response = self.client.post(
            f"/report/{self.artifact_id}/permissions",
            data={"action": "grant", "email": "reader@example.com"},
        )
        self.assertEqual(response.status_code, 403)

    def test_pdf_download_requires_report_access_and_is_audited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "test.pdf"
            pdf_path.write_bytes(b"%PDF-test")
            bundle = {
                "artifact": {"id": self.artifact_id, "assessment_id": "TEST-1"},
                "report": {"report_path": str(pdf_path)},
            }
            with patch.object(self.module, "get_assessment_full", return_value=bundle):
                response = self.client.get(f"/report/{self.artifact_id}/download")
                self.assertEqual(response.status_code, 200)
                response.close()
                self._switch_user("outsider@example.com")
                denied = self.client.get(f"/report/{self.artifact_id}/download")
                self.assertEqual(denied.status_code, 404)
                denied.close()
        self.assertIn("pdf_download", self._audit_actions())

    def test_sbom_download_requires_report_access_and_is_audited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sbom_path = Path(temp_dir) / "test.json"
            sbom_path.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
            bundle = {
                "artifact": {"id": self.artifact_id, "assessment_id": "TEST-1"},
                "scans": {"sbom": {"raw_details": {"sbom_path": str(sbom_path)}}},
            }
            with patch.object(self.module, "get_assessment_full", return_value=bundle):
                response = self.client.get(f"/sbom/{self.artifact_id}/download")
                self.assertEqual(response.status_code, 200)
                response.close()
                self._switch_user("outsider@example.com")
                denied = self.client.get(f"/sbom/{self.artifact_id}/download")
                self.assertEqual(denied.status_code, 404)
                denied.close()
        self.assertIn("sbom_download", self._audit_actions())


if __name__ == "__main__":
    unittest.main()
