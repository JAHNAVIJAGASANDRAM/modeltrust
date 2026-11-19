import unittest
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models.user import User


class AuthenticationAndRBACTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register(self, username="developer1", email="dev@example.com", password="correct-horse-1"):
        return self.client.post(
            "/auth/register",
            data={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": password,
                "role": "administrator",  # Unknown form input must not grant privileges.
            },
        )

    def login(self, email="dev@example.com", password="correct-horse-1", **query):
        return self.client.post(
            "/auth/login",
            query_string=query,
            data={"email": email, "password": password},
        )

    def test_registration_hashes_password_and_assigns_developer_role(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            user = User.query.filter_by(email="dev@example.com").one()
            self.assertEqual(user.role, "developer")
            self.assertNotEqual(user.password_hash, "correct-horse-1")
            self.assertTrue(user.password_hash.startswith("scrypt:"))
            self.assertTrue(user.check_password("correct-horse-1"))

    def test_login_uses_case_insensitive_email_and_secure_session_cookie(self):
        self.register()
        response = self.login(email="DEV@EXAMPLE.COM")
        self.assertEqual(response.status_code, 302)
        cookie = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        with self.client.session_transaction() as session:
            self.assertIn("_user_id", session)
            self.assertTrue(session.permanent)

    def test_invalid_password_does_not_create_an_authenticated_session(self):
        self.register()
        response = self.login(password="incorrect-password")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            self.assertNotIn("_user_id", session)

    def test_external_next_url_is_ignored(self):
        self.register()
        response = self.login(next="https://attacker.example/collect")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/"))

    def test_logout_is_post_only_and_clears_authentication(self):
        self.register()
        self.login()
        self.assertEqual(self.client.get("/auth/logout").status_code, 405)
        response = self.client.post("/auth/logout")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("_user_id", session)

    def test_protected_routes_redirect_anonymous_users(self):
        for path in ("/dashboard", "/submissions/new", "/api/v1/submissions"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/auth/login", response.headers["Location"])

    def test_authorized_user_cannot_create_developer_submission(self):
        self.register()
        self.client.post("/auth/logout")
        with self.app.app_context():
            account = User.query.filter_by(email="dev@example.com").one()
            account.role = "authorized_user"
            db.session.commit()
        self.login()
        self.assertEqual(self.client.get("/submissions/new").status_code, 403)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_submission_is_attributed_to_authenticated_user_and_url_is_normalized(self):
        self.register()
        self.login()
        with patch("utils.validators.validate_outbound_host"), patch(
            "app.submissions.routes.run_scan", side_effect=RuntimeError("scanner unavailable in test")
        ):
            response = self.client.post(
                "/submissions/new",
                data={"name": "Test Model", "repo_url": "org/model"},
            )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from app.models.submission import Submission

            submission = Submission.query.filter_by(name="Test Model").one()
            account = User.query.filter_by(email="dev@example.com").one()
            self.assertEqual(submission.user_id, account.id)
            self.assertEqual(submission.repo_url, "https://github.com/org/model")

    def test_operator_cli_can_assign_each_supported_role(self):
        self.register()
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["set-user-role", "DEV@example.com", "administrator"])
        self.assertEqual(result.exit_code, 0, result.output)
        with self.app.app_context():
            account = User.query.filter_by(email="dev@example.com").one()
            self.assertEqual(account.role, "administrator")
            self.assertTrue(account.is_admin)
        self.login()
        self.assertEqual(self.client.get("/submissions/new").status_code, 200)


if __name__ == "__main__":
    unittest.main()
