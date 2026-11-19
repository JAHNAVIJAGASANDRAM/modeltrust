import sqlite3
import unittest
from pathlib import Path


class ReportAuthorizationMigrationTests(unittest.TestCase):
    def test_sql_migration_adds_owner_column_to_legacy_artifacts_schema(self):
        project_root = Path(__file__).resolve().parents[1]
        schema = (project_root / "database" / "schema.sql").read_text(encoding="utf-8")
        # Reproduce the pre-Feature 3 schema without touching the user's DB.
        schema = schema.replace("    auth_user_id INTEGER,\n", "")
        migration = (project_root / "database" / "migrations" / "002_report_authorization.sql").read_text(
            encoding="utf-8"
        )
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(schema)
            conn.executescript(migration)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)")}
            self.assertIn("auth_user_id", columns)
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(artifacts)")}
            self.assertIn("idx_artifacts_auth_user_id", indexes)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
