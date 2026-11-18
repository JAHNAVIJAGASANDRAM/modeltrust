"""Central configuration for ModelTrust – A Secure AI Artifact Trust and Supply Chain Framework."""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Application, security, and organizational policy configuration."""

    APP_NAME = "ModelTrust"
    APP_SUBTITLE = "A Secure AI Artifact Trust and Supply Chain Framework"
    APP_VERSION = "1.0.0"

    SECRET_KEY = os.environ.get("SECRET_KEY", "modeltrust-dev-secret-change-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

    # Paths
    BASE_DIR = BASE_DIR
    FRONTEND_DIR = BASE_DIR / "frontend"
    TEMPLATE_DIR = FRONTEND_DIR / "templates"
    STATIC_DIR = FRONTEND_DIR / "static"

    DATABASE_DIR = BASE_DIR / "database"
    DATABASE_PATH = Path(os.environ.get("MODELTRUST_DB_PATH", str(DATABASE_DIR / "modeltrust.db")))
    SCHEMA_PATH = DATABASE_DIR / "schema.sql"

    STORAGE_DIR = BASE_DIR / "storage"
    DOWNLOADS_DIR = STORAGE_DIR / "downloaded_repositories"
    SBOM_DIR = STORAGE_DIR / "sbom_files"
    REPORTS_DIR = STORAGE_DIR / "reports"
    CERTIFICATES_DIR = STORAGE_DIR / "certificates"
    KEYS_DIR = CERTIFICATES_DIR / "keys"
    LOGS_DIR = STORAGE_DIR / "logs"

    # Optional API tokens (never exposed to frontend or templates)
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
    HUGGINGFACE_TOKEN = os.environ.get("HUGGINGFACE_TOKEN", "")

    # External tool paths (optional overrides; auto-discovered via PATH / sys.executable if empty)
    SYFT_BINARY = os.environ.get("SYFT_BINARY", "syft")

    # Security & resource limits
    MAX_DOWNLOAD_SIZE_MB = int(os.environ.get("MAX_DOWNLOAD_SIZE_MB", "50"))
    MAX_DOWNLOAD_SIZE_BYTES = MAX_DOWNLOAD_SIZE_MB * 1024 * 1024
    MAX_SINGLE_FILE_MB = int(os.environ.get("MAX_SINGLE_FILE_MB", "20"))
    MAX_SINGLE_FILE_BYTES = MAX_SINGLE_FILE_MB * 1024 * 1024
    MAX_FILE_COUNT = int(os.environ.get("MAX_FILE_COUNT", "1500"))
    HTTP_TIMEOUT_SECONDS = int(os.environ.get("HTTP_TIMEOUT_SECONDS", "25"))
    TOOL_TIMEOUT_SECONDS = int(os.environ.get("TOOL_TIMEOUT_SECONDS", "90"))

    # Allowed repository hostnames (strict SSRF allowlist)
    ALLOWED_REPO_HOSTS = frozenset({
        "github.com",
        "www.github.com",
        "huggingface.co",
        "www.huggingface.co",
    })

    # Organizational Policy Enforcement Rules (configurable)
    POLICY_RULES = {
        # Rule 1: High/Critical static code findings (e.g., command exec, eval/exec, shell injection) -> REJECT
        "reject_on_critical_sast": True,
        "sast_reject_severities": ["CRITICAL", "HIGH"],
        "sast_review_severities": ["MEDIUM", "LOW"],

        # Rule 2: Critical/High dependency vulnerabilities -> REJECT
        "reject_on_critical_vulnerabilities": True,
        "vuln_reject_severities": ["CRITICAL", "HIGH"],
        "vuln_review_severities": ["MEDIUM", "LOW", "UNKNOWN"],

        # Rule 3: Failed integrity verification (hash mismatch / tampering) -> REJECT
        "reject_on_integrity_failure": True,

        # Rule 4: Serialization safety policy
        # Malicious pickle payloads detected by PickleScan -> REJECT
        "reject_on_malicious_serialization": True,
        # Presence of unsafe pickle/legacy formats without malicious globals -> REVIEW or REJECT
        "unsafe_serialization_format_action": os.environ.get("POLICY_UNSAFE_SERIALIZATION_ACTION", "REVIEW"),

        # Rule 5: Unverified repository provenance -> REVIEW
        "review_on_unverified_provenance": True,

        # Rule 6: Minor security warnings -> REVIEW
        "review_on_minor_warnings": True,

        # Rule 7: Mandatory security checks that must actually execute (not NOT SCANNED) for APPROVE
        # If any mandatory check is NOT SCANNED, artifact cannot be auto-approved (forced to REVIEW).
        "mandatory_checks": [
            "provenance",
            "static_analysis",
            "dependency_analysis",
            "serialization_analysis",
            "integrity",
            "sbom",
        ],
        "require_sbom_for_approval": os.environ.get("POLICY_REQUIRE_SBOM", "true").lower() == "true",
    }

    @classmethod
    def ensure_directories(cls) -> None:
        """Create required storage and database directories if missing."""
        for path in [
            cls.DATABASE_DIR,
            cls.STORAGE_DIR,
            cls.DOWNLOADS_DIR,
            cls.SBOM_DIR,
            cls.REPORTS_DIR,
            cls.CERTIFICATES_DIR,
            cls.KEYS_DIR,
            cls.LOGS_DIR,
        ]:
            path.mkdir(parents=True, exist_ok=True)
