-- ModelTrust SQLite Database Schema
-- 7 Core Tables: users, artifacts, scan_results, policy_decisions, certificates, trusted_registry, reports

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL UNIQUE,
    user_id INTEGER,
    repository_url TEXT NOT NULL,
    platform TEXT NOT NULL,
    owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    repo_type TEXT NOT NULL DEFAULT 'repository',
    description TEXT,
    default_branch TEXT,
    repo_created_at TEXT,
    repo_updated_at TEXT,
    local_path TEXT,
    artifact_hash TEXT,
    file_count INTEGER DEFAULT 0,
    total_size_bytes INTEGER DEFAULT 0,
    metadata_json TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    submitted_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL,
    module_name TEXT NOT NULL,
    status TEXT NOT NULL,           -- PASS, WARNING, FAIL, NOT SCANNED
    severity TEXT NOT NULL,         -- NONE, LOW, MEDIUM, HIGH, CRITICAL
    summary TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    raw_details_json TEXT,
    tool_name TEXT,
    tool_available INTEGER NOT NULL DEFAULT 1,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL UNIQUE,
    decision TEXT NOT NULL,         -- APPROVE, REVIEW, REJECT
    risk_classification TEXT NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    violations_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    policy_snapshot_json TEXT,
    decided_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL UNIQUE,
    certificate_id TEXT NOT NULL UNIQUE,
    assessment_id TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    issuer TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    certificate_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'VALID',
    issued_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trusted_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL UNIQUE,
    certificate_id TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    platform TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    certification_status TEXT NOT NULL DEFAULT 'CERTIFIED',
    integrity_status TEXT NOT NULL DEFAULT 'VERIFIED',
    admitted_at TEXT NOT NULL,
    last_verified_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts (id) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id) REFERENCES certificates (certificate_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL UNIQUE,
    assessment_id TEXT NOT NULL,
    report_filename TEXT NOT NULL,
    report_path TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifacts_assessment_id ON artifacts (assessment_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_platform ON artifacts (platform);
CREATE INDEX IF NOT EXISTS idx_scan_results_artifact_id ON scan_results (artifact_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_decision ON policy_decisions (decision);
CREATE INDEX IF NOT EXISTS idx_trusted_registry_repo_name ON trusted_registry (repository_name);
