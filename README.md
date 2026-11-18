# ModelTrust – A Secure AI Artifact Trust and Supply Chain Framework

**ModelTrust** is a web-based AI supply chain security gateway built with **Python, Flask, SQLite, Bootstrap 5, and JavaScript**. It evaluates AI repositories sourced from **GitHub** and **Hugging Face** through independent security analysis modules, enforces configurable organizational security policies, digitally signs approved artifacts, admits only approved artifacts into a **Trusted AI Artifact Registry**, and generates downloadable **PDF Security Assessment Reports**.

---

## Key Capabilities & Modules

1. **Repository Acquisition (`modules/repository_acquisition/`)**
   - Supports HTTPS GitHub (`https://github.com/<owner>/<repo>`) and Hugging Face (`https://huggingface.co/<owner>/<model>`) URLs.
   - Strict URL validation, hostname allowlisting, SSRF defenses, Zip-Slip path traversal protection, and bounded download size/file-count caps.
   - Never executes downloaded repository code.
2. **Repository Provenance Analysis (`modules/provenance/`)**
   - Evaluates ownership, publisher identity, creation/update timestamps, releases, commit history/signatures, and metadata consistency.
   - Does **not** treat repository popularity or age as proof of trustworthiness.
3. **Static Code Security Analysis (`modules/static_analysis/`)**
   - Integrates **Bandit** to scan `.py` source files statically for dangerous constructs, command execution, and unsafe functions without running repository code.
4. **Dependency Vulnerability Analysis (`modules/dependency_analysis/`)**
   - Statically parses `requirements.txt`, `pyproject.toml`, `setup.py` (AST-only), `environment.yml`, and `package.json`.
   - Runs **pip-audit** (safe `--no-deps --disable-pip` mode) and queries the live **OSV API** (`https://api.osv.dev/v1/querybatch`).
5. **Serialization Safety Analysis (`modules/serialization_analysis/`)**
   - Identifies model formats (`.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.joblib`, `.safetensors`, `.onnx`, etc.).
   - Scans Pickle-based artifacts using **PickleScan** without deserializing untrusted files, and recommends safer formats (`safetensors`, `ONNX`).
6. **Integrity Verification (`modules/integrity/`)**
   - Generates streaming per-file **SHA-256** hashes and a deterministic composite repository SHA-256 digest.
   - Supports on-demand integrity re-verification to detect tampering or drift.
7. **SBOM Generation (`modules/sbom/`)**
   - Integrates **Anchore Syft** to generate CycloneDX JSON SBOMs stored under `storage/sbom_files/`.
   - Gracefully reports `NOT SCANNED` with installation instructions if Syft is not installed.
8. **Policy Enforcement Engine (`modules/policy_engine/`)**
   - Evaluates all scan results against configurable rules in `config.py` (`Config.POLICY_RULES`) and classifies each artifact as **APPROVE**, **REVIEW**, or **REJECT**.
   - Never auto-approves artifacts when mandatory security checks fail or are `NOT SCANNED`.
9. **Trust Certification (`modules/certification/`)**
   - Generates an organizational **RSA-2048 (PSS + SHA-256)** key pair stored strictly outside web-served directories (`storage/certificates/keys/`).
   - Digitally signs approved artifact metadata (`repository_url`, `artifact_hash`, `assessment_id`, `issue_date`) and supports cryptographic verification.
10. **Trusted AI Artifact Registry (`modules/registry/`)**
    - SQLite-backed registry admitting **only** `APPROVE`d and digitally certified artifacts, with search and live SHA-256 + RSA signature re-verification.
11. **Security Assessment Reporting (`modules/reporting/`)**
    - Generates structured executive PDF assessment reports using **ReportLab** stored in `storage/reports/`.

---

## Project Structure

```text
modeltrust/
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── frontend/
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── dashboard.html
│   │   ├── analysis.html
│   │   ├── report.html
│   │   └── registry.html
│   └── static/
│       ├── css/style.css
│       ├── js/script.js
│       └── images/
├── modules/
│   ├── repository_acquisition/
│   ├── provenance/
│   ├── static_analysis/
│   ├── dependency_analysis/
│   ├── serialization_analysis/
│   ├── integrity/
│   ├── sbom/
│   ├── policy_engine/
│   ├── certification/
│   ├── reporting/
│   └── registry/
├── database/
│   ├── db.py
│   └── schema.sql
├── storage/
│   ├── downloaded_repositories/
│   ├── sbom_files/
│   ├── reports/
│   └── certificates/
└── utils/
    ├── validators.py
    └── logger.py
```

---

## Installation & Setup

### 1. Prerequisites
- Python **3.11+** (tested on Python 3.13)
- (Optional, recommended for full SBOM generation) **Anchore Syft** CLI:
  - Windows: `winget install Anchore.Syft`
  - macOS: `brew install syft`
  - Linux: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Optional Environment Configuration
Create or edit `.env` in the project root:
```env
SECRET_KEY=replace-with-a-strong-secret-key
FLASK_DEBUG=true
# Optional tokens for higher API rate limits or gated repositories (never exposed in UI)
GITHUB_TOKEN=
HUGGINGFACE_TOKEN=
# Optional policy tuning: REVIEW or REJECT for non-malicious Pickle formats
POLICY_UNSAFE_SERIALIZATION_ACTION=REVIEW
# Set to false only if running without Syft installed
POLICY_REQUIRE_SBOM=true
```

### 4. Run the Application
```bash
python app.py
```
Then open **http://127.0.0.1:5000** in your browser.

The SQLite database (`database/modeltrust.db`), storage directories, and organizational RSA-2048 signing keys (`storage/certificates/keys/`) are automatically initialized on first startup.

---

## Security Practices Implemented
- Untrusted repository code is **never** executed (`setup.py` is parsed with Python `ast` only).
- Untrusted Pickle / PyTorch files are **never** deserialized (`picklescan` inspects pickle opcodes statically).
- URL validation enforces HTTPS + strict `github.com` / `huggingface.co` hostname allowlisting + private IP SSRF checks.
- Archive extraction prevents Zip Slip path traversal and skips symlinks.
- All external CLI tools run with `shell=False` and strict execution timeouts.
- Scan statuses explicitly distinguish **PASS**, **WARNING**, **FAIL**, and **NOT SCANNED**.
