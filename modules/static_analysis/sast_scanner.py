"""
Module 3: Static Code Security Analysis using Bandit.

Identifies Python source files and scans them statically with Bandit.
NEVER executes scanned source code.
Clearly reports NOT SCANNED if Bandit is not installed.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from config import Config
from utils.logger import get_logger

logger = get_logger("modeltrust.sast")


def is_bandit_available() -> bool:
    """Check whether the Bandit Python package is installed in the active environment."""
    return importlib.util.find_spec("bandit") is not None


def _rel_path(file_path: str, repo_dir: Path) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(repo_dir.resolve())).replace("\\", "/")
    except ValueError:
        return file_path


def run_sast_scan(repo_dir: Path) -> dict[str, Any]:
    """Scan Python files in repo_dir using Bandit without executing any repository code."""
    repo_dir = Path(repo_dir)
    python_files = sorted(p for p in repo_dir.rglob("*.py") if p.is_file())

    if not is_bandit_available():
        return {
            "module_name": "static_analysis",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": (
                "Bandit is not installed in the Python environment. "
                "Install it using: pip install bandit"
            ),
            "findings": [
                {
                    "title": "Bandit Static Analyzer Unavailable",
                    "severity": "MEDIUM",
                    "description": "Bandit could not be executed because the 'bandit' package is not installed.",
                    "recommendation": "Install Bandit via 'pip install bandit' and re-run the assessment.",
                }
            ],
            "raw_details": {
                "python_files_found": len(python_files),
                "install_hint": "pip install bandit",
            },
            "tool_name": "Bandit",
            "tool_available": False,
        }

    if not python_files:
        return {
            "module_name": "static_analysis",
            "status": "PASS",
            "severity": "NONE",
            "summary": "Bandit scan completed: no Python (.py) source files found in repository.",
            "findings": [],
            "raw_details": {
                "python_files_found": 0,
                "scanned_files": [],
                "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            },
            "tool_name": "Bandit",
            "tool_available": True,
        }

    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(repo_dir),
        "-f",
        "json",
        "--exit-zero",
        "--quiet",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Bandit timed out after %ss on %s", Config.TOOL_TIMEOUT_SECONDS, repo_dir)
        return {
            "module_name": "static_analysis",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Bandit scan timed out after {Config.TOOL_TIMEOUT_SECONDS} seconds.",
            "findings": [],
            "raw_details": {"python_files_found": len(python_files), "error": "timeout"},
            "tool_name": "Bandit",
            "tool_available": True,
        }
    except OSError as exc:
        logger.error("Failed to invoke Bandit: %s", exc)
        return {
            "module_name": "static_analysis",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Bandit execution failed: {exc}",
            "findings": [],
            "raw_details": {"python_files_found": len(python_files), "error": str(exc)},
            "tool_name": "Bandit",
            "tool_available": False,
        }

    stdout = (proc.stdout or "").strip()
    if not stdout:
        return {
            "module_name": "static_analysis",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Bandit returned empty output (stderr: {(proc.stderr or '')[:200]}).",
            "findings": [],
            "raw_details": {"stderr": (proc.stderr or "")[:500], "returncode": proc.returncode},
            "tool_name": "Bandit",
            "tool_available": True,
        }

    try:
        # Bandit occasionally emits warnings before JSON; locate opening brace
        json_start = stdout.find("{")
        payload = json.loads(stdout[json_start:] if json_start >= 0 else stdout)
    except json.JSONDecodeError as exc:
        logger.error("Could not parse Bandit JSON output: %s", exc)
        return {
            "module_name": "static_analysis",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": "Failed to parse Bandit JSON report.",
            "findings": [],
            "raw_details": {"error": str(exc), "raw_excerpt": stdout[:500]},
            "tool_name": "Bandit",
            "tool_available": True,
        }

    raw_results = payload.get("results") or []
    errors = payload.get("errors") or []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    findings: list[dict[str, Any]] = []

    # High-risk Bandit test IDs associated with arbitrary command / code execution
    command_exec_tests = {
        "B102", "B301", "B302", "B307", "B601", "B602", "B603", "B604", "B605", "B606", "B607", "B609"
    }

    for item in raw_results:
        sev = str(item.get("issue_severity") or "LOW").upper()
        conf = str(item.get("issue_confidence") or "LOW").upper()
        test_id = str(item.get("test_id") or "")
        test_name = str(item.get("test_name") or "bandit_issue")
        rel_file = _rel_path(str(item.get("filename") or ""), repo_dir)
        line_no = item.get("line_number")
        issue_text = str(item.get("issue_text") or "")

        if sev in severity_counts:
            severity_counts[sev] += 1

        category = "Command/Code Execution Risk" if test_id in command_exec_tests else "Unsafe Coding Construct"
        findings.append({
            "test_id": test_id,
            "title": f"[{test_id}] {test_name}",
            "category": category,
            "severity": sev,
            "confidence": conf,
            "file": rel_file,
            "line": line_no,
            "description": issue_text,
            "more_info": item.get("more_info"),
            "code_snippet": (item.get("code") or "").strip()[:240],
        })

    # Determine status & highest severity
    if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0:
        status = "FAIL"
        highest_sev = "CRITICAL" if severity_counts["CRITICAL"] > 0 else "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        status = "WARNING"
        highest_sev = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        status = "WARNING"
        highest_sev = "LOW"
    else:
        status = "PASS"
        highest_sev = "NONE"

    summary = (
        f"Bandit scanned {len(python_files)} Python file(s): "
        f"{severity_counts['HIGH']} HIGH, {severity_counts['MEDIUM']} MEDIUM, "
        f"{severity_counts['LOW']} LOW finding(s)."
    )

    return {
        "module_name": "static_analysis",
        "status": status,
        "severity": highest_sev,
        "summary": summary,
        "findings": findings,
        "raw_details": {
            "python_files_found": len(python_files),
            "severity_counts": severity_counts,
            "parse_errors": errors,
        },
        "tool_name": "Bandit",
        "tool_available": True,
    }
