"""
Module 7: Software Bill of Materials (SBOM) Generation using Anchore Syft.

Generates a CycloneDX JSON SBOM stored under storage/sbom_files/.
If Syft is not installed, honestly marks SBOM status as NOT SCANNED with clear
installation instructions (never fabricates a Syft SBOM).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from config import Config
from utils.logger import get_logger
from utils.validators import sanitize_filename

logger = get_logger("modeltrust.sbom")


def _find_syft_binary() -> str | None:
    configured = Config.SYFT_BINARY
    if configured and Path(configured).is_file():
        return configured
    found = shutil.which(configured or "syft")
    if found:
        return found
    # Check common Windows/user install locations
    candidates = [
        Path.home() / "AppData" / "Local" / "Microsoft" / "WinGet" / "Links" / "syft.exe",
        Path.home() / ".local" / "bin" / "syft.exe",
        Path("C:/ProgramData/chocolatey/bin/syft.exe"),
    ]
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    return None


def is_syft_available() -> bool:
    """Return True if Syft CLI is available on the host."""
    return _find_syft_binary() is not None


def generate_sbom(repo_dir: Path, assessment_id: str) -> dict[str, Any]:
    """Invoke Syft to generate a CycloneDX JSON SBOM for repo_dir."""
    syft_bin = _find_syft_binary()
    if not syft_bin:
        return {
            "module_name": "sbom",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": (
                "Syft is not installed on this system; SBOM was NOT generated. "
                "Install Syft via 'winget install Anchore.Syft' (Windows) or "
                "'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh' (Linux/macOS)."
            ),
            "findings": [
                {
                    "title": "Syft SBOM Generator Not Installed",
                    "severity": "MEDIUM",
                    "description": "Syft binary was not found in PATH or SYFT_BINARY configuration.",
                    "recommendation": "Install Anchore Syft (https://github.com/anchore/syft) and re-run the assessment.",
                }
            ],
            "raw_details": {
                "sbom_generated": False,
                "sbom_path": None,
                "component_count": 0,
                "components": [],
                "install_hint": "winget install Anchore.Syft",
            },
            "tool_name": "Syft",
            "tool_available": False,
        }

    Config.SBOM_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = sanitize_filename(assessment_id)
    sbom_filename = f"sbom_{safe_id}.cyclonedx.json"
    sbom_path = Config.SBOM_DIR / sbom_filename

    cmd = [
        syft_bin,
        f"dir:{Path(repo_dir).resolve()}",
        "-o",
        f"cyclonedx-json={sbom_path}",
        "-q",
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
        return {
            "module_name": "sbom",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Syft timed out after {Config.TOOL_TIMEOUT_SECONDS} seconds.",
            "findings": [],
            "raw_details": {"sbom_generated": False, "error": "timeout"},
            "tool_name": "Syft",
            "tool_available": True,
        }
    except OSError as exc:
        return {
            "module_name": "sbom",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Syft execution failed: {exc}",
            "findings": [],
            "raw_details": {"sbom_generated": False, "error": str(exc)},
            "tool_name": "Syft",
            "tool_available": False,
        }

    if proc.returncode != 0 or not sbom_path.exists():
        return {
            "module_name": "sbom",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Syft exited with code {proc.returncode}: {(proc.stderr or '')[:200]}",
            "findings": [],
            "raw_details": {
                "sbom_generated": False,
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[:500],
            },
            "tool_name": "Syft",
            "tool_available": True,
        }

    try:
        sbom_data = json.loads(sbom_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {
            "module_name": "sbom",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "summary": f"Syft produced invalid JSON output: {exc}",
            "findings": [],
            "raw_details": {"sbom_generated": False, "error": str(exc)},
            "tool_name": "Syft",
            "tool_available": True,
        }

    components_raw = sbom_data.get("components") or []
    components = [
        {
            "name": c.get("name"),
            "version": c.get("version") or "unpinned",
            "type": c.get("type"),
            "purl": c.get("purl"),
        }
        for c in components_raw
    ]

    return {
        "module_name": "sbom",
        "status": "PASS",
        "severity": "NONE",
        "summary": (
            f"Syft CycloneDX SBOM generated successfully ({len(components)} software component(s) identified). "
            f"Saved to {sbom_filename}."
        ),
        "findings": [],
        "raw_details": {
            "sbom_generated": True,
            "sbom_filename": sbom_filename,
            "sbom_path": str(sbom_path),
            "bom_format": sbom_data.get("bomFormat", "CycloneDX"),
            "spec_version": sbom_data.get("specVersion"),
            "component_count": len(components),
            "components": components[:150],
        },
        "tool_name": "Syft",
        "tool_available": True,
    }
