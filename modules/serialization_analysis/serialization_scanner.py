"""
Module 5: Serialization Safety Analysis using PickleScan.

Detects model serialization formats (Pickle, PyTorch, Joblib, Safetensors, ONNX, etc.)
and scans supported Pickle-based artifacts statically using PickleScan.
NEVER loads or deserializes untrusted model files!
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from config import Config
from utils.logger import get_logger

logger = get_logger("modeltrust.serialization")

# Pickle-based or arbitrary-code-capable model formats
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".p", ".dill", ".joblib"}
PYTORCH_PICKLE_EXTENSIONS = {".pt", ".pth", ".ckpt", ".bin"}
OTHER_RISKY_MODEL_EXTENSIONS = {".h5", ".keras", ".npy", ".npz", ".mar"}
SAFE_MODEL_EXTENSIONS = {".safetensors", ".onnx", ".gguf", ".tflite", ".pb", ".mlmodel"}

ALL_MODEL_EXTENSIONS = (
    PICKLE_EXTENSIONS
    | PYTORCH_PICKLE_EXTENSIONS
    | OTHER_RISKY_MODEL_EXTENSIONS
    | SAFE_MODEL_EXTENSIONS
)


def is_picklescan_available() -> bool:
    """Return True if the picklescan Python package is installed."""
    return importlib.util.find_spec("picklescan") is not None


def _run_picklescan_file(file_path: Path) -> dict[str, Any]:
    """Invoke PickleScan CLI via subprocess on a single file without ever deserializing it."""
    cmd = [sys.executable, "-m", "picklescan", "-p", str(file_path)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"executed": False, "error": f"PickleScan timed out after {Config.TOOL_TIMEOUT_SECONDS}s"}
    except OSError as exc:
        return {"executed": False, "error": str(exc)}

    combined = f"{proc.stdout or ''}\n{proc.stderr or ''}".strip()

    # Parse PickleScan output:
    # Example lines:
    #   "file.pkl: dangerous import 'os system' FOUND"
    #   "----------- SCAN SUMMARY -----------"
    #   "Scanned files: 1"
    #   "Infected files: 1"
    #   "Dangerous globals: 1"
    infected_match = re.search(r"Infected files:\s*(\d+)", combined, re.IGNORECASE)
    dangerous_match = re.search(r"Dangerous globals:\s*(\d+)", combined, re.IGNORECASE)
    infected_count = int(infected_match.group(1)) if infected_match else (1 if proc.returncode == 1 else 0)
    dangerous_count = int(dangerous_match.group(1)) if dangerous_match else 0

    dangerous_lines = [
        line.strip()
        for line in combined.splitlines()
        if any(tok in line.lower() for tok in ("dangerous", "suspicious", "infected", "found", "malicious"))
        and "dangerous globals: 0" not in line.lower()
        and "infected files: 0" not in line.lower()
    ]

    return {
        "executed": True,
        "returncode": proc.returncode,
        "infected": infected_count > 0 or dangerous_count > 0,
        "infected_count": infected_count,
        "dangerous_globals": dangerous_count,
        "details": dangerous_lines[:15],
        "raw_output": combined[:1500],
    }


def run_serialization_scan(
    repo_dir: Path,
    remote_files: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Identify model serialization artifacts and scan supported Pickle files with PickleScan."""
    repo_dir = Path(repo_dir)
    picklescan_ok = is_picklescan_available()

    local_model_files: list[dict[str, Any]] = []
    local_rel_set: set[str] = set()

    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext in ALL_MODEL_EXTENSIONS:
            rel = str(path.relative_to(repo_dir)).replace("\\", "/")
            local_rel_set.add(rel)
            local_model_files.append({
                "path": rel,
                "abs_path": path,
                "ext": ext,
                "size": path.stat().st_size,
                "downloaded": True,
            })

    # Include remote-only model files (e.g., oversized HF weights skipped from download)
    remote_only_models: list[dict[str, Any]] = []
    for rf in remote_files or []:
        rel = str(rf.get("path") or "")
        ext = Path(rel).suffix.lower()
        if rel and ext in ALL_MODEL_EXTENSIONS and rel not in local_rel_set:
            remote_only_models.append({
                "path": rel,
                "abs_path": None,
                "ext": ext,
                "size": int(rf.get("size") or 0),
                "downloaded": False,
            })

    all_models = local_model_files + remote_only_models

    if not all_models:
        return {
            "module_name": "serialization_analysis",
            "status": "PASS",
            "severity": "NONE",
            "summary": "No serialized model files (.pkl, .pt, .bin, .safetensors, .onnx, etc.) detected in repository.",
            "findings": [],
            "raw_details": {
                "model_files": [],
                "picklescan_available": picklescan_ok,
                "malicious_detected": False,
                "unsafe_format_detected": False,
            },
            "tool_name": "PickleScan",
            "tool_available": picklescan_ok,
        }

    findings: list[dict[str, Any]] = []
    malicious_detected = False
    unsafe_format_detected = False
    unscanned_pickle_files: list[str] = []
    scanned_pickle_count = 0
    safe_files: list[str] = []

    for mf in all_models:
        ext = mf["ext"]
        rel = mf["path"]

        if ext in SAFE_MODEL_EXTENSIONS:
            safe_files.append(rel)
            continue

        if ext in PICKLE_EXTENSIONS or ext in PYTORCH_PICKLE_EXTENSIONS:
            unsafe_format_detected = True
            format_label = "Pickle" if ext in PICKLE_EXTENSIONS else "PyTorch Pickle-based Archive"

            if mf["downloaded"] and mf["abs_path"] is not None:
                if picklescan_ok:
                    ps_res = _run_picklescan_file(mf["abs_path"])
                    if ps_res.get("executed"):
                        scanned_pickle_count += 1
                        if ps_res.get("infected"):
                            malicious_detected = True
                            findings.append({
                                "title": f"Malicious Pickle Payload Detected in {rel}",
                                "file": rel,
                                "format": format_label,
                                "severity": "CRITICAL",
                                "malicious": True,
                                "description": (
                                    f"PickleScan flagged dangerous/malicious globals in '{rel}' "
                                    f"(dangerous globals: {ps_res.get('dangerous_globals')}). "
                                    f"Details: {'; '.join(ps_res.get('details') or [])[:300]}"
                                ),
                                "recommendation": (
                                    "DO NOT load or deserialize this file. Reject the artifact and convert weights "
                                    "from verified source tensors into Safetensors (.safetensors) or ONNX (.onnx)."
                                ),
                            })
                        else:
                            findings.append({
                                "title": f"Unsafe Serialization Format ({ext}) — {rel}",
                                "file": rel,
                                "format": format_label,
                                "severity": "MEDIUM",
                                "malicious": False,
                                "description": (
                                    f"'{rel}' uses {format_label}, which executes Python pickle opcodes during loading. "
                                    "PickleScan found no known malicious globals, but the format remains inherently risky."
                                ),
                                "recommendation": "Migrate model weights to Safetensors (.safetensors) or ONNX (.onnx).",
                            })
                    else:
                        unscanned_pickle_files.append(rel)
                        findings.append({
                            "title": f"PickleScan Error on {rel}",
                            "file": rel,
                            "format": format_label,
                            "severity": "HIGH",
                            "malicious": False,
                            "description": f"Could not scan '{rel}' with PickleScan: {ps_res.get('error')}",
                            "recommendation": "Inspect artifact in an isolated sandbox or convert to Safetensors.",
                        })
                else:
                    unscanned_pickle_files.append(rel)
                    findings.append({
                        "title": f"Unscanned Pickle Artifact ({ext}) — {rel}",
                        "file": rel,
                        "format": format_label,
                        "severity": "HIGH",
                        "malicious": False,
                        "description": (
                            f"Detected Pickle-based file '{rel}', but PickleScan is not installed "
                            "(install via: pip install picklescan). File was NOT scanned."
                        ),
                        "recommendation": "Install picklescan and re-run assessment, or replace with Safetensors.",
                    })
            else:
                unscanned_pickle_files.append(rel)
                findings.append({
                    "title": f"Remote Pickle-based Weight File Exceeded Download Cap — {rel}",
                    "file": rel,
                    "format": format_label,
                    "severity": "MEDIUM",
                    "malicious": False,
                    "description": (
                        f"'{rel}' ({mf['size'] / (1024 * 1024):.1f} MB) uses a Pickle-based format and exceeded "
                        f"the {Config.MAX_SINGLE_FILE_MB} MB single-file download cap, so PickleScan could not scan it locally."
                    ),
                    "recommendation": "Prefer Safetensors (.safetensors) weights or scan this weight file directly with PickleScan.",
                })

        elif ext in OTHER_RISKY_MODEL_EXTENSIONS:
            unsafe_format_detected = True
            findings.append({
                "title": f"Potentially Unsafe Model Format ({ext}) — {rel}",
                "file": rel,
                "format": ext,
                "severity": "LOW",
                "malicious": False,
                "description": (
                    f"'{rel}' uses format '{ext}', which may embed executable Lambda layers (Keras/H5) "
                    "or pickled object arrays (NumPy with allow_pickle=True)."
                ),
                "recommendation": "Use safe deserialization flags (allow_pickle=False, safe_mode=True) or convert to Safetensors/ONNX.",
            })

    # Determine status cleanly
    if malicious_detected:
        status = "FAIL"
        overall_sev = "CRITICAL"
    elif not picklescan_ok and unscanned_pickle_files:
        status = "NOT SCANNED"
        overall_sev = "HIGH"
    elif unsafe_format_detected:
        status = "WARNING"
        overall_sev = "MEDIUM"
    else:
        status = "PASS"
        overall_sev = "NONE"

    summary = (
        f"Detected {len(all_models)} model file(s) ({len(safe_files)} safe format(s), "
        f"{len(all_models) - len(safe_files)} pickle/legacy format(s)). "
        f"PickleScan scanned {scanned_pickle_count} file(s); "
        f"malicious payload detected: {'YES' if malicious_detected else 'NO'}."
    )
    if not picklescan_ok and unscanned_pickle_files:
        summary += " PickleScan is not installed (pip install picklescan)."

    return {
        "module_name": "serialization_analysis",
        "status": status,
        "severity": overall_sev,
        "summary": summary,
        "findings": findings,
        "raw_details": {
            "model_files": [
                {"path": m["path"], "ext": m["ext"], "size": m["size"], "downloaded": m["downloaded"]}
                for m in all_models
            ],
            "safe_model_files": safe_files,
            "scanned_pickle_count": scanned_pickle_count,
            "unscanned_pickle_files": unscanned_pickle_files,
            "picklescan_available": picklescan_ok,
            "malicious_detected": malicious_detected,
            "unsafe_format_detected": unsafe_format_detected,
        },
        "tool_name": "PickleScan",
        "tool_available": picklescan_ok or (not unscanned_pickle_files),
    }
