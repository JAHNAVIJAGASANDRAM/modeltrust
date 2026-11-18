"""
Static dependency manifest parser for Python and JavaScript repositories.

Parses requirements.txt, pyproject.toml, setup.py (AST only, NEVER executed),
Pipfile, environment.yml, and package.json.
"""
from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

from utils.logger import get_logger

logger = get_logger("modeltrust.dependency.scanner")

_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*([=<>!~]=?[^;#\s,]+(?:\s*,\s*[=<>!~]=?[^;#\s,]+)*)?"
)
_EXACT_VER_RE = re.compile(r"==\s*([A-Za-z0-9._+-]+)")


def _normalize_pkg_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _parse_pep508_spec(raw: str) -> dict[str, Any] | None:
    """Extract package name, raw specifier, and exact pinned version (if ==) from a PEP 508 string."""
    cleaned = raw.split(";", 1)[0].split("#", 1)[0].strip()
    if not cleaned or cleaned.startswith(("-", "git+", "http://", "https://", ".")):
        return None

    m = _REQ_LINE_RE.match(cleaned)
    if not m:
        return None

    name = m.group(1).strip()
    spec = (m.group(2) or "").strip()
    exact_match = _EXACT_VER_RE.search(spec)
    exact_version = exact_match.group(1) if exact_match else None

    return {
        "name": name,
        "normalized_name": _normalize_pkg_name(name),
        "specifier": spec or "unpinned",
        "version": exact_version,
        "ecosystem": "PyPI",
    }


def _parse_requirements_txt(path: Path) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return deps

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        parsed = _parse_pep508_spec(line)
        if parsed:
            deps.append(parsed)
    return deps


def _parse_pyproject_toml(path: Path) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("Failed to parse pyproject.toml (%s): %s", path, exc)
        return deps

    project = data.get("project") or {}
    for entry in project.get("dependencies") or []:
        if isinstance(entry, str):
            parsed = _parse_pep508_spec(entry)
            if parsed:
                deps.append(parsed)

    opt_deps = project.get("optional-dependencies") or {}
    if isinstance(opt_deps, dict):
        for group_entries in opt_deps.values():
            if isinstance(group_entries, list):
                for entry in group_entries:
                    if isinstance(entry, str):
                        parsed = _parse_pep508_spec(entry)
                        if parsed:
                            deps.append(parsed)

    # Poetry dependencies
    poetry = (data.get("tool") or {}).get("poetry") or {}
    poetry_deps = poetry.get("dependencies") or {}
    if isinstance(poetry_deps, dict):
        for pkg, constraint in poetry_deps.items():
            if pkg.lower() == "python":
                continue
            spec = constraint if isinstance(constraint, str) else (
                constraint.get("version", "") if isinstance(constraint, dict) else ""
            )
            exact = spec.lstrip("=^~ ") if spec and re.match(r"^==?\s*\d", spec) else None
            deps.append({
                "name": pkg,
                "normalized_name": _normalize_pkg_name(pkg),
                "specifier": spec or "unpinned",
                "version": exact,
                "ecosystem": "PyPI",
            })

    return deps


def _parse_setup_py_static(path: Path) -> list[dict[str, Any]]:
    """Statically parse install_requires from setup.py using Python AST without executing code."""
    deps: list[dict[str, Any]] = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except Exception:
        return deps

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "install_requires" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            parsed = _parse_pep508_spec(elt.value)
                            if parsed:
                                deps.append(parsed)
    return deps


def _parse_environment_yml(path: Path) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps

    if not isinstance(data, dict):
        return deps

    for item in data.get("dependencies") or []:
        if isinstance(item, str):
            # Conda style: pkg=1.2.3 or pkg==1.2.3
            spec_str = re.sub(r"(?<![=<>!~])=(?!=)", "==", item, count=1)
            parsed = _parse_pep508_spec(spec_str)
            if parsed and parsed["normalized_name"] != "python":
                deps.append(parsed)
        elif isinstance(item, dict) and isinstance(item.get("pip"), list):
            for pip_dep in item["pip"]:
                if isinstance(pip_dep, str):
                    parsed = _parse_pep508_spec(pip_dep)
                    if parsed:
                        deps.append(parsed)
    return deps


def _parse_package_json(path: Path) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps

    if not isinstance(data, dict):
        return deps

    for section in ("dependencies", "devDependencies"):
        mapping = data.get(section) or {}
        if isinstance(mapping, dict):
            for pkg, ver in mapping.items():
                ver_str = str(ver or "").strip()
                clean_ver = ver_str.lstrip("^~=") if re.match(r"^[\^~=]?\d+\.\d+", ver_str) else None
                deps.append({
                    "name": pkg,
                    "normalized_name": pkg.lower(),
                    "specifier": ver_str or "unpinned",
                    "version": clean_ver,
                    "ecosystem": "npm",
                })
    return deps


def discover_dependencies(repo_dir: Path) -> dict[str, Any]:
    """Discover dependency manifests and extract deduplicated dependency descriptors."""
    repo_dir = Path(repo_dir)
    manifests: list[str] = []
    requirements_files: list[Path] = []
    extracted: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    def _add(dep: dict[str, Any], rel_manifest: str) -> None:
        key = (dep["ecosystem"], dep["normalized_name"], dep.get("version") or dep.get("specifier") or "")
        if key in seen_keys:
            return
        seen_keys.add(key)
        dep["source_manifest"] = rel_manifest
        extracted.append(dep)

    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file():
            continue
        # Skip hidden virtualenvs or git folders
        if any(part.startswith(".") or part in ("node_modules", "__pycache__", "venv") for part in path.relative_to(repo_dir).parts):
            continue

        fname = path.name.lower()
        rel = str(path.relative_to(repo_dir)).replace("\\", "/")

        if fname == "requirements.txt" or (fname.startswith("requirements") and fname.endswith(".txt")):
            manifests.append(rel)
            requirements_files.append(path)
            for dep in _parse_requirements_txt(path):
                _add(dep, rel)
        elif fname == "pyproject.toml":
            manifests.append(rel)
            for dep in _parse_pyproject_toml(path):
                _add(dep, rel)
        elif fname == "setup.py":
            manifests.append(rel)
            for dep in _parse_setup_py_static(path):
                _add(dep, rel)
        elif fname in ("environment.yml", "environment.yaml"):
            manifests.append(rel)
            for dep in _parse_environment_yml(path):
                _add(dep, rel)
        elif fname == "package.json":
            manifests.append(rel)
            for dep in _parse_package_json(path):
                _add(dep, rel)

    return {
        "manifests": manifests,
        "requirements_files": requirements_files,
        "dependencies": extracted,
    }
