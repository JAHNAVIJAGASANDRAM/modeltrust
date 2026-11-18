"""
Module 8: Policy Enforcement Engine.

Central decision-making gateway evaluating all security scan module outputs against
configurable organizational security policies.

Decisions:
- APPROVE: All mandatory security checks executed and satisfied policy rules.
- REVIEW: Requires manual investigation (unverified provenance, minor warnings,
          unsafe serialization format under REVIEW policy, or unavailable mandatory checks).
- REJECT: Critical security policy violations (critical/high malicious code, critical/high
          dependency CVEs, failed integrity verification, or malicious pickle payload).
"""
from __future__ import annotations

from typing import Any

from config import Config
from utils.logger import get_logger

logger = get_logger("modeltrust.policy")


def evaluate_policy(
    scan_results: dict[str, dict[str, Any]],
    policy_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Evaluate all security module results against organizational policy rules.

    Args:
        scan_results: mapping of module_name -> module scan output dict
        policy_overrides: optional dict overriding Config.POLICY_RULES keys

    Returns:
        dict with decision ('APPROVE' | 'REVIEW' | 'REJECT'),
        risk_classification ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'),
        violations (list), reason (str), and policy_snapshot (dict).
    """
    rules = dict(Config.POLICY_RULES)
    if policy_overrides:
        rules.update(policy_overrides)

    violations: list[dict[str, Any]] = []
    reject_reasons: list[str] = []
    review_reasons: list[str] = []

    def _add_violation(
        rule_id: str,
        module: str,
        action: str,
        severity: str,
        message: str,
    ) -> None:
        violations.append({
            "rule_id": rule_id,
            "module": module,
            "action": action,
            "severity": severity,
            "message": message,
        })
        if action == "REJECT":
            reject_reasons.append(message)
        elif action == "REVIEW":
            review_reasons.append(message)

    # Check mandatory modules availability (NEVER auto-approve if a mandatory scan was NOT SCANNED!)
    mandatory_modules = list(rules.get("mandatory_checks") or [])
    if not rules.get("require_sbom_for_approval", True) and "sbom" in mandatory_modules:
        mandatory_modules.remove("sbom")

    for mod in mandatory_modules:
        res = scan_results.get(mod)
        if not res or res.get("status") == "NOT SCANNED":
            _add_violation(
                rule_id="POL-000",
                module=mod,
                action="REVIEW",
                severity="MEDIUM",
                message=(
                    f"Mandatory security check '{mod}' was NOT SCANNED "
                    f"({(res or {}).get('summary', 'scanner unavailable')}). "
                    "Automatic approval is blocked until all mandatory checks execute."
                ),
            )

    # Rule 1: Critical/High static code findings -> REJECT
    sast = scan_results.get("static_analysis") or {}
    sast_findings = sast.get("findings") or []
    if sast.get("status") != "NOT SCANNED":
        reject_sevs = set(rules.get("sast_reject_severities") or ["CRITICAL", "HIGH"])
        review_sevs = set(rules.get("sast_review_severities") or ["MEDIUM", "LOW"])

        high_sast = [f for f in sast_findings if str(f.get("severity", "")).upper() in reject_sevs]
        minor_sast = [f for f in sast_findings if str(f.get("severity", "")).upper() in review_sevs]

        if high_sast and rules.get("reject_on_critical_sast", True):
            _add_violation(
                rule_id="POL-001",
                module="static_analysis",
                action="REJECT",
                severity="CRITICAL",
                message=f"Static code analysis detected {len(high_sast)} critical/high-risk finding(s) (e.g., {high_sast[0].get('title')}).",
            )
        elif minor_sast and rules.get("review_on_minor_warnings", True):
            _add_violation(
                rule_id="POL-006-SAST",
                module="static_analysis",
                action="REVIEW",
                severity="MEDIUM",
                message=f"Static code analysis reported {len(minor_sast)} medium/low severity security warning(s).",
            )

    # Rule 2: Critical/High dependency vulnerabilities -> REJECT
    dep = scan_results.get("dependency_analysis") or {}
    dep_findings = dep.get("findings") or []
    if dep.get("status") != "NOT SCANNED":
        vuln_reject_sevs = set(rules.get("vuln_reject_severities") or ["CRITICAL", "HIGH"])
        vuln_review_sevs = set(rules.get("vuln_review_severities") or ["MEDIUM", "LOW", "UNKNOWN"])

        # Only treat actual CVE/OSV/pip-audit vulnerabilities (with vuln_id) as CVE rejections
        actual_vulns = [f for f in dep_findings if f.get("vuln_id")]
        crit_vulns = [f for f in actual_vulns if str(f.get("severity", "")).upper() in vuln_reject_sevs]
        minor_vulns = [f for f in actual_vulns if str(f.get("severity", "")).upper() in vuln_review_sevs]
        unpinned_warnings = [f for f in dep_findings if not f.get("vuln_id")]

        if crit_vulns and rules.get("reject_on_critical_vulnerabilities", True):
            _add_violation(
                rule_id="POL-002",
                module="dependency_analysis",
                action="REJECT",
                severity="CRITICAL",
                message=(
                    f"Dependency analysis identified {len(crit_vulns)} critical/high vulnerability(ies) "
                    f"(e.g., {crit_vulns[0].get('title')})."
                ),
            )
        if minor_vulns and rules.get("review_on_minor_warnings", True):
            _add_violation(
                rule_id="POL-006-DEP",
                module="dependency_analysis",
                action="REVIEW",
                severity="MEDIUM",
                message=f"Dependency analysis identified {len(minor_vulns)} medium/low vulnerability(ies).",
            )
        if unpinned_warnings and rules.get("review_on_minor_warnings", True):
            _add_violation(
                rule_id="POL-006-PIN",
                module="dependency_analysis",
                action="REVIEW",
                severity="LOW",
                message=unpinned_warnings[0].get("title", "Unpinned dependencies require review."),
            )

    # Rule 3: Failed integrity verification -> REJECT
    integ = scan_results.get("integrity") or {}
    if integ.get("status") == "FAIL" and rules.get("reject_on_integrity_failure", True):
        _add_violation(
            rule_id="POL-003",
            module="integrity",
            action="REJECT",
            severity="CRITICAL",
            message=integ.get("summary") or "Integrity verification failed (hash mismatch or tampering detected).",
        )
    elif integ.get("status") == "WARNING" and rules.get("review_on_minor_warnings", True):
        _add_violation(
            rule_id="POL-006-INT",
            module="integrity",
            action="REVIEW",
            severity="LOW",
            message=integ.get("summary") or "Integrity check produced warnings.",
        )

    # Rule 4: Unsafe serialization findings -> REJECT or REVIEW according to policy
    serial = scan_results.get("serialization_analysis") or {}
    serial_details = serial.get("raw_details") or {}
    if serial.get("status") != "NOT SCANNED":
        if serial_details.get("malicious_detected") and rules.get("reject_on_malicious_serialization", True):
            _add_violation(
                rule_id="POL-004-MAL",
                module="serialization_analysis",
                action="REJECT",
                severity="CRITICAL",
                message="Malicious Pickle serialization payload detected by PickleScan.",
            )
        elif serial_details.get("unsafe_format_detected"):
            configured_action = str(rules.get("unsafe_serialization_format_action") or "REVIEW").upper()
            if configured_action not in ("REVIEW", "REJECT"):
                configured_action = "REVIEW"
            _add_violation(
                rule_id="POL-004-FMT",
                module="serialization_analysis",
                action=configured_action,
                severity="HIGH" if configured_action == "REJECT" else "MEDIUM",
                message=(
                    "Unsafe serialization format (Pickle / PyTorch legacy archive) detected; "
                    f"configured organizational policy mandates {configured_action}."
                ),
            )

    # Rule 5: Unverified repository provenance -> REVIEW (or REJECT if disabled/FAIL)
    prov = scan_results.get("provenance") or {}
    prov_details = prov.get("raw_details") or {}
    if prov.get("status") == "FAIL":
        _add_violation(
            rule_id="POL-005-FAIL",
            module="provenance",
            action="REJECT",
            severity="HIGH",
            message="Repository provenance check failed (missing ownership or disabled repository).",
        )
    elif prov.get("status") != "NOT SCANNED":
        provenance_verified = prov_details.get("provenance_verified", prov.get("verified", False))
        if not provenance_verified and rules.get("review_on_unverified_provenance", True):
            _add_violation(
                rule_id="POL-005",
                module="provenance",
                action="REVIEW",
                severity="MEDIUM",
                message="Repository provenance could not be fully verified; manual verification required.",
            )
        elif prov.get("status") == "WARNING" and rules.get("review_on_minor_warnings", True):
            _add_violation(
                rule_id="POL-006-PROV",
                module="provenance",
                action="REVIEW",
                severity="LOW",
                message="Repository provenance analysis raised minor metadata/signature warnings.",
            )

    # Final decision & risk classification
    if reject_reasons:
        decision = "REJECT"
        has_critical = any(v["severity"] == "CRITICAL" for v in violations)
        risk_classification = "CRITICAL" if has_critical else "HIGH"
        reason = "Artifact REJECTED due to critical policy violations: " + " | ".join(reject_reasons)
    elif review_reasons:
        decision = "REVIEW"
        has_high_or_med = any(v["severity"] in ("HIGH", "MEDIUM") for v in violations)
        risk_classification = "MEDIUM" if has_high_or_med else "LOW"
        reason = "Artifact flagged for REVIEW: " + " | ".join(review_reasons)
    else:
        decision = "APPROVE"
        risk_classification = "LOW"
        reason = (
            "Artifact APPROVED: All mandatory security checks executed cleanly with zero policy violations."
        )

    logger.info("Policy decision=%s risk=%s violations=%d", decision, risk_classification, len(violations))

    return {
        "decision": decision,
        "risk_classification": risk_classification,
        "violations": violations,
        "reason": reason,
        "policy_snapshot": rules,
    }
