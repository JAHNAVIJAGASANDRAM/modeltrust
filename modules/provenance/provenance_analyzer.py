"""
Module 2: Repository Provenance Analysis.

Evaluates ownership, publisher verifiability, creation/update dates, release history,
commit history & commit signatures, and metadata consistency.
Explicitly does NOT assume repository popularity or age establishes trustworthiness.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from utils.logger import get_logger

logger = get_logger("modeltrust.provenance")


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def analyze_provenance(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Analyze repository provenance and return structured findings."""
    if not metadata:
        return {
            "module_name": "provenance",
            "status": "NOT SCANNED",
            "severity": "MEDIUM",
            "verified": False,
            "summary": "Repository metadata unavailable; provenance could not be verified.",
            "findings": [
                {
                    "title": "Missing Repository Metadata",
                    "severity": "MEDIUM",
                    "description": "Repository metadata could not be retrieved from the source platform.",
                    "recommendation": "Verify network connectivity and repository accessibility before trusting this artifact.",
                }
            ],
            "raw_details": {"unverifiable_fields": ["all_metadata"]},
            "tool_name": "ModelTrust Provenance Analyzer",
            "tool_available": True,
        }

    platform = metadata.get("platform", "unknown")
    owner = metadata.get("owner")
    owner_type = metadata.get("owner_type") or "Unknown"
    owner_profile = metadata.get("owner_profile") or {}
    created_at = metadata.get("created_at")
    updated_at = metadata.get("updated_at")
    description = (metadata.get("description") or "").strip()
    releases = metadata.get("releases") or []
    commits = metadata.get("commits") or []
    license_info = metadata.get("license")
    is_archived = bool(metadata.get("archived"))
    is_disabled = bool(metadata.get("disabled"))
    is_fork = bool(metadata.get("is_fork"))

    findings: list[dict[str, Any]] = []
    unverifiable_fields: list[str] = []
    verified_signals: list[str] = []

    # 1. Ownership & Publisher Information
    if not owner:
        unverifiable_fields.append("owner")
        findings.append({
            "title": "Missing Repository Ownership",
            "severity": "HIGH",
            "description": "Repository owner/publisher identity could not be determined.",
            "recommendation": "Do not admit artifacts with unknown ownership without manual verification.",
        })
    else:
        if platform == "github":
            org_verified = owner_profile.get("is_verified")
            if owner_type == "Organization" and org_verified:
                verified_signals.append(f"Verified GitHub Organization: {owner}")
            elif owner_type == "Organization":
                unverifiable_fields.append("publisher_domain_verification")
                findings.append({
                    "title": "Unverified Organization Publisher",
                    "severity": "LOW",
                    "description": f"Publisher '{owner}' is a GitHub Organization without a verified domain badge.",
                    "recommendation": "Confirm organizational ownership out-of-band before production adoption.",
                })
            else:
                unverifiable_fields.append("individual_publisher_identity")
                findings.append({
                    "title": "Individual (Non-Organizational) Publisher",
                    "severity": "LOW",
                    "description": f"Repository is published under personal account '{owner}' rather than a verified organization.",
                    "recommendation": "Verify publisher identity and maintainer governance.",
                })
        elif platform == "huggingface":
            verified_signals.append(f"Hugging Face publisher namespace: {owner}")
            unverifiable_fields.append("publisher_cryptographic_verification")
            findings.append({
                "title": "Hugging Face Publisher Identity Not Cryptographically Attested",
                "severity": "LOW",
                "description": (
                    f"Publisher '{owner}' on Hugging Face Hub does not expose cryptographic "
                    "identity verification via public metadata."
                ),
                "recommendation": "Confirm official publisher namespace before adopting models in production.",
            })

    # 2. Creation & Last Updated Timestamp Consistency
    created_dt = _parse_iso(created_at)
    updated_dt = _parse_iso(updated_at)

    if not created_dt:
        unverifiable_fields.append("created_at")
        findings.append({
            "title": "Unverifiable Creation Timestamp",
            "severity": "LOW",
            "description": "Repository creation date is missing or unparseable in platform metadata.",
            "recommendation": "Verify repository origin and lineage manually.",
        })
    if not updated_dt:
        unverifiable_fields.append("updated_at")
        findings.append({
            "title": "Unverifiable Last Updated Timestamp",
            "severity": "LOW",
            "description": "Repository last-updated timestamp is missing in platform metadata.",
            "recommendation": "Inspect repository revision history manually.",
        })
    if created_dt and updated_dt and updated_dt < created_dt:
        findings.append({
            "title": "Timestamp Metadata Inconsistency",
            "severity": "MEDIUM",
            "description": f"Last updated timestamp ({updated_at}) precedes creation date ({created_at}).",
            "recommendation": "Investigate metadata anomaly before approving artifact.",
        })
    elif created_dt and updated_dt:
        verified_signals.append(f"Consistent lifecycle timestamps (created {created_at[:10]}, updated {updated_at[:10]})")

    # 3. Repository Status Flags (Archived / Disabled / Fork)
    if is_disabled:
        findings.append({
            "title": "Disabled Repository",
            "severity": "HIGH",
            "description": "Source platform reports this repository as disabled.",
            "recommendation": "Reject disabled repositories.",
        })
    if is_archived:
        findings.append({
            "title": "Archived / Unmaintained Repository",
            "severity": "MEDIUM",
            "description": "Repository is archived and no longer receives security patches.",
            "recommendation": "Review maintenance status and patch coverage before adoption.",
        })
    if is_fork:
        findings.append({
            "title": "Forked Repository Provenance",
            "severity": "LOW",
            "description": "Repository is a fork; upstream lineage and unauthorized modifications should be audited.",
            "recommendation": "Compare fork diff against trusted upstream repository.",
        })

    # 4. Release Information
    if platform == "github":
        if releases:
            verified_signals.append(f"{len(releases)} tagged release(s) available (latest: {releases[0].get('tag_name')})")
        else:
            unverifiable_fields.append("releases")
            findings.append({
                "title": "No Formal Releases Published",
                "severity": "LOW",
                "description": "No tagged GitHub releases were found; artifact is sourced directly from the default branch.",
                "recommendation": "Pin to an immutable release tag or commit SHA for reproducible supply-chain tracking.",
            })
    else:
        if metadata.get("sha"):
            verified_signals.append(f"Pinned Hugging Face commit revision: {str(metadata['sha'])[:12]}")
        else:
            unverifiable_fields.append("revision_sha")

    # 5. Commit History & Signed Commits
    if not commits:
        unverifiable_fields.append("commit_history")
        findings.append({
            "title": "Commit History Unavailable",
            "severity": "MEDIUM",
            "description": "Commit history could not be retrieved or is empty.",
            "recommendation": "Verify repository change history before trusting the artifact.",
        })
    else:
        signed_count = sum(1 for c in commits if c.get("verified_signature") is True)
        verified_signals.append(f"{len(commits)} recent commit(s) inspected ({signed_count} cryptographically signed)")
        if platform == "github" and signed_count == 0:
            unverifiable_fields.append("commit_signatures")
            findings.append({
                "title": "No Cryptographically Signed Recent Commits",
                "severity": "LOW",
                "description": f"None of the {len(commits)} most recent commits carry a verified GPG/SSH signature.",
                "recommendation": "Require signed commits or signed release attestations for critical AI dependencies.",
            })

    # 6. Metadata Consistency (License & Description)
    if not license_info or not license_info.get("name"):
        unverifiable_fields.append("license")
        findings.append({
            "title": "Missing License Metadata",
            "severity": "LOW",
            "description": "No software/model license was detected in repository metadata.",
            "recommendation": "Confirm legal terms and redistribution rights before admitting into the registry.",
        })
    else:
        verified_signals.append(f"License declared: {license_info.get('name')}")

    if not description:
        findings.append({
            "title": "Missing Repository Description",
            "severity": "LOW",
            "description": "Repository lacks a summary description in platform metadata.",
            "recommendation": "Verify artifact purpose and documentation.",
        })

    # Determine overall provenance status and verification flag
    severities = [f["severity"] for f in findings]
    if "HIGH" in severities or "CRITICAL" in severities:
        status = "FAIL"
        overall_severity = "HIGH"
        verified = False
    elif "MEDIUM" in severities or len(unverifiable_fields) >= 4:
        status = "WARNING"
        overall_severity = "MEDIUM"
        verified = False
    elif findings:
        status = "WARNING"
        overall_severity = "LOW"
        # Provenance is considered verified when core ownership, timestamps, commits, and license exist
        core_missing = any(f in unverifiable_fields for f in ("owner", "created_at", "updated_at", "commit_history"))
        verified = not core_missing
    else:
        status = "PASS"
        overall_severity = "NONE"
        verified = True

    summary = (
        f"Provenance analyzed for {platform}:{metadata.get('full_name')}. "
        f"{len(verified_signals)} verified signal(s), {len(findings)} finding(s), "
        f"{len(unverifiable_fields)} unverifiable attribute(s). "
        "Note: Popularity and repository age are never treated as proof of trustworthiness."
    )

    return {
        "module_name": "provenance",
        "status": status,
        "severity": overall_severity,
        "verified": verified,
        "summary": summary,
        "findings": findings,
        "raw_details": {
            "platform": platform,
            "owner": owner,
            "owner_type": owner_type,
            "created_at": created_at,
            "updated_at": updated_at,
            "releases_count": len(releases),
            "latest_release": releases[0] if releases else None,
            "commits_inspected": len(commits),
            "signed_commits": sum(1 for c in commits if c.get("verified_signature") is True),
            "recent_commits": commits[:5],
            "license": license_info,
            "verified_signals": verified_signals,
            "unverifiable_fields": unverifiable_fields,
            "provenance_verified": verified,
        },
        "tool_name": "ModelTrust Provenance Analyzer",
        "tool_available": True,
    }
