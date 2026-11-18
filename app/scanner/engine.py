"""
Scan engine — orchestrates all individual checkers and produces a ScanResult.
"""
from __future__ import annotations
from app.models.submission import Submission
from app.models.scan_result import ScanResult
from app.scanner.license_check import check_license
from app.scanner.model_card import check_model_card
from app.scanner.dependency_check import check_dependencies
from app.scanner.bias_check import check_bias
from app.scanner.readme_check import check_readme


def run_scan(submission: Submission) -> ScanResult:
    """Run all checkers against a submission and return an unsaved ScanResult."""
    repo_url = submission.repo_url
    model_type = submission.model_type

    license_result = check_license(repo_url)
    model_card_result = check_model_card(repo_url)
    dependency_result = check_dependencies(repo_url)
    bias_result = check_bias(repo_url, model_type)
    readme_result = check_readme(repo_url)

    trust_score = (
        license_result["score"]
        + model_card_result["score"]
        + dependency_result["score"]
        + bias_result["score"]
        + readme_result["score"]
    )

    scan = ScanResult(
        submission_id=submission.id,
        trust_score=round(trust_score, 1),
        license_score=license_result["score"],
        model_card_score=model_card_result["score"],
        dependency_score=dependency_result["score"],
        bias_score=bias_result["score"],
        readme_score=readme_result["score"],
    )
    scan.set_detail("license", license_result)
    scan.set_detail("model_card", model_card_result)
    scan.set_detail("dependency", dependency_result)
    scan.set_detail("bias", bias_result)
    scan.set_detail("readme", readme_result)

    return scan
