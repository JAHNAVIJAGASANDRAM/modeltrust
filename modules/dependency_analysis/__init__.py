"""Module 4: Dependency Vulnerability Analysis (Software Composition Analysis)."""
from modules.dependency_analysis.dependency_scanner import discover_dependencies
from modules.dependency_analysis.vulnerability_checker import check_dependencies_vulnerabilities

__all__ = ["discover_dependencies", "check_dependencies_vulnerabilities"]
