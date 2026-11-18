"""
Module 9: Organizational Digital Trust Certification using Python cryptography.

- Generates an organizational RSA-2048 key pair stored strictly outside web static paths.
- Never exposes the private key through the web interface.
- Signs approved artifact metadata (repository URL, artifact hash, assessment ID, issue date).
- Supports cryptographic signature verification using the public key.
"""
from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from config import Config
from utils.logger import get_logger
from utils.validators import sanitize_filename

logger = get_logger("modeltrust.certification")

ORG_ISSUER = "ModelTrust Organizational Trust Authority"
SIGNATURE_ALGORITHM = "RSA-2048-PSS-SHA256"


def _private_key_path() -> Path:
    return Config.KEYS_DIR / "org_private_key.pem"


def _public_key_path() -> Path:
    return Config.KEYS_DIR / "org_public_key.pem"


def ensure_org_keypair() -> tuple[Path, Path]:
    """Ensure the organizational RSA-2048 key pair exists; generate once if missing."""
    Config.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = _private_key_path()
    pub_path = _public_key_path()

    if priv_path.exists() and pub_path.exists():
        return priv_path, pub_path

    logger.info("Generating new organizational RSA-2048 signing key pair in %s", Config.KEYS_DIR)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize payload deterministically to UTF-8 JSON bytes for signing/verification."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_certificate(
    assessment_id: str,
    repository_url: str,
    repository_name: str,
    artifact_hash: str,
) -> dict[str, Any]:
    """Digitally sign an approved artifact's metadata and persist certificate JSON."""
    if not artifact_hash:
        raise ValueError("Cannot certify artifact without a valid SHA-256 artifact hash.")

    priv_path, pub_path = ensure_org_keypair()
    private_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)

    certificate_id = f"MTCERT-{uuid.uuid4().hex[:12].upper()}"
    issue_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "certificate_id": certificate_id,
        "assessment_id": assessment_id,
        "repository_url": repository_url,
        "repository_name": repository_name,
        "artifact_hash": artifact_hash,
        "issue_date": issue_date,
        "issuer": ORG_ISSUER,
        "algorithm": SIGNATURE_ALGORITHM,
    }

    signature = private_key.sign(
        _canonical_payload_bytes(payload),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("ascii")

    cert_document = {
        "payload": payload,
        "signature_b64": signature_b64,
        "public_key_pem": pub_path.read_text(encoding="utf-8"),
    }

    Config.CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
    cert_filename = f"certificate_{sanitize_filename(assessment_id)}.json"
    cert_path = Config.CERTIFICATES_DIR / cert_filename
    cert_path.write_text(json.dumps(cert_document, indent=2), encoding="utf-8")

    logger.info("Issued certificate %s for assessment %s", certificate_id, assessment_id)

    return {
        "certificate_id": certificate_id,
        "assessment_id": assessment_id,
        "repository_url": repository_url,
        "artifact_hash": artifact_hash,
        "issuer": ORG_ISSUER,
        "algorithm": SIGNATURE_ALGORITHM,
        "payload": payload,
        "signature_b64": signature_b64,
        "certificate_path": str(cert_path),
        "status": "VALID",
        "issue_date": issue_date,
    }


def verify_certificate_signature(
    payload: dict[str, Any],
    signature_b64: str,
) -> dict[str, Any]:
    """Verify a certificate's digital signature using the organizational public key."""
    pub_path = _public_key_path()
    if not pub_path.exists():
        return {
            "signature_valid": False,
            "reason": "Organizational public key not found.",
        }

    try:
        public_key = serialization.load_pem_public_key(pub_path.read_bytes())
        signature_bytes = base64.b64decode(signature_b64.encode("ascii"))
        public_key.verify(
            signature_bytes,
            _canonical_payload_bytes(payload),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return {
            "signature_valid": True,
            "reason": "Cryptographic RSA-2048-PSS-SHA256 signature verified successfully.",
        }
    except (InvalidSignature, ValueError, TypeError) as exc:
        return {
            "signature_valid": False,
            "reason": f"Digital signature verification FAILED: {exc}",
        }
