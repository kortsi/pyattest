"""Tests for GoogleKeyAttestationVerifier — verification logic."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig
from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCertificateChainException,
    InvalidNonceException,
    InvalidSecurityLevelException,
    RevokedCertificateException,
)
from pyattest.key_description import (
    SECURITY_LEVEL_SOFTWARE,
    SECURITY_LEVEL_STRONG_BOX,
)
from pyattest.testutils.factories.attestation import google_key as factory

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


# --- Happy path ---


def test_happy_path():
    """Valid TEE key attestation."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()

    data = attestation.data["data"]
    assert data["security_level"] == "TrustedEnvironment"
    assert data["challenge"] == nonce
    assert data["package_name"] == "com.example.app"


def test_happy_path_strongbox():
    """Valid StrongBox key attestation."""
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        security_level=SECURITY_LEVEL_STRONG_BOX,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()
    assert attestation.data["data"]["security_level"] == "StrongBox"


def test_happy_path_production():
    """Valid TEE attestation in production mode (checks package name)."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Security level ---


def test_invalid_security_level():
    """Software-backed key should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        security_level=SECURITY_LEVEL_SOFTWARE,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


# --- Nonce ---


def test_invalid_nonce():
    """Wrong nonce should be rejected."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    wrong_nonce = os.urandom(32)
    attestation = Attestation(attest, wrong_nonce, config)
    with raises(InvalidNonceException):
        attestation.verify()


# --- Certificate chain ---


def test_invalid_certificate_chain():
    """Attestation without matching root CA should be rejected."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


# --- Package name ---


def test_invalid_package_name():
    """Wrong package name should be rejected in production mode."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.wrong.package",
        root_ca=root_ca_pem,
        production=True,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_package_name_not_checked_in_dev():
    """Package name mismatch should pass in non-production mode."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.wrong.package",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Revocation ---


def test_revoked_certificate():
    """Certificate with a revoked serial should be rejected."""
    import base64
    import json
    from cryptography.x509 import load_der_x509_certificate

    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    chain = json.loads(attest)
    leaf = load_der_x509_certificate(base64.b64decode(chain[0]))

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
        revoked_serials={format(leaf.serial_number, "x")},
    )
    attestation = Attestation(attest, nonce, config)
    with raises(RevokedCertificateException):
        attestation.verify()


def test_revocation_not_checked_when_empty():
    """Revocation check should pass when revoked_serials is empty."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
        revoked_serials=set(),
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


# --- Key origin ---


def test_generated_key_passes():
    """Key with origin=0 (Generated) should pass."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce, origin=0
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


def test_imported_key_rejected():
    """Key with origin=1 (Imported) should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce, origin=1
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


def test_derived_key_rejected():
    """Key with origin=2 (Derived) should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce, origin=2
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


def test_securely_imported_key_rejected():
    """Key with origin=4 (Securely Imported) should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce, origin=4
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidSecurityLevelException):
        attestation.verify()


def test_missing_origin_rejected():
    """Key with no origin field should be rejected."""
    # Factory always sets origin, so we need to patch the parsed result
    from unittest.mock import patch

    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)

    # Intercept parse_key_description to remove origin from hardware_enforced
    original_parse = __import__("pyattest.key_description", fromlist=["parse_key_description"]).parse_key_description

    def patched_parse(data):
        result = original_parse(data)
        result["hardware_enforced"].pop("origin", None)
        return result

    with patch("pyattest.verifiers.google_key_attestation.parse_key_description", patched_parse):
        with raises(InvalidSecurityLevelException, match="origin"):
            attestation.verify()


# --- APK signature digest ---


def test_signature_digest_match():
    """Matching signature digest should pass."""
    known_digest = bytes.fromhex("abcdef1234567890" * 4)
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        signature_digest=known_digest,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=[known_digest.hex()],
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()


def test_signature_digest_mismatch():
    """Wrong signature digest should be rejected."""
    known_digest = bytes.fromhex("abcdef1234567890" * 4)
    attest, _ = factory.get(
        apk_package_name="com.example.app",
        nonce=nonce,
        signature_digest=known_digest,
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=["0000000000000000" * 4],
    )
    attestation = Attestation(attest, nonce, config)
    with raises(InvalidAppIdException):
        attestation.verify()


def test_signature_digest_not_checked_when_not_configured():
    """When apk_signature_digests is None, any digest should pass."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=True,
        apk_signature_digests=None,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()
