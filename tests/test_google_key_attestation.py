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
    PyAttestException,
)
from pyattest.key_description import (
    SECURITY_LEVEL_SOFTWARE,
    SECURITY_LEVEL_STRONG_BOX,
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    parse_key_description,
)
from pyattest.testutils.factories.attestation import google_key as factory

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


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


def test_invalid_nonce():
    """Wrong nonce should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    wrong_nonce = os.urandom(32)
    attestation = Attestation(attest, wrong_nonce, config)

    with raises(InvalidNonceException):
        attestation.verify()


def test_invalid_certificate_chain():
    """Attestation without matching root CA should be rejected."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        production=False,
        # No custom root_ca - will try to validate against bundled Google roots
    )
    attestation = Attestation(attest, nonce, config)

    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_invalid_package_name():
    """Wrong package name should be rejected in production mode."""
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce
    )
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
    attest, _ = factory.get(
        apk_package_name="com.example.app", nonce=nonce
    )
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.wrong.package",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest, nonce, config)
    attestation.verify()  # Should not raise


# --- Parser tests using real device certificate ---


def test_parse_real_device_cert():
    """
    Parse the KeyDescription extension from a real Pixel 3 (blueline) TEE EC cert.

    Test data from android/keyattestation (Apache 2.0):
      https://github.com/android/keyattestation/blob/b1bf4375/testdata/blueline/sdk28/TEE_EC_NONE.pem
    """
    pem_path = Path("pyattest/testutils/fixtures/google_key_tee_ec.pem")
    pem_data = pem_path.read_bytes()

    # Extract the leaf certificate (first in PEM chain)
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography import x509 as cx509

    # Split PEM chain into individual certs
    certs = []
    current = b""
    for line in pem_data.split(b"\n"):
        current += line + b"\n"
        if b"END CERTIFICATE" in line:
            certs.append(current)
            current = b""

    leaf = load_pem_x509_certificate(certs[0])

    # Extract the attestation extension
    oid = cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    ext = leaf.extensions.get_extension_for_oid(oid)
    key_desc_bytes = ext.value.value

    parsed = parse_key_description(key_desc_bytes)

    # Validate against expected values from the JSON
    assert parsed["attestation_version"] == 3
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    assert parsed["attestation_challenge"] == b"challenge"

    sw = parsed["software_enforced"]
    assert "attestation_application_id" in sw
    app_id = sw["attestation_application_id"]
    assert app_id["package_name"] == "com.google.wireless.android.security.attestationverifier.collector"

    hw = parsed["hardware_enforced"]
    assert 2 in hw.get("purposes", [])
    assert hw.get("ec_curve") == 1
    assert hw.get("origin") == 0  # GENERATED
    assert "root_of_trust" in hw


# --- Adversarial input tests ---


def test_empty_attestation():
    """Empty JSON array should raise InvalidCertificateChainException."""
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation("[]", nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_invalid_json():
    """Non-JSON input should raise PyAttestException."""
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation("not json at all", nonce, config)
    with raises(PyAttestException):
        attestation.verify()


def test_invalid_base64_in_chain():
    """Bad base64 in cert chain should raise InvalidCertificateChainException."""
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    import json
    bad_chain = json.dumps(["not-valid-base64!!!"])
    attestation = Attestation(bad_chain, nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_truncated_der():
    """Truncated DER cert should raise an exception."""
    import base64
    import json

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    truncated = json.dumps([base64.b64encode(b"\x30\x82\x00\x10" + b"\x00" * 8).decode()])
    attestation = Attestation(truncated, nonce, config)
    with raises((InvalidCertificateChainException, PyAttestException, ValueError)):
        attestation.verify()


def test_trailing_der_bytes():
    """KeyDescription with trailing bytes should be rejected."""
    from pyattest.key_description import parse_key_description
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type import univ

    # Build a minimal valid KeyDescription then append garbage
    from pyattest.key_description import KeyDescriptionSequence, SecurityLevel, AuthorizationList

    key_desc = KeyDescriptionSequence()
    key_desc.setComponentByName("attestationVersion", univ.Integer(300))
    key_desc.setComponentByName("attestationSecurityLevel", SecurityLevel(1))
    key_desc.setComponentByName("keyMintVersion", univ.Integer(300))
    key_desc.setComponentByName("keyMintSecurityLevel", SecurityLevel(1))
    key_desc.setComponentByName("attestationChallenge", univ.OctetString(b"test"))
    key_desc.setComponentByName("uniqueId", univ.OctetString(b""))
    key_desc.setComponentByName("softwareEnforced", AuthorizationList())
    key_desc.setComponentByName("hardwareEnforced", AuthorizationList())

    valid_der = der_encoder.encode(key_desc)
    tampered = valid_der + b"\x00\x01\x02"

    with raises(ValueError, match="Trailing data"):
        parse_key_description(tampered)
