"""
Tests for KeyDescription ASN.1 parser using real device certificate chains.

Test data from android/keyattestation (Apache 2.0):
  https://github.com/android/keyattestation/blob/b1bf4375/testdata/
"""

import os
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig
from pyattest.exceptions import PyAttestException
from pyattest.key_description import (
    SECURITY_LEVEL_SOFTWARE,
    SECURITY_LEVEL_STRONG_BOX,
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    parse_key_description,
)

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)

FIXTURES = Path("pyattest/testutils/fixtures")
ATTESTATION_OID = cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def _parse_leaf(fixture_name):
    """Load leaf cert from a PEM chain fixture and parse KeyDescription."""
    pem_data = (FIXTURES / fixture_name).read_bytes()
    certs = []
    current = b""
    for line in pem_data.split(b"\n"):
        current += line + b"\n"
        if b"END CERTIFICATE" in line:
            certs.append(current)
            current = b""
    leaf = load_pem_x509_certificate(certs[0])
    ext = leaf.extensions.get_extension_for_oid(ATTESTATION_OID)
    return parse_key_description(ext.value.value)


# --- Pixel 3 (blueline) - factory provisioned, 4-cert RSA chain, 2016 root ---
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/blueline/sdk28/TEE_EC_NONE.pem


def test_blueline_tee():
    parsed = _parse_leaf("google_key_tee_ec.pem")

    assert parsed["attestation_version"] == 3
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    assert parsed["attestation_challenge"] == b"challenge"

    sw = parsed["software_enforced"]
    app_id = sw["attestation_application_id"]
    assert app_id["package_name"] == "com.google.wireless.android.security.attestationverifier.collector"
    assert len(app_id["packages"]) >= 1

    hw = parsed["hardware_enforced"]
    assert 2 in hw.get("purposes", [])
    assert hw.get("ec_curve") == 1
    assert hw.get("origin") == 0
    assert "root_of_trust" in hw


# --- Pixel XL (marlin) - SOFTWARE security level, 3-cert chain ---
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/marlin/sdk29/TEE_EC_NONE.pem


def test_marlin_old_keymaster_schema():
    """Marlin (Pixel XL, SDK 29) uses Keymaster v2 schema with different tag
    numbers (e.g. tag 703 rollbackResistant vs 303 rollbackResistance in KeyMint).
    Our parser uses the KeyMint schema and rejects the old format.
    This is a known limitation - devices from ~2017 are not supported."""
    with raises(ValueError, match="Malformed KeyDescription"):
        _parse_leaf("google_key_marlin_tee_ec.pem")


# --- Pixel 8a (akita) - factory provisioned, 5-cert chain, 2019 RSA root ---
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/akita/sdk34/TEE_EC_NONE.pem


def test_akita_tee_factory():
    parsed = _parse_leaf("google_key_akita_tee_ec.pem")

    assert parsed["attestation_version"] == 300
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    assert parsed["attestation_challenge"] == b"challenge"

    hw = parsed["hardware_enforced"]
    assert hw.get("origin") == 0
    assert hw.get("ec_curve") == 1
    assert "root_of_trust" in hw


# --- Pixel 9 (caiman) - remotely provisioned (RKP), 5-cert chain, 2019 RSA root ---
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/caiman/sdk36/TEE_EC_RKP.pem
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/caiman/sdk36/SB_EC_RKP.pem


def test_caiman_tee_rkp():
    parsed = _parse_leaf("google_key_caiman_tee_ec_rkp.pem")

    assert parsed["attestation_version"] == 400
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_TRUSTED_ENVIRONMENT

    sw = parsed["software_enforced"]
    app_id = sw["attestation_application_id"]
    assert app_id["package_name"] == "com.google.android.attestation"

    hw = parsed["hardware_enforced"]
    assert hw.get("origin") == 0
    assert hw.get("ec_curve") == 1


def test_caiman_strongbox_rkp():
    parsed = _parse_leaf("google_key_caiman_sb_ec_rkp.pem")

    assert parsed["attestation_version"] == 300
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_STRONG_BOX

    sw = parsed["software_enforced"]
    app_id = sw["attestation_application_id"]
    assert app_id["package_name"] == "com.google.android.attestation"

    hw = parsed["hardware_enforced"]
    assert hw.get("origin") == 0


# --- Pixel 9a (tegu) - remotely provisioned, 5-cert chain, 2025 ECDSA root ---
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/tegu/sdk36/SB_EC_2026_ROOT.pem
# https://github.com/android/keyattestation/blob/b1bf4375/testdata/tegu/sdk36/TEE_EC_2026_ROOT.pem


def test_tegu_tee_ec_2026_root():
    parsed = _parse_leaf("google_key_tegu_tee_ec_2026.pem")

    assert parsed["attestation_security_level"] == SECURITY_LEVEL_TRUSTED_ENVIRONMENT

    hw = parsed["hardware_enforced"]
    assert hw.get("origin") == 0
    assert hw.get("ec_curve") == 1


def test_tegu_strongbox_ec_2026_root():
    parsed = _parse_leaf("google_key_tegu_sb_ec_2026.pem")

    assert parsed["attestation_version"] == 300
    assert parsed["attestation_security_level"] == SECURITY_LEVEL_STRONG_BOX

    sw = parsed["software_enforced"]
    app_id = sw["attestation_application_id"]
    assert app_id["package_name"] == "com.google.android.attestation"

    hw = parsed["hardware_enforced"]
    assert hw.get("origin") == 0


# --- Parser edge cases ---


def test_trailing_der_bytes():
    """KeyDescription with trailing bytes should be rejected."""
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type import univ
    from pyattest.key_description import (
        AuthorizationList,
        KeyDescriptionSequence,
        SecurityLevel,
    )

    key_desc = KeyDescriptionSequence()
    key_desc.setComponentByName("attestationVersion", univ.Integer(300))
    key_desc.setComponentByName("attestationSecurityLevel", SecurityLevel(1))
    key_desc.setComponentByName("keyMintVersion", univ.Integer(300))
    key_desc.setComponentByName("keyMintSecurityLevel", SecurityLevel(1))
    key_desc.setComponentByName("attestationChallenge", univ.OctetString(b"test"))
    key_desc.setComponentByName("uniqueId", univ.OctetString(b""))
    key_desc.setComponentByName("softwareEnforced", AuthorizationList())
    key_desc.setComponentByName("hardwareEnforced", AuthorizationList())

    tampered = der_encoder.encode(key_desc) + b"\x00\x01\x02"
    with raises(ValueError, match="Trailing data"):
        parse_key_description(tampered)


def test_malformed_key_description():
    """Malformed DER that isn't a valid KeyDescription should raise PyAttestException."""
    import base64
    import json
    import datetime
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate as load_pem
    from cryptography.x509.oid import NameOID

    rk = load_pem_private_key(
        Path("pyattest/testutils/fixtures/root_key.pem").read_bytes(), b"123"
    )
    rc = load_pem(Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes())

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Test")]))
        .issuer_name(rc.subject)
        .public_key(leaf_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            cx509.UnrecognizedExtension(
                cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
                b"\x30\x03\x01\x01\xff",
            ),
            critical=False,
        )
        .sign(rk, hashes.SHA256())
    )

    chain = json.dumps([
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
        base64.b64encode(rc.public_bytes(serialization.Encoding.DER)).decode(),
    ])

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(chain, nonce, config)
    with raises(PyAttestException):
        attestation.verify()
