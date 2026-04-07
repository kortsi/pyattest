"""Tests for KeyDescription ASN.1 parser and real device certificate parsing."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from pytest import raises

from pyattest.attestation import Attestation
from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig
from pyattest.exceptions import PyAttestException
from pyattest.key_description import (
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
    parse_key_description,
)
from pyattest.testutils.factories.attestation import google_key as factory

root_ca = load_pem_x509_certificate(
    Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
)
root_ca_pem = root_ca.public_bytes(serialization.Encoding.PEM)
nonce = os.urandom(32)


def _load_leaf_from_pem_chain(pem_path):
    """Load the first (leaf) certificate from a PEM chain file."""
    from cryptography.x509 import load_pem_x509_certificate

    pem_data = pem_path.read_bytes()
    certs = []
    current = b""
    for line in pem_data.split(b"\n"):
        current += line + b"\n"
        if b"END CERTIFICATE" in line:
            certs.append(current)
            current = b""
    return load_pem_x509_certificate(certs[0])


def test_parse_real_device_cert():
    """
    Parse the KeyDescription extension from a real Pixel 3 (blueline) TEE EC cert.

    Test data from android/keyattestation (Apache 2.0):
      https://github.com/android/keyattestation/blob/b1bf4375/testdata/blueline/sdk28/TEE_EC_NONE.pem
    """
    from cryptography import x509 as cx509

    leaf = _load_leaf_from_pem_chain(
        Path("pyattest/testutils/fixtures/google_key_tee_ec.pem")
    )
    oid = cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    ext = leaf.extensions.get_extension_for_oid(oid)
    parsed = parse_key_description(ext.value.value)

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
    assert hw.get("origin") == 0
    assert "root_of_trust" in hw


def test_parse_all_packages():
    """Parser should return all packages, not just the first."""
    from cryptography import x509 as cx509

    leaf = _load_leaf_from_pem_chain(
        Path("pyattest/testutils/fixtures/google_key_tee_ec.pem")
    )
    oid = cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    ext = leaf.extensions.get_extension_for_oid(oid)
    parsed = parse_key_description(ext.value.value)

    app_id = parsed["software_enforced"]["attestation_application_id"]
    assert "packages" in app_id
    assert len(app_id["packages"]) >= 1
    assert app_id["packages"][0]["package_name"] == app_id["package_name"]


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
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
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
