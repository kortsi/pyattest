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
    RevokedCertificateException,
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


# --- Revocation tests ---


def test_revoked_certificate():
    """Certificate with a revoked serial should be rejected."""
    import base64
    import json

    from cryptography.x509 import load_der_x509_certificate

    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)

    # Extract the leaf cert serial number from the generated attestation
    chain = json.loads(attest)
    leaf = load_der_x509_certificate(base64.b64decode(chain[0]))
    revoked_serial = leaf.serial_number

    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
        revoked_serials={format(revoked_serial, "x")},
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
    attestation.verify()  # Should not raise


# --- Key origin tests ---


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
    attestation.verify()  # Should not raise


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


# --- APK signature digest tests ---


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
    attestation.verify()  # Should not raise


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
    attestation.verify()  # Should not raise


# --- App identity tests ---


def test_parse_all_packages():
    """Parser should return all packages, not just the first."""
    from pyattest.key_description import parse_key_description
    # Real device cert has one package — verify the packages list structure
    pem_path = Path("pyattest/testutils/fixtures/google_key_tee_ec.pem")
    pem_data = pem_path.read_bytes()
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography import x509 as cx509

    certs = []
    current = b""
    for line in pem_data.split(b"\n"):
        current += line + b"\n"
        if b"END CERTIFICATE" in line:
            certs.append(current)
            current = b""

    leaf = load_pem_x509_certificate(certs[0])
    oid = cx509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    ext = leaf.extensions.get_extension_for_oid(oid)
    parsed = parse_key_description(ext.value.value)

    app_id = parsed["software_enforced"]["attestation_application_id"]
    assert "packages" in app_id
    assert len(app_id["packages"]) >= 1
    assert app_id["packages"][0]["package_name"] == app_id["package_name"]


# --- Fetch utility tests (mocked network) ---


def test_parse_root_certs_merges_and_deduplicates():
    """parse_google_root_certs should merge fetched + bundled and deduplicate."""
    from pyattest.verifiers.utils import parse_google_root_certs

    # Pass a bundled cert as "fetched" — should be deduped
    bundled_pem = Path("pyattest/certificates/google_hardware_attestation_root_rsa_2022.pem").read_text()
    roots = parse_google_root_certs([bundled_pem])

    assert len(roots) == 5  # 5 bundled, duplicate removed


def test_parse_root_certs_adds_new():
    """parse_google_root_certs should add a new cert not in the bundle."""
    from pyattest.verifiers.utils import parse_google_root_certs
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    # Generate a unique self-signed cert
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        cx509.CertificateBuilder()
        .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Test New Root")]))
        .issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Test New Root")]))
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    new_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    roots = parse_google_root_certs([new_pem])

    assert len(roots) == 6  # 5 bundled + 1 new


def test_parse_root_certs_not_list():
    """parse_google_root_certs should raise on non-list input."""
    from pyattest.verifiers.utils import parse_google_root_certs
    with raises(ValueError, match="Expected a list"):
        parse_google_root_certs({"not": "a list"})


def test_parse_revocation_list():
    """parse_google_revocation_list should return revoked serials as hex strings."""
    from pyattest.verifiers.utils import parse_google_revocation_list

    data = {
        "entries": {
            "abcdef1234": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
            "1234567890": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
            "fedcba9876": {"status": "SUSPENDED"},
        }
    }
    revoked = parse_google_revocation_list(data)

    assert revoked == {"abcdef1234", "1234567890"}
    assert "fedcba9876" not in revoked


def test_parse_revocation_list_missing_entries():
    """parse_google_revocation_list should raise if 'entries' key is missing."""
    from pyattest.verifiers.utils import parse_google_revocation_list
    with raises(ValueError, match="Expected a dict"):
        parse_google_revocation_list({"no_entries": {}})


def test_parse_revocation_list_not_dict():
    """parse_google_revocation_list should raise on non-dict input."""
    from pyattest.verifiers.utils import parse_google_revocation_list
    with raises(ValueError, match="Expected a dict"):
        parse_google_revocation_list("not a dict")


def test_fetch_roots_delegates_to_parse():
    """fetch_google_key_attestation_roots should fetch and delegate to parse."""
    from unittest.mock import patch, MagicMock
    from pyattest.verifiers.utils import fetch_google_key_attestation_roots
    import json

    bundled_pem = Path("pyattest/certificates/google_hardware_attestation_root_rsa_2022.pem").read_text()
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps([bundled_pem]).encode()

    with patch("pyattest.verifiers.utils.urllib.request.urlopen", return_value=fake_response):
        roots = fetch_google_key_attestation_roots()

    assert len(roots) == 5


def test_fetch_roots_network_error():
    """fetch_google_key_attestation_roots should raise RuntimeError on network failure."""
    from unittest.mock import patch
    from pyattest.verifiers.utils import fetch_google_key_attestation_roots
    import urllib.error

    with patch("pyattest.verifiers.utils.urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        with raises(RuntimeError, match="Failed to fetch"):
            fetch_google_key_attestation_roots()


def test_fetch_revocation_delegates_to_parse():
    """fetch_google_revocation_list should fetch and delegate to parse."""
    from unittest.mock import patch, MagicMock
    from pyattest.verifiers.utils import fetch_google_revocation_list
    import json

    fake_data = {"entries": {"abc123": {"status": "REVOKED"}}}
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(fake_data).encode()

    with patch("pyattest.verifiers.utils.urllib.request.urlopen", return_value=fake_response):
        revoked = fetch_google_revocation_list()

    assert revoked == {"abc123"}


def test_fetch_revocation_network_error():
    """fetch_google_revocation_list should raise RuntimeError on network failure."""
    from unittest.mock import patch
    from pyattest.verifiers.utils import fetch_google_revocation_list
    import urllib.error

    with patch("pyattest.verifiers.utils.urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        with raises(RuntimeError, match="Failed to fetch"):
            fetch_google_revocation_list()


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


def test_bytes_input():
    """Attestation data passed as bytes should work."""
    attest, _ = factory.get(apk_package_name="com.example.app", nonce=nonce)
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(attest.encode("utf-8"), nonce, config)
    attestation.verify()


def test_chain_too_long():
    """Certificate chain with more than 10 certs should be rejected."""
    import json
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    long_chain = json.dumps(["AAAA"] * 11)
    attestation = Attestation(long_chain, nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_json_object_not_array():
    """JSON object instead of array should be rejected."""
    import json
    config = GoogleKeyAttestationConfig(
        apk_package_name="com.example.app",
        root_ca=root_ca_pem,
        production=False,
    )
    attestation = Attestation(json.dumps({"not": "an array"}), nonce, config)
    with raises(InvalidCertificateChainException):
        attestation.verify()


def test_malformed_key_description():
    """Malformed DER that isn't a valid KeyDescription should raise PyAttestException."""
    import base64
    import json
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    # Build a cert with a bogus attestation extension
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root_key_bytes = Path("pyattest/testutils/fixtures/root_key.pem").read_bytes()
    root_cert_bytes = Path("pyattest/testutils/fixtures/root_cert.pem").read_bytes()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate as load_pem
    rk = load_pem_private_key(root_key_bytes, b"123")
    rc = load_pem(root_cert_bytes)

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
                b"\x30\x03\x01\x01\xff",  # bogus DER
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
