import json
import urllib.request
from pathlib import Path
from typing import List

from asn1crypto import pem
from asn1crypto.x509 import Certificate

GOOGLE_ROOT_CERTS_URL = "https://android.googleapis.com/attestation/root"
GOOGLE_REVOCATION_STATUS_URL = "https://android.googleapis.com/attestation/status"


def _load_certificate(cert_bytes: bytes) -> Certificate:
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)

    return Certificate.load(cert_bytes)


def fetch_google_key_attestation_roots(
    url: str = GOOGLE_ROOT_CERTS_URL,
) -> List[Certificate]:
    """
    Fetch current Google hardware attestation root certificates and merge
    with the bundled roots, returning a deduplicated list.

    Useful for keeping root CAs up to date.

    Usage::

        from pyattest.verifiers.utils import fetch_google_key_attestation_roots
        from pyattest.configs.google_key_attestation import GoogleKeyAttestationConfig

        roots = fetch_google_key_attestation_roots()
        config = GoogleKeyAttestationConfig(
            apk_package_name='com.example.app',
            production=True,
            root_cas=roots,
        )
    """
    # Fetch from Google's endpoint
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        pem_strings = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Failed to fetch root certificates from {url}: {e}") from e

    if not isinstance(pem_strings, list):
        raise RuntimeError(f"Unexpected response format from {url}: expected JSON array")

    fetched = [_load_certificate(p.encode()) for p in pem_strings]

    # Load bundled roots
    cert_dir = Path(__file__).parent / "../certificates"
    bundled = [
        _load_certificate(p.read_bytes())
        for p in sorted(cert_dir.glob("google_hardware_attestation_root_*.pem"))
    ]

    # Deduplicate by DER bytes
    seen = set()
    merged = []
    for cert in bundled + fetched:
        der = cert.dump()
        if der not in seen:
            seen.add(der)
            merged.append(cert)

    return merged


def fetch_google_revocation_list(
    url: str = GOOGLE_REVOCATION_STATUS_URL,
) -> set:
    """
    Fetch Google's certificate revocation status list.

    Returns a set of revoked certificate serial numbers as hex strings
    (without 0x prefix), matching Google's API format.

    See: https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status

    Usage::

        from pyattest.verifiers.utils import fetch_google_revocation_list

        revoked = fetch_google_revocation_list()
        config = GoogleKeyAttestationConfig(
            apk_package_name='com.example.app',
            production=True,
            revoked_serials=revoked,
        )
    """
    try:
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(f"Failed to fetch revocation list from {url}: {e}") from e

    entries = data.get("entries")
    if not isinstance(entries, dict):
        raise RuntimeError(f"Unexpected response format from {url}: missing 'entries' dict")

    # Serial numbers in Google's API are hex strings without 0x prefix.
    # Lookup in the verifier uses format(cert.serial_number, "x").
    return {
        serial
        for serial, info in entries.items()
        if isinstance(info, dict) and info.get("status") == "REVOKED"
    }
