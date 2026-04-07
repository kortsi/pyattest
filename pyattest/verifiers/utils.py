import json
import urllib.request
from pathlib import Path
from typing import List

from asn1crypto import pem
from asn1crypto.x509 import Certificate

GOOGLE_ROOT_CERTS_URL = "https://android.googleapis.com/attestation/root"


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
    resp = urllib.request.urlopen(url)
    pem_strings = json.loads(resp.read())
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
