"""
Configuration for Android Key Attestation verification.

Root CA certificates are bundled from Google's official sources:
  RSA roots: https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
  ECDSA root: https://github.com/android/keyattestation/blob/b1bf4375/roots.json

There are 4 RSA root re-issuances (same key, different validity periods: 2016, 2019,
2021, 2022) and 1 ECDSA root (2025) for remotely provisioned devices. Older Android
devices chain to older root generations - all 5 are needed for full compatibility.
"""

from pathlib import Path
from typing import List, Optional

from asn1crypto.x509 import Certificate

from pyattest.configs.config import Config
from pyattest.verifiers.google_assertion import GoogleAssertionVerifier
from pyattest.verifiers.google_key_attestation import GoogleKeyAttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class GoogleKeyAttestationConfig(Config):
    attestation_verifier_class = GoogleKeyAttestationVerifier
    assertion_verifier_class = GoogleAssertionVerifier

    def __init__(
        self,
        apk_package_name: str,
        production: bool,
        root_ca: Optional[bytes] = None,
        root_cas: Optional[List[Certificate]] = None,
    ):
        self.apk_package_name = apk_package_name
        self.production = production
        self._custom_root_ca = _load_certificate(root_ca) if root_ca else None
        self._custom_root_cas = root_cas

    @property
    def root_cas(self) -> List[Certificate]:
        """
        Google hardware attestation root CAs.

        Priority: root_cas (pre-loaded list) > root_ca (single PEM bytes) > bundled certs.

        Use ``fetch_google_key_attestation_roots()`` from ``pyattest.verifiers.utils``
        to get an up-to-date list merged with the bundled roots.
        """
        if self._custom_root_cas:
            return self._custom_root_cas

        if self._custom_root_ca:
            return [self._custom_root_ca]

        cert_dir = Path(__file__).parent / "../certificates"
        roots = []
        for pem_file in sorted(cert_dir.glob("google_hardware_attestation_root_*.pem")):
            roots.append(_load_certificate(pem_file.read_bytes()))
        return roots
