import base64
import hmac
import json
from typing import List, Optional

from asn1crypto.x509 import Certificate
from cryptography import x509 as cx509
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError

from pyattest.exceptions import (
    InvalidAppIdException,
    InvalidCertificateChainException,
    InvalidNonceException,
    InvalidSecurityLevelException,
    PyAttestException,
)
from pyattest.key_description import (
    OID_KEY_ATTESTATION,
    SECURITY_LEVEL_NAMES,
    SECURITY_LEVEL_SOFTWARE,
    parse_key_description,
)
from pyattest.verifiers.attestation import AttestationVerifier
from pyattest.verifiers.utils import _load_certificate


class GoogleKeyAttestationVerifier(AttestationVerifier):
    def verify(self):
        """
        Verify Android Key Attestation.

        The attestation is a JSON array of base64-encoded DER certificates,
        where the first certificate is the leaf (attestation key) and the
        last is closest to the root.

        Verification steps:
        1. Decode and validate the certificate chain against Google root CAs
        2. Parse the KeyDescription extension from the leaf certificate
        3. Verify the attestation challenge matches the expected nonce
        4. Verify the security level is TEE or StrongBox (not Software)
        5. Verify the package name (if production mode)
        """
        chain, key_description = self.unpack(self.attestation.raw)
        self.verify_nonce(key_description.get("attestation_challenge"))
        self.verify_security_level(
            key_description.get("attestation_security_level")
        )

        if self.attestation.config.production:
            self.verify_package_name(key_description)

        security_level_int = key_description.get("attestation_security_level", 0)
        data = {
            "security_level": SECURITY_LEVEL_NAMES.get(
                security_level_int, str(security_level_int)
            ),
            "attestation_version": key_description.get("attestation_version"),
            "challenge": key_description.get("attestation_challenge"),
            "software_enforced": key_description.get("software_enforced", {}),
            "hardware_enforced": key_description.get("hardware_enforced", {}),
        }

        # Extract package name if available
        app_id = (
            key_description.get("software_enforced", {})
            .get("attestation_application_id", {})
        )
        if app_id.get("package_name"):
            data["package_name"] = app_id["package_name"]

        self.attestation.verified_data({"data": data, "certs": chain})

    def unpack(self, raw):
        """
        Decode the certificate chain and parse the KeyDescription extension.

        Returns (validated_chain, key_description_dict).
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        try:
            cert_chain_b64 = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as e:
            raise PyAttestException(
                "Attestation data is not valid JSON."
            ) from e

        if not isinstance(cert_chain_b64, list) or len(cert_chain_b64) == 0:
            raise InvalidCertificateChainException(
                "Certificate chain is empty or not a list."
            )

        try:
            der_certs = [base64.b64decode(c) for c in cert_chain_b64]
        except Exception as e:
            raise InvalidCertificateChainException(
                "Certificate chain contains invalid base64."
            ) from e

        validated_chain = self.verify_certificate_chain(der_certs)

        # Parse KeyDescription from the leaf certificate (first in chain)
        try:
            leaf_cert = cx509.load_der_x509_certificate(der_certs[0])
        except Exception as e:
            raise InvalidCertificateChainException(
                "Leaf certificate is not valid DER."
            ) from e

        key_description = self._parse_attestation_extension(leaf_cert)

        return validated_chain, key_description

    def verify_certificate_chain(self, der_certs: List[bytes]):
        """
        Validate the certificate chain against Google hardware attestation root CAs.
        """
        root_cas = self.attestation.config.root_cas
        context = ValidationContext(trust_roots=root_cas)

        cert = _load_certificate(der_certs[0])
        intermediates = [_load_certificate(c) for c in der_certs[1:]]

        validator = CertificateValidator(
            cert, intermediates, validation_context=context
        )

        try:
            return validator.validate_usage({"digital_signature"})
        except (PathBuildingError, PathValidationError) as e:
            raise InvalidCertificateChainException from e

    def verify_nonce(self, challenge: Optional[bytes]):
        """Verify the attestation challenge matches the expected nonce."""
        if not challenge or not hmac.compare_digest(challenge, self.attestation.nonce):
            raise InvalidNonceException

    def verify_security_level(self, level: Optional[int]):
        """Reject software-backed keys."""
        if level is None or level == SECURITY_LEVEL_SOFTWARE:
            raise InvalidSecurityLevelException

    def verify_package_name(self, key_description: dict):
        """
        Verify the package name from the attestation extension.

        The package name is in softwareEnforced.attestationApplicationId.
        """
        app_id = (
            key_description.get("software_enforced", {})
            .get("attestation_application_id", {})
        )
        package_name = app_id.get("package_name")
        if (
            not package_name
            or package_name != self.attestation.config.apk_package_name
        ):
            raise InvalidAppIdException

    def _parse_attestation_extension(self, cert: cx509.Certificate) -> dict:
        """Extract and parse the KeyDescription extension from the certificate."""
        oid = cx509.ObjectIdentifier(OID_KEY_ATTESTATION)
        try:
            ext = cert.extensions.get_extension_for_oid(oid)
        except cx509.ExtensionNotFound as e:
            raise ValueError(
                "Key attestation extension not found in certificate."
            ) from e

        if isinstance(ext.value, cx509.UnrecognizedExtension):
            key_desc_bytes = ext.value.value
        elif isinstance(ext.value, bytes):
            key_desc_bytes = ext.value
        else:
            raise ValueError(
                f"Unexpected attestation extension type: {type(ext.value)}"
            )

        return parse_key_description(key_desc_bytes)
