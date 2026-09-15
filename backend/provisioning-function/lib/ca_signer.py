import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def parse_and_verify_csr(csr_pem: bytes, expected_device_id: str) -> x509.CertificateSigningRequest:
    """Parse a PEM CSR, verify its self-signature, and check CN + key algorithm.

    Verifying the self-signature proves possession of the private key
    matching the embedded public key. The CN is checked against the
    device_id from the request so a device can't request a cert for a
    different device's identity even with a valid token for itself. The key
    algorithm/curve is checked so only EC P-256 keys (what the firmware
    generates) are accepted.

    Raises ValueError on any check failure.
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except ValueError as exc:
        raise ValueError(f"malformed CSR: {exc}") from exc

    if not csr.is_signature_valid:
        raise ValueError("CSR self-signature verification failed")

    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

    if not common_names or common_names[0].value != expected_device_id:
        raise ValueError("CSR CN does not match device_id")

    public_key = csr.public_key()

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("CSR public key is not an EC key")

    if public_key.curve.name != "secp256r1":
        raise ValueError("CSR public key is not on the P-256 curve")

    return csr


def sign_device_certificate(
    csr: x509.CertificateSigningRequest,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    device_id: str,
) -> tuple[bytes, str]:
    """Sign a new leaf certificate for the given CSR using the Intermediate CA.

    Returns (certificate_pem_bytes, serial_number_hex).
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    now = datetime.datetime.now(datetime.timezone.utc)
    serial_number = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM), format(serial_number, "x")
