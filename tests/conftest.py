import pytest


@pytest.fixture(autouse=True)
def _private_ai_ledger(tmp_path, monkeypatch):
    """Tests never touch the real spending ledger (~/.aegis/ai-spend.json) or the user's AI limits."""
    monkeypatch.setenv("AEGIS_AI_LEDGER", str(tmp_path / "ai-spend.json"))
    monkeypatch.delenv("AEGIS_AI_BUDGET", raising=False)
    monkeypatch.delenv("AEGIS_AI_TOTAL_BUDGET", raising=False)


@pytest.fixture
def make_cert():
    """Self-signed certificate and key files for a host name (TLS origins and checks)."""
    pytest.importorskip("cryptography")
    import datetime

    def make(tmp_path, name: str):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        return cert_path, key_path

    return make
