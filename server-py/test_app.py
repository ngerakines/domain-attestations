import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

from app import (
    create_app,
    build_signature_base,
    public_key_jwk,
    public_key_multibase,
    jwk_thumbprint,
    did_key_id,
    load_private_key,
    _base58btc_encode,
    _base58btc_decode,
    _load_from_did_key,
    _load_from_jwk,
)


@pytest.fixture
def key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, pem


@pytest.fixture
def client(key_pair):
    private_key, pem = key_pair
    os.environ["HTTPSIG_PRIVATE_KEY"] = pem.decode()
    os.environ["SERVER_DOMAIN"] = "example.com"
    app = create_app(private_key=private_key)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    os.environ.pop("HTTPSIG_PRIVATE_KEY", None)
    os.environ.pop("SERVER_DOMAIN", None)


def test_home_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Domain Attestation Server" in resp.data
    assert b"did:web:example.com" in resp.data


def test_did_document_structure(client, key_pair):
    private_key, _ = key_pair
    resp = client.get("/.well-known/did.json")
    assert resp.status_code == 200
    assert resp.content_type == "application/json"

    doc = json.loads(resp.data)
    assert doc["id"] == "did:web:example.com"
    assert "@context" in doc
    assert len(doc["verificationMethod"]) == 1

    vm = doc["verificationMethod"][0]
    assert vm["type"] == "Multikey"
    assert vm["id"] == "did:web:example.com#atproto"
    assert vm["controller"] == "did:web:example.com"

    # publicKeyMultibase should be the multibase-encoded compressed P-256 key
    expected_multibase = public_key_multibase(private_key)
    assert vm["publicKeyMultibase"] == expected_multibase
    assert vm["publicKeyMultibase"].startswith("z")

    # alsoKnownAs and service should be present
    assert doc["alsoKnownAs"] == []
    assert len(doc["service"]) == 1
    assert doc["service"][0]["id"] == "#attestation"
    assert doc["service"][0]["type"] == "DomainAttestationService"

    # controller should not be present without SERVICE_CONTROLLER env var
    assert "controller" not in doc


def test_did_document_with_controller(key_pair):
    """SERVICE_CONTROLLER env var adds controller to the DID document."""
    private_key, pem = key_pair
    os.environ["HTTPSIG_PRIVATE_KEY"] = pem.decode()
    os.environ["SERVER_DOMAIN"] = "example.com"
    os.environ["SERVICE_CONTROLLER"] = "did:plc:abc123"
    app = create_app(private_key=private_key)
    app.config["TESTING"] = True
    with app.test_client() as client:
        resp = client.get("/.well-known/did.json")
        doc = json.loads(resp.data)
        assert doc["controller"] == "did:plc:abc123"
    os.environ.pop("SERVICE_CONTROLLER", None)


def test_signature_headers_present(client, key_pair):
    private_key, _ = key_pair
    resp = client.get("/.well-known/did.json")

    sig_input = resp.headers.get("Signature-Input")
    assert sig_input is not None
    assert sig_input.startswith("sig=")
    assert 'alg="ecdsa-p256-sha256"' in sig_input

    # keyid should be the verification method id (did:web:domain#atproto)
    assert 'keyid="did:web:example.com#atproto"' in sig_input

    sig = resp.headers.get("Signature")
    assert sig is not None
    assert sig.startswith("sig=:")
    assert sig.endswith(":")


def test_signature_verifies(client, key_pair):
    private_key, _ = key_pair
    resp = client.get("/.well-known/did.json")

    # Extract signature
    sig_header = resp.headers["Signature"]
    sig_b64 = sig_header.removeprefix("sig=:").removesuffix(":")
    sig_bytes = base64.standard_b64decode(sig_b64)

    # Extract signature params
    sig_input = resp.headers["Signature-Input"]
    sig_params = sig_input.removeprefix("sig=")

    # Reconstruct signature base
    lines = [
        '"@status": 200',
        '"content-type": application/json',
        f'"@signature-params": {sig_params}',
    ]
    sig_base = "\n".join(lines)

    # Verify
    digest = hashlib.sha256(sig_base.encode()).digest()
    public_key = private_key.public_key()
    public_key.verify(
        sig_bytes,
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def test_build_signature_base():
    key_id = "did:key:zDntest#abc123"
    base, params = build_signature_base(
        200, "application/json", ["@status", "content-type"], key_id, 1700000000
    )
    assert '"@status": 200' in base
    assert '"content-type": application/json' in base
    assert '"@signature-params":' in base
    assert "created=1700000000" in params
    assert f'keyid="{key_id}"' in params
    assert 'alg="ecdsa-p256-sha256"' in params


def test_public_key_jwk(key_pair):
    private_key, _ = key_pair
    jwk = public_key_jwk(private_key)
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert len(base64.urlsafe_b64decode(jwk["x"] + "==")) == 32
    assert len(base64.urlsafe_b64decode(jwk["y"] + "==")) == 32


def test_jwk_thumbprint(key_pair):
    private_key, _ = key_pair
    jwk = public_key_jwk(private_key)
    thumbprint = jwk_thumbprint(jwk)
    # RFC 7638: base64url-encoded SHA-256, no padding
    assert "=" not in thumbprint
    raw = base64.urlsafe_b64decode(thumbprint + "==")
    assert len(raw) == 32  # SHA-256 is 32 bytes


def test_did_key_id(key_pair):
    private_key, _ = key_pair
    did_key, key_id = did_key_id(private_key)

    # did:key starts with "did:key:z" (multibase base58btc)
    assert did_key.startswith("did:key:z")

    # key_id is did:key + # + thumbprint
    assert key_id.startswith(did_key + "#")

    # Fragment is the multibase value per the did:key spec
    fragment = key_id.split("#", 1)[1]
    expected_multibase = public_key_multibase(private_key)
    assert fragment == expected_multibase


def test_missing_key_env_var():
    os.environ.pop("HTTPSIG_PRIVATE_KEY", None)
    with pytest.raises(RuntimeError, match="HTTPSIG_PRIVATE_KEY"):
        create_app()


def test_load_private_key_from_did_key(key_pair):
    """Test loading a private key from a did:key: string with P-256 private multicodec."""
    private_key, _ = key_pair
    # Encode the private key as a did:key string (multicodec prefix 0x86 0x24 for P-256 private)
    private_numbers = private_key.private_numbers()
    key_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")
    # P-256 private key multicodec prefix
    multicodec = b"\x86\x26" + key_bytes
    did_key_str = "did:key:z" + _base58btc_encode(multicodec)

    loaded = _load_from_did_key(did_key_str)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)
    # Verify same key by comparing public key coordinates
    orig_pub = private_key.public_key().public_numbers()
    loaded_pub = loaded.public_key().public_numbers()
    assert orig_pub.x == loaded_pub.x
    assert orig_pub.y == loaded_pub.y


def test_load_private_key_from_jwk(key_pair):
    """Test loading a private key from a JWK JSON string."""
    private_key, _ = key_pair
    numbers = private_key.private_numbers()
    pub = numbers.public_numbers
    jwk = json.dumps({
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(pub.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(pub.y.to_bytes(32, "big")).rstrip(b"=").decode(),
        "d": base64.urlsafe_b64encode(numbers.private_value.to_bytes(32, "big")).rstrip(b"=").decode(),
    })

    loaded = _load_from_jwk(jwk)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert isinstance(loaded.curve, ec.SECP256R1)
    loaded_pub = loaded.public_key().public_numbers()
    assert pub.x == loaded_pub.x
    assert pub.y == loaded_pub.y


def test_load_private_key_jwk_missing_d():
    """JWK without 'd' parameter should raise."""
    jwk = json.dumps({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"})
    with pytest.raises(RuntimeError, match="missing 'd' parameter"):
        _load_from_jwk(jwk)


def test_load_private_key_did_key_public_rejected():
    """did:key with a public key prefix should be rejected."""
    # Use a dummy P-256 public key multicodec prefix (0x80 0x24)
    dummy = b"\x80\x24" + b"\x00" * 33
    did_key_str = "did:key:z" + _base58btc_encode(dummy)
    with pytest.raises(RuntimeError, match="public key, not a private key"):
        _load_from_did_key(did_key_str)


def test_load_private_key_env_did_key(key_pair):
    """Test that load_private_key dispatches correctly for did:key format."""
    private_key, _ = key_pair
    private_numbers = private_key.private_numbers()
    key_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")
    multicodec = b"\x86\x26" + key_bytes
    did_key_str = "did:key:z" + _base58btc_encode(multicodec)

    os.environ["HTTPSIG_PRIVATE_KEY"] = did_key_str
    loaded = load_private_key()
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    os.environ.pop("HTTPSIG_PRIVATE_KEY", None)


def test_load_private_key_env_jwk(key_pair):
    """Test that load_private_key dispatches correctly for JWK format."""
    private_key, _ = key_pair
    numbers = private_key.private_numbers()
    pub = numbers.public_numbers
    jwk = json.dumps({
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(pub.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(pub.y.to_bytes(32, "big")).rstrip(b"=").decode(),
        "d": base64.urlsafe_b64encode(numbers.private_value.to_bytes(32, "big")).rstrip(b"=").decode(),
    })

    os.environ["HTTPSIG_PRIVATE_KEY"] = jwk
    loaded = load_private_key()
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    os.environ.pop("HTTPSIG_PRIVATE_KEY", None)


def test_base58btc_round_trip():
    """Test base58btc encode/decode round-trip."""
    test_data = b"\x86\x26" + os.urandom(32)
    encoded = _base58btc_encode(test_data)
    decoded = _base58btc_decode(encoded)
    assert decoded == test_data
