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

    # Verification method id should be did:key:<pubkey>#<thumbprint>
    _did_key, expected_key_id = did_key_id(private_key)
    assert vm["id"] == expected_key_id
    assert vm["id"].startswith("did:key:z")
    assert "#" in vm["id"]

    # publicKeyMultibase should be the multibase-encoded compressed P-256 key
    assert "publicKeyMultibase" in vm
    expected_multibase = public_key_multibase(private_key)
    assert vm["publicKeyMultibase"] == expected_multibase
    assert vm["publicKeyMultibase"].startswith("z")


def test_signature_headers_present(client, key_pair):
    private_key, _ = key_pair
    resp = client.get("/.well-known/did.json")

    sig_input = resp.headers.get("Signature-Input")
    assert sig_input is not None
    assert sig_input.startswith("sig=")
    assert 'alg="ecdsa-p256-sha256"' in sig_input

    # keyid should contain the did:key and thumbprint
    _did_key, expected_key_id = did_key_id(private_key)
    assert f'keyid="{expected_key_id}"' in sig_input

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

    # Fragment is a valid JWK thumbprint
    fragment = key_id.split("#", 1)[1]
    jwk = public_key_jwk(private_key)
    assert fragment == jwk_thumbprint(jwk)


def test_missing_key_env_var():
    os.environ.pop("HTTPSIG_PRIVATE_KEY", None)
    with pytest.raises(RuntimeError, match="HTTPSIG_PRIVATE_KEY"):
        create_app()
