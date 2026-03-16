import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from flask import Flask, Response


def load_private_key():
    pem_data = os.environ.get("HTTPSIG_PRIVATE_KEY")
    if not pem_data:
        raise RuntimeError("HTTPSIG_PRIVATE_KEY environment variable is required")
    key = serialization.load_pem_private_key(pem_data.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("Key must be an ECDSA private key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise RuntimeError("Key must use the P-256 curve")
    return key


def public_key_jwk(private_key):
    """Return the public key as a JWK dict with required EC members."""
    pub = private_key.public_key()
    numbers = pub.public_numbers()
    x_bytes = numbers.x.to_bytes(32, byteorder="big")
    y_bytes = numbers.y.to_bytes(32, byteorder="big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode(),
    }


def jwk_thumbprint(jwk):
    """Compute the RFC 7638 JWK Thumbprint (SHA-256, base64url-encoded).

    For EC keys the required members in lexicographic order are:
    crv, kty, x, y.
    """
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# Base58btc alphabet (Bitcoin)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc (Bitcoin alphabet)."""
    n = int.from_bytes(data, "big")
    result = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r])
    # Preserve leading zero bytes
    for byte in data:
        if byte == 0:
            result.append(_B58_ALPHABET[0])
        else:
            break
    result.reverse()
    return result.decode("ascii")


def public_key_multibase(private_key):
    """Encode the public key as a multibase base58btc string with multicodec prefix.

    The result is suitable for use as a publicKeyMultibase value in a DID
    document with type "Multikey".
    """
    pub = private_key.public_key()
    # Compressed public key (33 bytes: 0x02/0x03 prefix + 32-byte x)
    compressed = pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    # Multicodec prefix for P-256 public key: 0x1200 varint-encoded as 0x80 0x24
    multicodec = b"\x80\x24" + compressed
    # Multibase base58btc: 'z' prefix
    return "z" + _base58btc_encode(multicodec)


def did_key_id(private_key):
    """Derive a did:key identifier and JWK thumbprint fragment for the public key.

    Returns (did_key, key_id) where:
      - did_key is e.g. "did:key:zDn..."
      - key_id is "did:key:zDn...#<jwk-thumbprint>"
    """
    multibase = public_key_multibase(private_key)
    did_key = "did:key:" + multibase

    jwk = public_key_jwk(private_key)
    thumbprint = jwk_thumbprint(jwk)

    return did_key, f"{did_key}#{thumbprint}"


def build_signature_base(status, content_type, covered, key_id, created):
    """Build RFC 9421 signature base string and signature params."""
    lines = []
    for component in covered:
        if component == "@status":
            lines.append(f'"{component}": {status}')
        elif component == "content-type":
            lines.append(f'"{component}": {content_type}')

    parts = " ".join(f'"{c}"' for c in covered)
    sig_params = f"({parts});created={created};keyid=\"{key_id}\";alg=\"ecdsa-p256-sha256\""
    lines.append(f'"@signature-params": {sig_params}')

    return "\n".join(lines), sig_params


def sign_response(response, private_key, key_id, covered):
    """Add RFC 9421 HTTP Message Signature headers to a response."""
    created = int(time.time())
    content_type = response.content_type or "application/octet-stream"

    sig_base, sig_params = build_signature_base(
        response.status_code, content_type, covered, key_id, created
    )

    digest = hashlib.sha256(sig_base.encode()).digest()
    sig_bytes = private_key.sign(
        digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    sig_encoded = base64.standard_b64encode(sig_bytes).decode()

    response.headers["Signature-Input"] = f"sig={sig_params}"
    response.headers["Signature"] = f"sig=:{sig_encoded}:"
    return response


def create_app(private_key=None):
    app = Flask(__name__)

    if private_key is None:
        private_key = load_private_key()

    domain = os.environ.get("SERVER_DOMAIN", "localhost:5000")
    covered = ["@status", "content-type"]

    did = f"did:web:{domain}"
    _did_key, key_id = did_key_id(private_key)
    multibase = public_key_multibase(private_key)

    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }

    @app.route("/")
    def home():
        return (
            f"<html><body>"
            f"<h1>Domain Attestation Server</h1>"
            f"<p>DID: <code>{did}</code></p>"
            f'<p><a href="/.well-known/did.json">/.well-known/did.json</a></p>'
            f"</body></html>"
        )

    @app.route("/.well-known/did.json")
    def did_json():
        body = json.dumps(did_document, indent=2)
        response = Response(body, status=200, content_type="application/json")
        return sign_response(response, private_key, key_id, covered)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run()
