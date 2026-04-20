# server-py

A minimal Python server that serves a `did:web` DID document with RFC 9421 HTTP Message Signatures, allowing consumers to cryptographically verify the document origin.

## Setup

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Provide a key

`HTTPSIG_PRIVATE_KEY` accepts either a `did:key:` string (multibase P-256 private key) or a JWK JSON object. PEM is not supported.

```sh
# did:key form (preferred)
export HTTPSIG_PRIVATE_KEY="did:key:z..."

# JWK form
export HTTPSIG_PRIVATE_KEY='{"kty":"EC","crv":"P-256","x":"...","y":"...","d":"..."}'
```

## Run

```sh
export SERVER_DOMAIN=example.com
flask --app app run
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HTTPSIG_PRIVATE_KEY` | Yes | — | `did:key:` string or JWK JSON object (P-256) |
| `SERVER_DOMAIN` | No | `localhost:5000` | Domain for the `did:web` DID document |
| `SERVICE_CONTROLLER` | No | — | Optional DID to set as the document's top-level `controller` |
| `SERVICE_ALSO_KNOWN_AS` | No | — | Optional comma-separated list of values for the document's `alsoKnownAs` array |

The `keyid` in the `Signature-Input` header is derived automatically from the public key using `did:key` encoding with an RFC 7638 JWK Thumbprint fragment (e.g. `did:key:zDn...#<thumbprint>`).

## Endpoints

- `GET /` — Home page with link to DID document
- `GET /.well-known/did.json` — Signed DID document with `Signature` and `Signature-Input` headers

## Verifying signatures

```sh
curl -v http://localhost:5000/.well-known/did.json
```

The response includes:

```
Signature-Input: sig=("@status" "content-type");created=1700000000;keyid="did:key:zDn...#abc123";alg="ecdsa-p256-sha256"
Signature: sig=:MEUCIQDx...base64...:
```

The `keyid` matches a `verificationMethod` entry in the DID document, which contains the `publicKeyJwk` needed to verify the signature.

## Testing

```sh
pytest -v
```
