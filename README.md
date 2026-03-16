# Domain Attestations for AT Protocol

Cryptographic domain attestations for AT Protocol `did:web` identities using [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).

This project demonstrates how HTTP responses serving DID documents can be signed with ECDSA P-256, enabling consumers to verify that a `did:web` DID document was genuinely produced by the holder of a specific private key. By binding a domain's DID document to a cryptographic signature, we create a trust anchor that is independently verifiable without relying on TLS certificate authority infrastructure alone.

Companion implementation for the paper:

> **Onions in the ATmosphere: Decentralizing Trust in Identity**
> Paul Syverson & Nick Gerakines
> *FOCI 2026 (Free and Open Communications on the Internet)*

## Background

The AT Protocol uses two DID methods: `did:plc` (registered in a public ledger) and `did:web` (resolved via HTTPS from a domain). While `did:plc` is self-certifying, `did:web` relies on the security of DNS and TLS for authenticity. This means `did:web` inherits the blocking, hijacking, fingerprinting, and surveillance risks of traditional web domains.

RFC 9421 HTTP Message Signatures provide a mechanism to sign HTTP responses with a key whose identity is embedded in the DID document itself. A server signs its `/.well-known/did.json` response, and any client can verify the signature against the public key published in that document. This creates a cryptographic binding between the domain and the DID document it serves, independent of the TLS layer.

The FOCI'26 paper explores how this technique combines with existing approaches to self-certifying meaningful identity (SCMI), including union associations, onion associations, and contextual trust. It describes how `did:web` domain attestations, together with AT Protocol's existing `did:plc` method, enable stronger blocking resistance and manipulation resistance for decentralized identity.

## Architecture

```
┌─────────────────────┐         GET /.well-known/did.json          ┌─────────────────────┐
│                     │ ──────────────────────────────────────────→ │                     │
│  Firefox Extension  │                                            │   Server (Python     │
│  (Signature         │ ←────────────────────────────────────────── │   or Caddy plugin)   │
│   Verification)     │   200 OK + Signature + Signature-Input     │   (Signature         │
│                     │          + DID Document (JSON)              │    Generation)       │
└─────────────────────┘                                            └─────────────────────┘
        │                                                                   │
        │  1. Parse Signature-Input header                                  │  1. Load ECDSA P-256 private key
        │  2. Fetch /.well-known/did.json                                   │  2. Build RFC 9421 signature base
        │  3. Find verificationMethod by keyid                              │  3. Sign with ecdsa-p256-sha256
        │  4. Rebuild signature base                                        │  4. Attach Signature and
        │  5. Verify ECDSA P-256 signature                                  │     Signature-Input headers
        │  6. Update toolbar icon                                           │
        └───────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Language | Role |
|---|---|---|
| [server-py](server-py/) | Python (Flask) | Serves and signs a `did:web` DID document |
| [caddy-httpsig](caddy-httpsig/) | Go (Caddy plugin) | Caddy middleware that signs any HTTP response |
| [firefox-extension](firefox-extension/) | TypeScript | Verifies HTTP signatures on DID documents in the browser |

---

## server-py

A standalone Flask server that constructs a `did:web` DID document from an ECDSA P-256 private key and signs every response to `/.well-known/did.json` with RFC 9421 HTTP Message Signatures.

### DID Document Construction

The server derives a full DID document from the private key:

1. Encodes the public key as a `publicKeyMultibase` value (base58btc with the P-256 multicodec prefix)
2. Computes an [RFC 7638 JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638) (SHA-256, base64url) to use as the key fragment
3. Constructs a `did:key` identifier (e.g. `did:key:zDn...#<thumbprint>`) for the verification method
4. Produces a DID document with W3C DID v1 and Multikey contexts

### Endpoints

- `GET /` — Home page with a link to the DID document
- `GET /.well-known/did.json` — Signed DID document with `Signature` and `Signature-Input` headers

### Setup and Usage

```sh
# Create a virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate an ECDSA P-256 key
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
export HTTPSIG_PRIVATE_KEY="$(cat key.pem)"

# Run the server
export SERVER_DOMAIN=example.com
flask --app app run
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `HTTPSIG_PRIVATE_KEY` | Yes | — | PEM-encoded ECDSA P-256 private key |
| `SERVER_DOMAIN` | No | `localhost:5000` | Domain used in the `did:web` DID document |

### Testing

```sh
pytest -v
```

---

## caddy-httpsig

A [Caddy](https://caddyserver.com/) HTTP middleware plugin that signs responses using RFC 9421 HTTP Message Signatures with ECDSA P-256. Unlike server-py, this plugin signs responses from any Caddy-served origin, making it suitable for adding signatures to existing infrastructure.

### Building

Requires [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/ngerakines/caddy-httpsig=.
```

Or use the Makefile:

```sh
make build
```

### Caddyfile Configuration

```
{
    order httpsig before respond
}

:8080 {
    httpsig {
        key_file /path/to/ecdsa-p256-private.pem
        key_id my-server-key
        covered @status content-type
    }

    respond /.well-known/did.json `{"id":"did:web:example.com"}` 200 {
        Content-Type application/json
    }
}
```

### Directives

| Directive | Description | Default |
|---|---|---|
| `key_file` | Path to a PEM-encoded ECDSA P-256 private key file | _(required if no `key_env`)_ |
| `key_env` | Environment variable containing a PEM-encoded ECDSA P-256 key | _(required if no `key_file`)_ |
| `key_id` | Identifier in the `Signature-Input` header's `keyid` parameter | `default` |
| `covered` | Space-separated response components to sign | `@status content-type` |
| `signature_name` | Label for the signature in output headers | `sig` |

### Covered Components

The `covered` directive accepts:

- `@status` — HTTP response status code
- `@method` — request method
- `@path` — request path
- `@authority` — request host
- Any response header name (e.g. `content-type`, `content-digest`)

### Testing

```sh
go test -v ./...
```

---

## firefox-extension

A Firefox Web Extension that automatically intercepts HTTP responses and verifies RFC 9421 signatures on `did:web` DID documents. When you visit a page that serves signed responses, the extension verifies the signature and reflects the result in the toolbar icon.

### Verification Flow

1. **Intercept** — listens on `webRequest.onHeadersReceived` for main frame navigations
2. **Parse** — extracts `Signature` and `Signature-Input` headers; parses key ID, algorithm, and covered components
3. **Validate algorithm** — ensures `ecdsa-p256-sha256`
4. **Fetch DID document** — retrieves `/.well-known/did.json` from the response origin
5. **Lookup verification method** — finds the method matching the `keyid` from the signature
6. **Extract public key** — reads the JWK (`publicKeyJwk`) from the verification method
7. **Rebuild signature base** — reconstructs the RFC 9421 signature base string from covered components
8. **Verify** — uses the Web Crypto API (`crypto.subtle.verify`) with ECDSA P-256 to check the signature
9. **Display result** — updates the toolbar icon (green = verified, red = failed) and stores the result

### Toolbar Popup

The popup UI has two tabs:

- **Current** — shows the verification status, DID, key ID, algorithm, covered components, and a step-by-step breakdown of the verification process with timestamps and durations
- **History** — lists the last 50 verification results with expandable details

### Installation

```sh
npm install
npm run build
```

Then load the extension in Firefox:

1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json` from the `firefox-extension/` directory

### Development

```sh
npm run watch      # rebuild on file changes
npm run typecheck  # type-check without emitting
```

---

## RFC 9421 Signature Details

All components implement [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) with the following parameters:

- **Algorithm:** `ecdsa-p256-sha256` (ECDSA with curve P-256 and SHA-256)
- **Key format:** PEM-encoded ECDSA P-256 (SEC 1 or PKCS#8) for signing; JWK for verification
- **Signature encoding:** Base64-encoded DER/ASN.1 on the wire (the Firefox extension converts to IEEE P1363 for the Web Crypto API)
- **Default covered components:** `@status`, `content-type`

### Response Headers

Signed responses include two headers:

```
Signature-Input: sig=("@status" "content-type");created=1700000000;keyid="did:key:zDn...#abc123";alg="ecdsa-p256-sha256"
Signature: sig=:MEUCIQDx...base64...:
```

The `keyid` value matches a `verificationMethod` entry in the DID document, which contains the public key needed to verify the signature.

## Generating a Key

Both server components accept a PEM-encoded ECDSA P-256 private key. Generate one with OpenSSL:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

## Quick Start

To try the full signing and verification flow locally:

```sh
# 1. Generate a key
openssl ecparam -name prime256v1 -genkey -noout -out key.pem

# 2. Start the Python server
cd server-py
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export HTTPSIG_PRIVATE_KEY="$(cat ../key.pem)"
flask --app app run &

# 3. Build and load the Firefox extension
cd ../firefox-extension
npm install && npm run build
# Load in Firefox via about:debugging#/runtime/this-firefox

# 4. Visit http://localhost:5000/.well-known/did.json in Firefox
# The extension icon should turn green, indicating a verified signature.
```

## License

MIT
