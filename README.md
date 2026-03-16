# domain-attestations

Demonstrations of domain-based attestations for AT Protocol `did:web` identities using [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).

These implementations sign `GET /.well-known/did.json` responses with `Signature` and `Signature-Input` headers, allowing consumers to cryptographically verify that a DID document was served by the holder of the corresponding private key.

Companion code for the paper: *Onions in the ATmosphere: Decentralizing Trust in Identity* (Syverson & Gerakines, FOCI 2026).

## Components

| Component | Language | Description |
|---|---|---|
| [server-py](server-py/) | Python (Flask) | Standalone server that serves and signs a `did:web` DID document |
| [caddy-httpsig](caddy-httpsig/) | Go (Caddy plugin) | Caddy middleware that signs any HTTP response with RFC 9421 signatures |
| [firefox-extension](firefox-extension/) | JavaScript | Firefox extension that verifies HTTP signatures on DID documents |

The server components use ECDSA P-256 with SHA-256 (`ecdsa-p256-sha256`) and produce interoperable signatures. The Firefox extension verifies these signatures using the Web Crypto API.

## Generating a key

Both components accept a PEM-encoded ECDSA P-256 private key:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

See each component's README for configuration details.
