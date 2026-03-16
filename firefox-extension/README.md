# firefox-extension

A Firefox extension that verifies RFC 9421 HTTP Message Signatures on `did:web` DID documents using ECDSA P-256.

When you visit a site that serves signed responses (e.g. `/.well-known/did.json` from server-py or caddy-httpsig), the extension automatically verifies the signature and shows the result in the toolbar.

## How it works

1. Intercepts HTTP responses on main frame navigation
2. Checks for `Signature` and `Signature-Input` headers
3. Parses the signature metadata (key ID, algorithm, covered components)
4. Fetches the site's DID document from `/.well-known/did.json`
5. Finds the verification method matching the key ID
6. Extracts the JWK public key from the DID document
7. Rebuilds the RFC 9421 signature base string
8. Verifies the ECDSA P-256 signature using the Web Crypto API
9. Updates the toolbar icon (green = verified, red = failed)

## Installation

1. Clone this repository
2. Install dependencies and build:
   ```sh
   npm install
   npm run build
   ```
3. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
4. Click "Load Temporary Add-on"
5. Select the `manifest.json` file from this directory

## Development

Source is written in TypeScript (`src/background.ts`, `src/popup.ts`) and bundled to JS with esbuild.

```sh
npm run watch      # rebuild on change
npm run typecheck  # type-check without emitting
```

## Testing with server-py

1. Start the server-py application (see `../server-py/README.md`)
2. Navigate to `http://localhost:5000/.well-known/did.json` in Firefox
3. Click the extension icon to see verification details

## Supported signature format

- Algorithm: `ecdsa-p256-sha256` (ECDSA P-256 with SHA-256)
- Key format: JWK (`publicKeyJwk`) in DID document verification methods
- Signature encoding: DER/ASN.1 (converted to IEEE P1363 for Web Crypto API)
- Signature label: configurable (default `sig`)
- Covered components: parsed dynamically from `Signature-Input` header
