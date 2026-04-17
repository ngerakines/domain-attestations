# caddy-httpsig

A Caddy plugin that signs HTTP responses using [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) with ECDSA P-256.

Responses are signed and include `Signature` and `Signature-Input` headers, allowing clients to verify that a response was produced by the holder of a specific private key. A typical use case is signing `GET /.well-known/did.json` responses so that consumers can authenticate the origin.

## Building

Requires [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Build a Caddy binary with the plugin:

```sh
xcaddy build --with github.com/ngerakines/caddy-httpsig=.
```

Or use the Makefile:

```sh
make build
```

## Configuration

### Caddyfile

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

| Directive        | Description                                                                 | Default                    |
|------------------|-----------------------------------------------------------------------------|----------------------------|
| `key_file`       | Path to a PEM-encoded ECDSA P-256 private key file.                         | _(none, required if no `key_env`)_ |
| `key_env`        | Name of an environment variable containing a PEM-encoded ECDSA P-256 key.   | _(none, required if no `key_file`)_ |
| `key_id`         | Identifier included in the `Signature-Input` header's `keyid` parameter.    | `default`                  |
| `covered`        | Space-separated list of response components to sign.                        | `@status content-type`     |
| `signature_name` | Label for the signature in the `Signature` and `Signature-Input` headers.   | `sig`                      |
| `at_uri`         | AT-URI bound to the signature, emitted as the RFC 9421 `tag` parameter.     | _(none)_                   |

One of `key_file` or `key_env` is required. Both accept PEM-encoded keys in either SEC 1 (`EC PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`) format.

### Covered components

The `covered` directive accepts any combination of:

- `@status` -- the HTTP response status code
- `@method` -- the request method (derived from the request)
- `@path` -- the request path (derived from the request)
- `@authority` -- the request host (derived from the request)
- Any response header name (e.g. `content-type`, `content-digest`)

### AT-URI tag

When `at_uri` is set, its value is included in the signature params as the
RFC 9421 `tag` parameter, binding the signature to a specific AT Protocol
resource:

```
httpsig {
    key_file /path/to/key.pem
    key_id did:key:z...
    at_uri at://did:plc:example/app.bsky.feed.post/abc123
}
```

Produces:

```
Signature-Input: sig=("@status" "content-type");created=1700000000;keyid="did:key:z...";alg="ecdsa-p256-sha256";tag="at://did:plc:example/app.bsky.feed.post/abc123"
```

Because the `tag` parameter is part of `@signature-params`, it is covered by
the signature and cannot be altered without invalidating it.

## Generating a key

Generate an ECDSA P-256 private key with OpenSSL:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
```

Or load a key from an environment variable:

```sh
export HTTPSIG_PRIVATE_KEY="$(cat key.pem)"
```

```
httpsig {
    key_env HTTPSIG_PRIVATE_KEY
    key_id my-server-key
}
```

## Response headers

Signed responses include two headers:

```
Signature-Input: sig=("@status" "content-type");created=1700000000;keyid="my-server-key";alg="ecdsa-p256-sha256"
Signature: sig=:MEUCIQDx...base64...:
```

The signature is computed over the [signature base](https://www.rfc-editor.org/rfc/rfc9421#section-2.5) as defined by RFC 9421, using the `ecdsa-p256-sha256` algorithm (ECDSA with P-256 and SHA-256).

## Testing

```sh
go test -v ./...
```

## License

MIT
