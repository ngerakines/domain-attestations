package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(HTTPSig{})
	httpcaddyfile.RegisterHandlerDirective("httpsig", parseCaddyfile)
}

// HTTPSig signs HTTP responses using RFC 9421 HTTP Message Signatures
// with ECDSA P-256 (ecdsa-p256-sha256).
type HTTPSig struct {
	// KeyFile is the path to a PEM-encoded ECDSA private key file.
	KeyFile string `json:"key_file,omitempty"`

	// KeyEnv is the name of an environment variable containing
	// a PEM-encoded ECDSA private key.
	KeyEnv string `json:"key_env,omitempty"`

	// KeyID is the identifier for the signing key, included in
	// the Signature-Input header. Defaults to "default".
	KeyID string `json:"key_id,omitempty"`

	// CoveredComponents lists the response components to include
	// in the signature. Defaults to ["@status", "content-type"].
	// Supported derived components: @status, @method, @path, @authority.
	// Any response header name is also supported.
	CoveredComponents []string `json:"covered_components,omitempty"`

	// SignatureName is the label for the signature in the Signature
	// and Signature-Input headers. Defaults to "sig".
	SignatureName string `json:"signature_name,omitempty"`

	// ATURI, when non-empty, is serialized as the RFC 9421 `tag`
	// signature parameter (e.g. "at://did:plc:abc/app.bsky.feed.post/xyz").
	// This binds the signature to a specific AT Protocol resource.
	ATURI string `json:"at_uri,omitempty"`

	key    *ecdsa.PrivateKey
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (HTTPSig) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.httpsig",
		New: func() caddy.Module { return new(HTTPSig) },
	}
}

// Provision loads the signing key and sets defaults.
func (h *HTTPSig) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	if h.KeyID == "" {
		h.KeyID = "default"
	}
	if h.SignatureName == "" {
		h.SignatureName = "sig"
	}
	if len(h.CoveredComponents) == 0 {
		h.CoveredComponents = []string{"@status", "content-type"}
	}

	var pemData []byte
	switch {
	case h.KeyFile != "":
		data, err := os.ReadFile(h.KeyFile)
		if err != nil {
			return fmt.Errorf("httpsig: reading key file: %w", err)
		}
		pemData = data
	case h.KeyEnv != "":
		val := os.Getenv(h.KeyEnv)
		if val == "" {
			return fmt.Errorf("httpsig: environment variable %q is empty", h.KeyEnv)
		}
		pemData = []byte(val)
	default:
		return fmt.Errorf("httpsig: either key_file or key_env must be configured")
	}

	key, err := parseECDSAPrivateKey(pemData)
	if err != nil {
		return fmt.Errorf("httpsig: parsing private key: %w", err)
	}
	h.key = key

	h.logger.Info("httpsig middleware provisioned",
		zap.String("key_id", h.KeyID),
		zap.Strings("covered_components", h.CoveredComponents),
	)

	return nil
}

// Validate ensures the configuration is valid.
func (h *HTTPSig) Validate() error {
	if h.key == nil {
		return fmt.Errorf("httpsig: no signing key loaded")
	}
	return nil
}

// ServeHTTP signs the response after the next handler has written it.
func (h *HTTPSig) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := new(bytes.Buffer)
	rec := caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		return true // always buffer
	})

	err := next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}

	status := rec.Status()
	header := rec.Header()

	created := time.Now().Unix()

	sigBase, sigParams, err := h.buildSignatureBase(status, header, r, created)
	if err != nil {
		h.logger.Error("httpsig: building signature base", zap.Error(err))
		rec.WriteResponse()
		return nil
	}

	digest := sha256.Sum256([]byte(sigBase))
	sigBytes, err := ecdsa.SignASN1(rand.Reader, h.key, digest[:])
	if err != nil {
		h.logger.Error("httpsig: signing", zap.Error(err))
		rec.WriteResponse()
		return nil
	}

	sigEncoded := base64.StdEncoding.EncodeToString(sigBytes)

	header.Set("Signature-Input", fmt.Sprintf("%s=%s", h.SignatureName, sigParams))
	header.Set("Signature", fmt.Sprintf("%s=:%s:", h.SignatureName, sigEncoded))

	rec.WriteResponse()
	return nil
}

// buildSignatureBase constructs the RFC 9421 signature base string
// and the @signature-params value.
func (h *HTTPSig) buildSignatureBase(status int, header http.Header, r *http.Request, created int64) (string, string, error) {
	var lines []string

	for _, component := range h.CoveredComponents {
		val, err := h.resolveComponent(component, status, header, r)
		if err != nil {
			return "", "", err
		}
		lines = append(lines, fmt.Sprintf("%q: %s", strings.ToLower(component), val))
	}

	// Build the inner list of covered components for @signature-params.
	var parts []string
	for _, c := range h.CoveredComponents {
		parts = append(parts, fmt.Sprintf("%q", strings.ToLower(c)))
	}
	sigParams := fmt.Sprintf("(%s);created=%d;keyid=%q;alg=%q",
		strings.Join(parts, " "), created, h.KeyID, "ecdsa-p256-sha256")
	if h.ATURI != "" {
		sigParams += fmt.Sprintf(";tag=%q", h.ATURI)
	}

	lines = append(lines, fmt.Sprintf("%q: %s", "@signature-params", sigParams))

	return strings.Join(lines, "\n"), sigParams, nil
}

// resolveComponent returns the value for a covered component.
func (h *HTTPSig) resolveComponent(name string, status int, header http.Header, r *http.Request) (string, error) {
	switch strings.ToLower(name) {
	case "@status":
		return fmt.Sprintf("%d", status), nil
	case "@method":
		return r.Method, nil
	case "@path":
		return r.URL.Path, nil
	case "@authority":
		return r.Host, nil
	default:
		// Treat as a header field name.
		canonical := http.CanonicalHeaderKey(name)
		vals := header.Values(canonical)
		if len(vals) == 0 {
			return "", fmt.Errorf("header %q not present in response", name)
		}
		return strings.Join(vals, ", "), nil
	}
}

// parseECDSAPrivateKey parses a PEM-encoded ECDSA private key.
// Supports both EC PRIVATE KEY (SEC 1) and PRIVATE KEY (PKCS#8) formats.
func parseECDSAPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not ECDSA")
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// parseCaddyfile sets up the handler from Caddyfile tokens.
//
// Syntax:
//
//	httpsig {
//	    key_file <path>
//	    key_env <env_var_name>
//	    key_id <id>
//	    covered <component1> [<component2> ...]
//	    signature_name <name>
//	    at_uri <at-uri>
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var hs HTTPSig
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "key_file":
				if !h.Args(&hs.KeyFile) {
					return nil, h.ArgErr()
				}
			case "key_env":
				if !h.Args(&hs.KeyEnv) {
					return nil, h.ArgErr()
				}
			case "key_id":
				if !h.Args(&hs.KeyID) {
					return nil, h.ArgErr()
				}
			case "covered":
				hs.CoveredComponents = h.RemainingArgs()
				if len(hs.CoveredComponents) == 0 {
					return nil, h.Err("covered requires at least one component")
				}
			case "signature_name":
				if !h.Args(&hs.SignatureName) {
					return nil, h.ArgErr()
				}
			case "at_uri":
				if !h.Args(&hs.ATURI) {
					return nil, h.ArgErr()
				}
			default:
				return nil, h.Errf("unrecognized option: %s", h.Val())
			}
		}
	}
	return &hs, nil
}

// Interface guards.
var (
	_ caddy.Module                = (*HTTPSig)(nil)
	_ caddy.Provisioner           = (*HTTPSig)(nil)
	_ caddy.Validator             = (*HTTPSig)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPSig)(nil)
)
