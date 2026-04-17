package httpsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	return key, pemData
}

func TestParseECDSAPrivateKey_SEC1(t *testing.T) {
	_, pemData := generateTestKey(t)
	key, err := parseECDSAPrivateKey(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve")
	}
}

func TestParseECDSAPrivateKey_PKCS8(t *testing.T) {
	origKey, _ := generateTestKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(origKey)
	if err != nil {
		t.Fatalf("marshaling PKCS8: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	key, err := parseECDSAPrivateKey(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve")
	}
}

func TestParseECDSAPrivateKey_Invalid(t *testing.T) {
	_, err := parseECDSAPrivateKey([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestServeHTTP_SignsResponse(t *testing.T) {
	key, _ := generateTestKey(t)

	h := &HTTPSig{
		key:               key,
		KeyID:             "test-key",
		SignatureName:     "sig",
		CoveredComponents: []string{"@status", "content-type"},
	}

	inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hello":"world"}`))
		return nil
	})

	req := httptest.NewRequest("GET", "http://example.com/.well-known/did.json", nil)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, inner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()

	sigInput := resp.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("missing Signature-Input header")
	}
	if !strings.HasPrefix(sigInput, "sig=") {
		t.Fatalf("Signature-Input should start with 'sig=', got: %s", sigInput)
	}
	if !strings.Contains(sigInput, `alg="ecdsa-p256-sha256"`) {
		t.Fatalf("Signature-Input should contain algorithm, got: %s", sigInput)
	}
	if !strings.Contains(sigInput, `keyid="test-key"`) {
		t.Fatalf("Signature-Input should contain keyid, got: %s", sigInput)
	}

	sig := resp.Header.Get("Signature")
	if sig == "" {
		t.Fatal("missing Signature header")
	}
	if !strings.HasPrefix(sig, "sig=:") {
		t.Fatalf("Signature should start with 'sig=:', got: %s", sig)
	}
	if !strings.HasSuffix(sig, ":") {
		t.Fatalf("Signature should end with ':', got: %s", sig)
	}
}

func TestServeHTTP_SignatureVerifies(t *testing.T) {
	key, _ := generateTestKey(t)

	h := &HTTPSig{
		key:               key,
		KeyID:             "test-key",
		SignatureName:     "sig",
		CoveredComponents: []string{"@status", "content-type"},
	}

	inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hello":"world"}`))
		return nil
	})

	req := httptest.NewRequest("GET", "http://example.com/.well-known/did.json", nil)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, inner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()

	// Extract signature value.
	sigHeader := resp.Header.Get("Signature")
	// Format: sig=:<base64>:
	sigB64 := strings.TrimPrefix(sigHeader, "sig=:")
	sigB64 = strings.TrimSuffix(sigB64, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}

	// Extract signature params to reconstruct the base.
	sigInput := resp.Header.Get("Signature-Input")
	sigParams := strings.TrimPrefix(sigInput, "sig=")

	// Reconstruct signature base.
	lines := []string{
		`"@status": 200`,
		`"content-type": application/json`,
	}
	lines = append(lines, `"@signature-params": `+sigParams)
	sigBase := strings.Join(lines, "\n")

	digest := sha256.Sum256([]byte(sigBase))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sigBytes) {
		t.Fatal("signature verification failed")
	}
}

func TestBuildSignatureBase(t *testing.T) {
	key, _ := generateTestKey(t)

	h := &HTTPSig{
		key:               key,
		KeyID:             "test-key",
		SignatureName:     "sig",
		CoveredComponents: []string{"@status", "content-type"},
	}

	header := http.Header{}
	header.Set("Content-Type", "application/json")

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	base, params, err := h.buildSignatureBase(200, header, req, 1700000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(base, `"@status": 200`) {
		t.Errorf("base should contain @status line, got:\n%s", base)
	}
	if !strings.Contains(base, `"content-type": application/json`) {
		t.Errorf("base should contain content-type line, got:\n%s", base)
	}
	if !strings.Contains(base, `"@signature-params":`) {
		t.Errorf("base should contain @signature-params line, got:\n%s", base)
	}
	if !strings.Contains(params, "created=1700000000") {
		t.Errorf("params should contain created timestamp, got: %s", params)
	}
}

func TestBuildSignatureBase_WithATURI(t *testing.T) {
	key, _ := generateTestKey(t)

	atURI := "at://did:plc:abc/app.bsky.feed.post/rkey"
	h := &HTTPSig{
		key:               key,
		KeyID:             "test-key",
		SignatureName:     "sig",
		CoveredComponents: []string{"@status", "content-type"},
		ATURI:             atURI,
	}

	header := http.Header{}
	header.Set("Content-Type", "application/json")

	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	base, params, err := h.buildSignatureBase(200, header, req, 1700000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := `tag="` + atURI + `"`
	if !strings.Contains(params, want) {
		t.Errorf("params should contain %s, got: %s", want, params)
	}
	if !strings.Contains(base, want) {
		t.Errorf("signature base should contain %s in @signature-params, got:\n%s", want, base)
	}
}

func TestServeHTTP_SignatureVerifiesWithATURI(t *testing.T) {
	key, _ := generateTestKey(t)

	atURI := "at://did:plc:abc/app.bsky.feed.post/rkey"
	h := &HTTPSig{
		key:               key,
		KeyID:             "test-key",
		SignatureName:     "sig",
		CoveredComponents: []string{"@status", "content-type"},
		ATURI:             atURI,
	}

	inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hello":"world"}`))
		return nil
	})

	req := httptest.NewRequest("GET", "http://example.com/.well-known/did.json", nil)
	rec := httptest.NewRecorder()

	if err := h.ServeHTTP(rec, req, inner); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()

	sigInput := resp.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, `tag="`+atURI+`"`) {
		t.Fatalf("Signature-Input should contain tag param, got: %s", sigInput)
	}

	sigHeader := resp.Header.Get("Signature")
	sigB64 := strings.TrimPrefix(sigHeader, "sig=:")
	sigB64 = strings.TrimSuffix(sigB64, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}

	sigParams := strings.TrimPrefix(sigInput, "sig=")

	lines := []string{
		`"@status": 200`,
		`"content-type": application/json`,
		`"@signature-params": ` + sigParams,
	}
	sigBase := strings.Join(lines, "\n")

	digest := sha256.Sum256([]byte(sigBase))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sigBytes) {
		t.Fatal("signature verification failed")
	}
}

func TestResolveComponent_RequestDerived(t *testing.T) {
	key, _ := generateTestKey(t)
	h := &HTTPSig{key: key}

	header := http.Header{}
	req := httptest.NewRequest("POST", "http://example.com/api/v1", nil)

	val, err := h.resolveComponent("@method", 200, header, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "POST" {
		t.Errorf("expected POST, got %s", val)
	}

	val, err = h.resolveComponent("@path", 200, header, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "/api/v1" {
		t.Errorf("expected /api/v1, got %s", val)
	}

	val, err = h.resolveComponent("@authority", 200, header, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "example.com" {
		t.Errorf("expected example.com, got %s", val)
	}
}

func TestResolveComponent_MissingHeader(t *testing.T) {
	key, _ := generateTestKey(t)
	h := &HTTPSig{key: key}

	header := http.Header{}
	req := httptest.NewRequest("GET", "http://example.com/", nil)

	_, err := h.resolveComponent("x-missing", 200, header, req)
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}
