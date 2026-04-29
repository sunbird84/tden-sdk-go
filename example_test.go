// Smoke test ensuring the SDK at least compiles + the helpers don't panic.
// Real integration tests live in Phase B (need a running test gateway).
package tden

import (
	"context"
	"strings"
	"testing"
)

func TestNewClient_RequiresClientID(t *testing.T) {
	if _, err := NewClient(ClientOptions{RedirectURI: "https://example.com/cb"}); err == nil {
		t.Error("expected error when ClientID missing")
	}
}

func TestNewClient_RequiresRedirectURI(t *testing.T) {
	if _, err := NewClient(ClientOptions{ClientID: "test"}); err == nil {
		t.Error("expected error when RedirectURI missing")
	}
}

func TestPKCE_Lengths(t *testing.T) {
	v, c, err := generatePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 64 {
		t.Errorf("verifier len: %d != 64", len(v))
	}
	if c == "" {
		t.Error("challenge empty")
	}
}

func TestVerifyWebhook_RejectsBadSignature(t *testing.T) {
	body := []byte(`{"event":"consent.revoked","package_id":"x","timestamp":1}`)
	if _, err := VerifyWebhook(body, "sha256=deadbeef", "secret"); err == nil {
		t.Error("expected verify to fail with bad signature")
	}
	if _, err := VerifyWebhook(body, "", "secret"); err == nil {
		t.Error("expected verify to fail with empty header")
	}
}

func TestDecodeIDToken_MalformedRejected(t *testing.T) {
	if _, err := DecodeIDToken("not-a-jwt"); err == nil {
		t.Error("expected error on malformed token")
	}
}

func TestAuthorizeURL_WithoutNetwork(t *testing.T) {
	// Build a client and ensure AuthorizeURL fails fast when discovery is unreachable
	// (rather than panicking). We can't actually fetch in unit tests; just exercise
	// the path that an empty issuer + no http client doesn't crash construction.
	c, err := NewClient(ClientOptions{
		ClientID:    "test",
		RedirectURI: "https://example.com/cb",
		Issuer:      "http://127.0.0.1:1", // unreachable port
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AuthorizeURL(context.Background(), AuthorizeOptions{Scope: "openid test"})
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("expected discovery dial error, got: %v", err)
	}
}
