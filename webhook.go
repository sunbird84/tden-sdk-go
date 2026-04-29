// webhook.go — Webhook signature verification.
package tden

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// WebhookEvent is the payload TDEN gateway POSTs to package webhook_url.
type WebhookEvent struct {
	Event     string `json:"event"`     // consent.granted | consent.revoked | consent.expired | package.revoked
	GrantID   string `json:"grant_id,omitempty"`
	PackageID string `json:"package_id"`
	UserDID   string `json:"user_did,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Reason    string `json:"reason,omitempty"`
}

// VerifyWebhook validates the X-TDEN-Signature HMAC header against the body bytes
// using the per-package webhook secret (issued at approval time).
//
// Returns the parsed event on success. Use raw body bytes — DO NOT call
// json.Unmarshal before verifying, signature is over the original bytes.
//
// Phase A2.4 状态:gateway 端 webhook 投递还在路线图上,但 RP 可以提前接好 verifier,
// 投递上线立刻就有用。
//
// Phase A2.4: gateway-side webhook delivery is on roadmap; this verifier
// is ready ahead of time for forward-compat.
func VerifyWebhook(body []byte, signatureHeader, secret string) (*WebhookEvent, error) {
	if signatureHeader == "" {
		return nil, fmt.Errorf("tden webhook: missing X-TDEN-Signature header")
	}
	const prefix = "sha256="
	if !strings.HasPrefix(signatureHeader, prefix) {
		return nil, fmt.Errorf("tden webhook: signature header must start with %q", prefix)
	}
	expectedHex := strings.ToLower(strings.TrimPrefix(signatureHeader, prefix))
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return nil, fmt.Errorf("tden webhook: signature hex decode: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	actual := mac.Sum(nil)

	if !hmac.Equal(actual, expected) {
		return nil, fmt.Errorf("tden webhook: signature mismatch")
	}

	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, fmt.Errorf("tden webhook: JSON decode: %w", err)
	}
	return &event, nil
}
