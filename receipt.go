// receipt.go — Access Receipt verifier (Phase A2.7+).
//
// 创意特性 / Innovation:
// 每次第三方查询用户数据,gateway 给用户的访问日志加 Ed25519 签名。
// 用户(或第三方审计)用此 helper + gateway JWKS 独立验证 — 这是
// TDEN 的"用户主权"证据机制。
//
// Innovation: gateway signs every DataAccessLog with its OIDC Ed25519 key.
// Users / auditors verify here. Confirms (a) log not tampered, (b) signature
// is gateway's, (c) gaps in receipts are detectable.

package tden

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AccessReceipt 是 gateway /api/me/access-receipts 返回的单条记录。
// AccessReceipt is a single entry from gateway /api/me/access-receipts.
type AccessReceipt struct {
	Log struct {
		LogID         string   `json:"log_id"`
		AuthID        string   `json:"auth_id"`
		PackageID     string   `json:"package_id"`
		PackageName   string   `json:"package_name"`
		DeveloperUID  string   `json:"developer_uid"`
		UserUID       string   `json:"user_uid"`
		FieldsAccessed []string `json:"fields_accessed"`
		AccessType    string   `json:"access_type"`
		RemoteIP      string   `json:"remote_ip"`
		AccessedAt    int64    `json:"accessed_at"`
	} `json:"log"`
	CanonicalJSON string `json:"canonical_json"`
	SignatureB64  string `json:"signature_b64"`
	Kid           string `json:"kid"`
	Algorithm     string `json:"alg"`
	JwksURL       string `json:"jwks_url"`
}

// JWK / JWKS — minimal subset for Ed25519 keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// FetchJWKS 从指定 URL 拉 JWKS(常见:gateway.tden.network/oauth/jwks)。
// FetchJWKS pulls the JWKS document from the gateway.
func FetchJWKS(ctx context.Context, url string) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}
	return &jwks, nil
}

// VerifyAccessReceipt 验证一条访问回执;返回 nil 表示通过,error 表示失败原因。
// VerifyAccessReceipt verifies one receipt; returns nil on success.
func VerifyAccessReceipt(receipt *AccessReceipt, jwks *JWKS) error {
	if receipt.Algorithm != "EdDSA" {
		return fmt.Errorf("unsupported alg: %s", receipt.Algorithm)
	}
	var jwk *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == receipt.Kid {
			jwk = &jwks.Keys[i]
			break
		}
	}
	if jwk == nil {
		return fmt.Errorf("key id %s not in JWKS", receipt.Kid)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		return fmt.Errorf("JWK is not an Ed25519 OKP key (kty=%s crv=%s)", jwk.Kty, jwk.Crv)
	}
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.X, "="))
	if err != nil {
		return fmt.Errorf("decode x: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key wrong length: %d", len(pub))
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(receipt.SignatureB64, "="))
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature wrong length: %d", len(sig))
	}
	digest := sha256.Sum256([]byte(receipt.CanonicalJSON))
	if !ed25519.Verify(pub, digest[:], sig) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// FindReceiptGaps 返回时间间隔超过 gapSeconds 的相邻 receipt 索引列表 —
// 帮用户对账"网关有没有静默藏掉一次访问"。
//
// FindReceiptGaps returns indices of receipt pairs separated by more than
// gapSeconds — heuristic for "did the gateway silently drop one?".
func FindReceiptGaps(receipts []AccessReceipt, gapSeconds int64) []int {
	out := []int{}
	for i := 1; i < len(receipts); i++ {
		if receipts[i].Log.AccessedAt-receipts[i-1].Log.AccessedAt > gapSeconds {
			out = append(out, i)
		}
	}
	return out
}
