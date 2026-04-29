// Package tden provides a Go SDK for "Sign in with TDEN" (OIDC IdP) plus
// scene-package read helpers and webhook signature verification.
//
// 用法 / Usage(net/http 例子):
//
//	c, err := tden.NewClient(tden.ClientOptions{
//	    ClientID:     "your_scene_package_id",
//	    ClientSecret: os.Getenv("TDEN_CLIENT_SECRET"),
//	    RedirectURI:  "https://your-app.example.com/auth/tden/callback",
//	})
//
//	http.HandleFunc("/auth/tden/login", func(w http.ResponseWriter, r *http.Request) {
//	    auth, _ := c.AuthorizeURL(r.Context(), tden.AuthorizeOptions{
//	        Scope: "openid your_scene_package_id",
//	    })
//	    // store auth.Verifier + auth.State + auth.Nonce in session, redirect to auth.URL
//	    http.Redirect(w, r, auth.URL, http.StatusFound)
//	})
//
// Phase A2.6:OIDC code 流 + scenepkg 读 + webhook 验签 已经稳定。
//             Phase B 加 JWKS-verified id_token 校验 + ZK proof helper。
//
// Status: Phase A2.6. OIDC code flow + scenepkg read + webhook verification
// stable. Phase B: JWKS-verified id_token + ZK proof helpers.

package tden

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── Public types ─────────────────────────────────────────────────────────────

// ClientOptions configures a TDEN OIDC client.
type ClientOptions struct {
	ClientID     string
	ClientSecret string // optional; omit for PKCE-only public clients
	RedirectURI  string

	// Issuer overrides the default https://gateway.tden.network.
	Issuer string

	// HTTPClient overrides the default; useful for proxy / test injection.
	HTTPClient *http.Client
}

// Client is the high-level OIDC + scenepkg client.
type Client struct {
	opts ClientOptions

	mu        sync.RWMutex
	discovery *DiscoveryDoc
}

// DiscoveryDoc mirrors gateway's /.well-known/openid-configuration.
type DiscoveryDoc struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	IDTokenSigningAlg      []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods   []string `json:"code_challenge_methods_supported"`
}

// AuthorizeOptions controls /authorize URL building.
type AuthorizeOptions struct {
	Scope string  // e.g. "openid tden_demo_basic_v1"
	State string  // CSRF; auto-generated if empty
	Nonce string  // OIDC replay defense; auto-generated if empty
}

// AuthorizeResult holds the redirect URL and the values RP must persist
// in their session for the callback handler.
type AuthorizeResult struct {
	URL      string
	Verifier string // PKCE verifier — pass to ExchangeCode
	State    string
	Nonce    string
}

// TokenResponse is the /oauth/token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// IDTokenClaims models the OIDC id_token payload.
type IDTokenClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"` // user DID
	Aud   string `json:"aud"` // your client_id
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce,omitempty"`

	DID                  string   `json:"did,omitempty"`
	IsRealNameVerified   bool     `json:"is_real_name_verified,omitempty"`
	ReputationScore      *float64 `json:"reputation_score,omitempty"`
	RealName             string   `json:"real_name,omitempty"`
	WalletAddress        string   `json:"wallet_address,omitempty"`
	ScenePackageID       string   `json:"tden:scene_package_id,omitempty"`
	ScenePackageVersion  string   `json:"tden:scene_package_version,omitempty"`
	GrantedFields        []string `json:"tden:granted_fields,omitempty"`
	AuthMethods          []string `json:"tden:auth_methods,omitempty"`
	AuthStrength         string   `json:"tden:auth_strength,omitempty"`
}

// UserInfo aliases IDTokenClaims — gateway returns the same shape for /userinfo.
type UserInfo = IDTokenClaims

// ── Construction ─────────────────────────────────────────────────────────────

// NewClient validates options and returns a ready-to-use client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.ClientID == "" {
		return nil, fmt.Errorf("tden: ClientID required")
	}
	if opts.RedirectURI == "" {
		return nil, fmt.Errorf("tden: RedirectURI required")
	}
	if opts.Issuer == "" {
		opts.Issuer = "https://gateway.tden.network"
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{opts: opts}, nil
}

// Discovery returns the cached discovery document, fetching once on first call.
func (c *Client) Discovery(ctx context.Context) (*DiscoveryDoc, error) {
	c.mu.RLock()
	if c.discovery != nil {
		d := c.discovery
		c.mu.RUnlock()
		return d, nil
	}
	c.mu.RUnlock()

	url := strings.TrimRight(c.opts.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tden: discovery HTTP %d", resp.StatusCode)
	}
	var doc DiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("tden: discovery decode: %w", err)
	}

	c.mu.Lock()
	c.discovery = &doc
	c.mu.Unlock()
	return &doc, nil
}

// ── Authorize URL ────────────────────────────────────────────────────────────

// AuthorizeURL builds the /authorize URL + PKCE verifier + state/nonce.
func (c *Client) AuthorizeURL(ctx context.Context, o AuthorizeOptions) (*AuthorizeResult, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, err
	}

	state := o.State
	if state == "" {
		state, err = randomToken()
		if err != nil {
			return nil, err
		}
	}
	nonce := o.Nonce
	if nonce == "" {
		nonce, err = randomToken()
		if err != nil {
			return nil, err
		}
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.opts.ClientID)
	q.Set("redirect_uri", c.opts.RedirectURI)
	q.Set("scope", o.Scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	return &AuthorizeResult{
		URL:      disc.AuthorizationEndpoint + "?" + q.Encode(),
		Verifier: verifier,
		State:    state,
		Nonce:    nonce,
	}, nil
}

// ── Token exchange ───────────────────────────────────────────────────────────

// ExchangeCodeOptions is the input to ExchangeCode.
type ExchangeCodeOptions struct {
	Code     string
	Verifier string // PKCE verifier from AuthorizeURL
}

// ExchangeCode redeems the auth code for ID + access tokens.
func (c *Client) ExchangeCode(ctx context.Context, o ExchangeCodeOptions) (*TokenResponse, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	body := url.Values{}
	body.Set("grant_type", "authorization_code")
	body.Set("code", o.Code)
	body.Set("redirect_uri", c.opts.RedirectURI)
	body.Set("client_id", c.opts.ClientID)
	body.Set("code_verifier", o.Verifier)
	if c.opts.ClientSecret != "" {
		body.Set("client_secret", c.opts.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tden: token HTTP %d — %s", resp.StatusCode, string(raw))
	}
	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("tden: token decode: %w", err)
	}
	return &tr, nil
}

// ── ID token decode (UNVERIFIED) ─────────────────────────────────────────────

// DecodeIDToken parses an id_token's payload WITHOUT verifying the signature.
// Phase B: VerifyIDToken with JWKS fetch + Ed25519 verify.
func DecodeIDToken(idToken string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("tden: id_token: not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("tden: id_token base64: %w", err)
	}
	var c IDTokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("tden: id_token JSON: %w", err)
	}
	return &c, nil
}

// ── /userinfo ────────────────────────────────────────────────────────────────

// UserInfo fetches the merged user attribute view via /oauth/userinfo.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	disc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tden: userinfo HTTP %d — %s", resp.StatusCode, string(raw))
	}
	var u UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("tden: userinfo decode: %w", err)
	}
	return &u, nil
}

// ── PKCE / random helpers (internal) ─────────────────────────────────────────

func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 64)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)[:64]
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
