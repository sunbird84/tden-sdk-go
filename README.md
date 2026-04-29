# tden-sdk-go

> Status: **Phase A2.6** — OIDC client + scenepkg read + webhook verifier shipping. Phase B adds JWKS-verified id_token check.

Go SDK for "Sign in with TDEN". Same surface as `@tden/sdk` (JS), shipped as a separate package for backend engineers who don't want to bridge to Node.

## Install

```bash
go get github.com/sunbird84/tden-sdk-go
```

## Quick start (net/http example)

```go
package main

import (
	"net/http"
	"os"

	"github.com/sunbird84/tden-sdk-go"
)

func main() {
	c, err := tden.NewClient(tden.ClientOptions{
		ClientID:     "your_scene_package_id",
		ClientSecret: os.Getenv("TDEN_CLIENT_SECRET"),
		RedirectURI:  "https://your-app.example.com/auth/tden/callback",
	})
	if err != nil { panic(err) }

	http.HandleFunc("/auth/tden/login", func(w http.ResponseWriter, r *http.Request) {
		auth, err := c.AuthorizeURL(r.Context(), tden.AuthorizeOptions{
			Scope: "openid your_scene_package_id",
		})
		if err != nil { http.Error(w, err.Error(), 500); return }
		// ... store auth.Verifier + auth.State + auth.Nonce in your session ...
		http.Redirect(w, r, auth.URL, http.StatusFound)
	})

	http.HandleFunc("/auth/tden/callback", func(w http.ResponseWriter, r *http.Request) {
		// ... fetch verifier/state/nonce from session ...
		tokens, err := c.ExchangeCode(r.Context(), tden.ExchangeCodeOptions{
			Code:     r.URL.Query().Get("code"),
			Verifier: sessionVerifier,
		})
		if err != nil { http.Error(w, err.Error(), 500); return }
		user, err := c.UserInfo(r.Context(), tokens.AccessToken)
		if err != nil { http.Error(w, err.Error(), 500); return }
		_ = user.DID
		_ = user.IsRealNameVerified
		// ...
	})

	http.ListenAndServe(":3000", nil)
}
```

## Webhook verifier

```go
http.HandleFunc("/webhooks/tden", func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	event, err := tden.VerifyWebhook(body, r.Header.Get("X-TDEN-Signature"), os.Getenv("TDEN_WEBHOOK_SECRET"))
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	// event.Event ∈ {consent.granted, consent.revoked, consent.expired, package.revoked}
	// event.GrantID, event.PackageID, event.UserDID, event.Timestamp, event.Reason
	w.WriteHeader(http.StatusNoContent)
})
```

## API surface

| Type / func | Stability |
|---|---|
| `NewClient(ClientOptions)` | Stable |
| `Client.AuthorizeURL(ctx, AuthorizeOptions)` | Stable |
| `Client.ExchangeCode(ctx, ExchangeCodeOptions)` | Stable |
| `Client.UserInfo(ctx, accessToken)` | Stable |
| `Client.Discovery(ctx)` | Stable; cached |
| `DecodeIDToken(idToken)` | Stable; **does NOT verify signature** — Phase B adds verified path |
| `NewScenePackages(gatewayURL)` | Stable |
| `ScenePackages.ListApproved(ctx)` / `Get(ctx, id)` | Stable |
| `VerifyWebhook(body, sigHeader, secret)` | Stable |

## Phase B roadmap

- `Client.VerifyIDToken(ctx, idToken)` — JWKS fetch + Ed25519 verify + claims validation
- `Client.RevokeConsent(ctx, grantID)` — for users-not-RPs flows
- ZK-proof helpers for credential-disclosure flows

## License

AGPL-3.0.
