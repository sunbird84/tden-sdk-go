# tden-sdk-go

> 英文版:[README.md](README.md)

> 状态:**Phase A2.6** —— OIDC 客户端 + 场景包读取 + Webhook 校验已交付。Phase B 增加 JWKS 验证 id_token。

TDEN 的 Go SDK,用于"用 TDEN 登录"。表面与 `@tden/sdk`(JS)一致,作为独立包发布,方便后端工程师无需借道 Node。

## 安装

```bash
go get github.com/sunbird84/tden-sdk-go
```

## 快速开始(net/http 示例)

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

## Webhook 校验

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

## API 表面

| 类型 / 函数 | 稳定性 |
|---|---|
| `NewClient(ClientOptions)` | Stable |
| `Client.AuthorizeURL(ctx, AuthorizeOptions)` | Stable |
| `Client.ExchangeCode(ctx, ExchangeCodeOptions)` | Stable |
| `Client.UserInfo(ctx, accessToken)` | Stable |
| `Client.Discovery(ctx)` | Stable;带缓存 |
| `DecodeIDToken(idToken)` | Stable;**不验证签名** —— Phase B 增加验签路径 |
| `NewScenePackages(gatewayURL)` | Stable |
| `ScenePackages.ListApproved(ctx)` / `Get(ctx, id)` | Stable |
| `VerifyWebhook(body, sigHeader, secret)` | Stable |

## Phase B 路线图

- `Client.VerifyIDToken(ctx, idToken)` —— JWKS 拉取 + Ed25519 验签 + claims 校验
- `Client.RevokeConsent(ctx, grantID)` —— 用户(非 RP)流程使用
- 凭证披露流程的 ZK 证明 helper

## 许可证

AGPL-3.0。
