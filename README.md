# onehux-sso-go

A real, installable Go SDK wrapping OneHux Accounts' Authorization Code + PKCE flow against its
real hosted login page — the same shape and behavior as this project's Django/Node.js/Laravel
SDKs, adapted to Go's standard library rather than any one framework (Go has no single dominant
web/session framework the way those three languages do).

Two layers, in one package:

- `OneHuxClient` — the framework-agnostic client (PKCE, token exchange, `/userinfo`, logout URL,
  OIDC Back-Channel Logout verification). No dependency on `net/http` handler wiring at all —
  usable from any Go web framework or a plain script.
- `Handlers` — real, runnable `net/http.HandlerFunc`s wiring `OneHuxClient` to a `SessionStore`
  (an interface this package defines, with one working `MemorySessionStore` implementation
  shipped). Only use this if you want the five ready-made routes; wire `OneHuxClient` directly
  otherwise.

Zero non-stdlib dependencies.

## Install

```bash
go get github.com/onehux/onehux-sso-go
```

(Not yet published to a public module proxy — until that's decided, add a `replace` directive
in your own `go.mod` pointing at a local path or this repo directly.)

## Two hosts — don't mix them up

`accounts.onehux.com` serves the hosted login/logout pages a browser is redirected to.
`api-accounts.onehux.com` serves the actual OAuth API your backend calls server-to-server. This
package keeps them as two separate options (`LoginBaseURL` / `APIBaseURL`) precisely because
collapsing them into one host was a real, confirmed bug in the original integration guides (see
the backend repo's `README.md`, ADR-070) — the wrong host doesn't error loudly, it silently
404s.

## Setup — using Handlers

1. Register a real confidential-client `Application` in your OneHux Accounts Organization
   (Dashboard → Applications), with a `redirect_uri` pointing at wherever you mount this
   package's `/callback` route, **and** your `post_logout_redirect_uri` registered in that same
   list — OneHux Accounts validates both against the one `redirect_uris` list, not two separate
   ones.

2. Wire it up:

   ```go
   package main

   import (
       "log"
       "net/http"
       "os"

       onehuxsso "github.com/onehux/onehux-sso-go"
   )

   func main() {
       client := onehuxsso.NewClient(onehuxsso.ClientOptions{
           ClientID:              os.Getenv("ONEHUX_CLIENT_ID"),
           ClientSecret:          os.Getenv("ONEHUX_CLIENT_SECRET"),
           RedirectURI:           "https://yourapp.example.com/auth/callback",
           PostLogoutRedirectURI: "https://yourapp.example.com/auth/logged-out",
           // LoginBaseURL / APIBaseURL / Scope all have real production defaults.
       })

       store := onehuxsso.NewMemorySessionStore(true) // true: Secure cookie flag (HTTPS)
       handlers := onehuxsso.NewHandlers(onehuxsso.HandlersOptions{
           Client: client,
           Store:  store,
       })

       mux := http.NewServeMux()
       handlers.Mount(mux, "/auth")
       log.Fatal(http.ListenAndServe(":8080", mux))
   }
   ```

   This gives you five real, working routes: `/auth/login`, `/auth/callback`, `/auth/logout`,
   `/auth/userinfo` (a ready-to-use JSON endpoint your own frontend can call with credentials
   included, matching the BFF pattern documented for the web-frontend integration guide — your
   frontend never talks to OneHux directly), and `/auth/backchannel-logout` (only does anything
   once you configure it — see "Logging out" below).

`MemorySessionStore` is a real, working implementation — correct for a single-process
deployment. A multi-process production deployment should supply its own `SessionStore`
implementation (the interface is four methods) backed by shared storage (Redis, a database,
...).

## Using the client directly (any framework, or a custom flow)

```go
client := onehuxsso.NewClient(onehuxsso.ClientOptions{ /* ...same options as above... */ })

pending, err := client.StartAuthorization()
// stash pending.State / pending.CodeVerifier in your own session, then redirect the browser
// to pending.AuthorizationURL

tokens, err := client.ExchangeCode(code, state, session["onehux_sso_state"], session["onehux_sso_pkce_verifier"])

claims, err := client.GetUserinfo(tokens.AccessToken)

logoutURL := client.BuildLogoutURL("")
```

## Public application launcher

`GET /api/v1/organizations/{orgSlug}/public-applications/` is a real, public, unauthenticated
platform endpoint — no `ClientID`/`ClientSecret` involved, usable for any Organization by its own
slug, not just your own configured one. It returns only `Name`/`LogoURL`/`HomeURL` for
Applications that Organization has opted into public listing — a pure "what can I launch" list,
never a way to start a sign-in flow.

```go
apps, err := client.GetPublicApplications("onehux")
// [{Name: "ODS", LogoURL: "https://...", HomeURL: "https://..."}]
```

Rendering is entirely up to you — this package ships the data method only, no UI component (Go
has no standard templating/UI convention to build one against). A plain, unstyled illustration
(adapt this to your own design, don't copy it as-is):

```gotemplate
{{range .Applications}}
  <a href="{{.HomeURL}}"><img src="{{.LogoURL}}" alt="{{.Name}}">{{.Name}}</a>
{{end}}
```

## Logging out — what the user actually sees

There are two different triggers, and — once you wire up back-channel logout (below) — they
produce the same fast, correct result. Understanding both is still worth it, since the second
one only becomes immediate if you actually complete the setup:

**1. The user clicks "Log out" inside your app (SP-initiated).** `Handlers.LogoutHandler`
(`/auth/logout`) clears its local session *and* redirects through `/end-session` in the same
action, which ends the real, shared platform session immediately. From the user's point of
view: they click Log out, land on your app's own logged-out page, and if they then open the
dashboard or any other app, they're asked to log in again — everywhere, right away. This works
cleanly because your own app is the one driving both halves of the logout at once, with no
dependency on back-channel logout at all.

**2. The user logs out somewhere else — a different app, or directly at
`accounts.onehux.com`/the dashboard (IdP-initiated).** The shared platform session is revoked
immediately and correctly on the backend — same underlying revocation call as case 1. Whether
*your app* finds out immediately depends entirely on whether you've completed the back-channel
logout setup below:

- **With it wired up:** OneHux POSTs a signed `logout_token` to your `/auth/backchannel-logout`
  route the instant the session is revoked. This package verifies it and destroys the matching
  local session server-side. From the user's point of view: functionally identical to case 1 —
  if they reload or navigate, they're asked to log in again right away, even though they never
  touched this app's own logout button.
- **Without it:** your app has no way to find out proactively. It'll keep showing the user as
  signed in — its own local session cookie hasn't changed — right up until the moment it makes
  its next real call to `/userinfo`, which returns a real `TokenExpiredError`. In the worst
  realistic case, that's **up to 15 minutes** of stale "signed in" UI, bounded by the access
  token's own lifetime. This is not a security hole — no protected data actually leaks, since
  the real API call starts failing the moment it's tried — but the *displayed* state can look
  stale for that window.

**To wire up back-channel logout:**

1. Pass `BackchannelLogoutSigningSecret` in `HandlersOptions` — this enables the
   `POST /auth/backchannel-logout` route (mounted automatically alongside the other four).
2. Register that exact URL with OneHux:
   ```
   PATCH /api/v1/applications/{id}/backchannel-logout/
   { "backchannel_logout_uri": "https://yourapp.example.com/auth/backchannel-logout" }
   ```
   The response includes `backchannel_logout_secret` **exactly once** — this is a dedicated
   signing secret, deliberately **not** your `ClientSecret` (the backend stores that only as a
   one-way hash and can never read it back to sign anything with it). Use that value as
   `BackchannelLogoutSigningSecret`.
3. If you run more than one process (a real production deployment almost certainly does), also
   supply a `SidIndex` implementation backed by shared storage (Redis, etc.) via
   `HandlersOptions.SidIndex` — the default `MemorySidIndex` only works within a single
   process, since the process that receives the `logout_token` POST may not be the same one
   that handled the original login.

If you're using `OneHuxClient` directly (no `Handlers`), call `client.VerifyLogoutToken(logoutToken,
signingSecret)` yourself from wherever your framework routes the POST, then locate and destroy
the matching local session using the returned payload's `SID`.

Spec: [openid-connect-backchannel-1_0](https://openid.net/specs/openid-connect-backchannel-1_0.html).

## No refresh token today — this is real, not a bug

OneHux Accounts access tokens are a 15-minute, single-issue lifetime. This platform does not
currently issue a refresh token. `client.GetUserinfo()` returns a `*TokenExpiredError` when the
token has expired or been revoked — check for it (`errors.As`) and send the user back through
`client.StartAuthorization()` for a fresh login. There is no silent-refresh path to fall back
to; this package makes that explicit rather than hiding it behind a generic error.

## Example project

See `example/` for a complete, runnable Go program using this module end-to-end — real sign-in,
real `/userinfo` claims, real RP-initiated logout, and real OIDC Back-Channel Logout, all
against production. It has its own `go.mod` with a `replace` directive pointing at this
package.

```bash
cd example
ONEHUX_CLIENT_ID=... ONEHUX_CLIENT_SECRET=... ONEHUX_BACKCHANNEL_LOGOUT_SIGNING_SECRET=... go run .
```

## Build

```bash
go build ./...
go vet ./...
```

## License

MIT — see `LICENSE`. (License choice not yet finalized for public distribution — see the
publish-readiness pass this repo's own tracking notes reference.)
