// errors.go
// Errors raised by the OneHux SSO client. Real backend error shapes (error/error_description)
// are preserved, not swallowed into a generic message — a caller that wants the raw OAuth
// error code can type-assert to *TokenExchangeError directly.
package onehuxsso

import "fmt"

// InvalidStateError: the callback's state parameter didn't match what was stashed at redirect
// time, or code/state was missing outright — a real CSRF-protection failure, or a stale/
// replayed callback URL.
type InvalidStateError struct {
	Message string
}

func (e *InvalidStateError) Error() string { return e.Message }

// TokenExchangeError: POST /api/v1/oauth/token/ returned a non-2xx response. Carries the real
// OAuth error/error_description from oauth.views._error_response() rather than a generic
// message, so a caller can distinguish e.g. invalid_grant (expired code) from invalid_client
// (misconfigured client_id/secret).
type TokenExchangeError struct {
	OAuthError       string
	ErrorDescription string
	StatusCode       int
}

func (e *TokenExchangeError) Error() string {
	return fmt.Sprintf("%s: %s", e.OAuthError, e.ErrorDescription)
}

// TokenExpiredError: GET /api/v1/oauth/userinfo/ rejected the access token.
//
// OneHux Accounts does not currently issue a refresh token (access tokens are a 15-minute,
// single-issue lifetime) — this is a real, permanent platform constraint, not a bug in this
// client. Callers must catch this and route the user back through
// OneHuxClient.StartAuthorization() for a fresh login; there is no silent-refresh path to fall
// back to.
type TokenExpiredError struct {
	Message string
}

func (e *TokenExpiredError) Error() string { return e.Message }

// InvalidLogoutTokenError: an incoming POST to the backchannel-logout handler failed real OIDC
// Back-Channel Logout validation (spec §2.6) — bad/missing signature, wrong aud, missing/
// malformed events claim, a present nonce claim (forbidden), an expired token, or a missing
// sub/sid. The handler turns this into the spec-required HTTP 400, never a 500 — a forged or
// malformed request on a public endpoint is expected adversarial input, not a server bug.
type InvalidLogoutTokenError struct {
	Message string
}

func (e *InvalidLogoutTokenError) Error() string { return e.Message }
