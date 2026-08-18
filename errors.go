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

// StepUpRequiredError: POST /api/v1/oauth/token/ returned {"error": "step_up_required", ...}
// (README.md ADR-076, backend repo) — credentials/code were valid, but the platform's
// device/location trust gate rejected this specific login (password or Google) as coming from
// an unrecognized device/location. NOT a fatal error: ExchangeCode returns this distinctly from
// *TokenExchangeError so the caller (CallbackHandler) can redirect the browser to complete
// step-up (magic link/email code/passkey) rather than showing a hard failure — the same
// automatic-redirect behavior the platform's own first-party dashboard uses for this identical
// error.
type StepUpRequiredError struct {
	ErrorDescription string
}

func (e *StepUpRequiredError) Error() string { return e.ErrorDescription }

// OrganizationNotFoundError: GET /api/v1/organizations/{orgSlug}/public-applications/ returned
// a non-2xx response — no Organization matches that slug, or it isn't usable (deactivated/
// deleted). Carries the real error description from the backend rather than a generic message.
type OrganizationNotFoundError struct {
	ErrorDescription string
}

func (e *OrganizationNotFoundError) Error() string { return e.ErrorDescription }

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
