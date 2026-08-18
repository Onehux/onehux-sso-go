// client.go
// OneHuxClient — PKCE generation, the hosted-login redirect, the authorization_code token
// exchange, /userinfo, and the RP-initiated /end-session redirect. Framework-agnostic: takes/
// returns plain strings and structs, no dependency on net/http handler wiring — handlers.go
// wires this to a real net/http-based SessionStore. Zero non-stdlib dependencies, matching the
// same minimal-footprint discipline as the Node.js SDK (this package's closest sibling).
//
// Two distinct hosts, by design (README.md ADR-070 in the backend repo, found by a real
// end-to-end manual walkthrough against production): the hosted login/logout pages live on
// LoginBaseURL, the actual OAuth API lives on the separate APIBaseURL. Mixing them up
// previously produced a silent 404 HTML body instead of a JSON error — this client never lets
// that ambiguity exist, since the two are separate struct fields, not one shared value.
package onehuxsso

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LogoutEventClaimKey is the fixed key OIDC Back-Channel Logout requires inside a
// logout_token's `events` claim (spec §2.4).
const LogoutEventClaimKey = "http://schemas.openid.net/event/backchannel-logout"

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ClientOptions configures a new OneHuxClient. LoginBaseURL/APIBaseURL/Scope default to this
// platform's own production hosts and OpenID's standard scope when left empty.
type ClientOptions struct {
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	PostLogoutRedirectURI string
	LoginBaseURL          string
	APIBaseURL            string
	Scope                 string
	HTTPClient            *http.Client
}

// PendingAuthorization is the PKCE verifier + state a caller must persist (a real server-side
// session) between the redirect and the callback — never round-tripped through browser-visible
// state.
type PendingAuthorization struct {
	CodeVerifier     string
	State            string
	AuthorizationURL string
}

// TokenResult mirrors oauth.views.TokenView's real response shape exactly (access_token,
// id_token, token_type, expires_in, scope) — no fields invented, none dropped.
type TokenResult struct {
	AccessToken string
	IDToken     string
	TokenType   string
	ExpiresIn   int
	Scope       string
}

// LogoutTokenPayload is a verified OIDC Back-Channel Logout logout_token's claims.
type LogoutTokenPayload struct {
	Issuer   string                 `json:"iss"`
	Audience string                 `json:"aud"`
	IssuedAt int64                  `json:"iat"`
	Expiry   int64                  `json:"exp"`
	JTI      string                 `json:"jti"`
	Events   map[string]interface{} `json:"events"`
	Subject  string                 `json:"sub,omitempty"`
	SID      string                 `json:"sid,omitempty"`
}

// OneHuxClient is a confidential OAuth 2.0 + PKCE client for OneHux Accounts.
type OneHuxClient struct {
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	PostLogoutRedirectURI string
	LoginBaseURL          string
	APIBaseURL            string
	Scope                 string
	httpClient            *http.Client
}

// NewClient constructs a OneHuxClient, applying the same production-host/scope defaults every
// other SDK in this family uses.
func NewClient(opts ClientOptions) *OneHuxClient {
	loginBaseURL := opts.LoginBaseURL
	if loginBaseURL == "" {
		loginBaseURL = "https://accounts.onehux.com"
	}
	apiBaseURL := opts.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = "https://api-accounts.onehux.com"
	}
	scope := opts.Scope
	if scope == "" {
		scope = "openid profile email"
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &OneHuxClient{
		ClientID:              opts.ClientID,
		ClientSecret:          opts.ClientSecret,
		RedirectURI:           opts.RedirectURI,
		PostLogoutRedirectURI: opts.PostLogoutRedirectURI,
		LoginBaseURL:          strings.TrimRight(loginBaseURL, "/"),
		APIBaseURL:            strings.TrimRight(apiBaseURL, "/"),
		Scope:                 scope,
		httpClient:            httpClient,
	}
}

// StartAuthorization generates a fresh PKCE pair + state and builds the hosted-login redirect
// URL. The caller is responsible for persisting CodeVerifier/State server-side (a real session)
// until the callback — never in a cookie the browser itself can read.
func (c *OneHuxClient) StartAuthorization() (*PendingAuthorization, error) {
	verifierBytes := make([]byte, 48)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to generate code_verifier: %w", err)
	}
	codeVerifier := base64URLEncode(verifierBytes)

	challengeSum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncode(challengeSum[:])

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to generate state: %w", err)
	}
	state := base64URLEncode(stateBytes)

	query := url.Values{
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {c.Scope},
		"state":                 {state},
	}
	return &PendingAuthorization{
		CodeVerifier:     codeVerifier,
		State:            state,
		AuthorizationURL: fmt.Sprintf("%s/login?%s", c.LoginBaseURL, query.Encode()),
	}, nil
}

// ExchangeCode verifies state, then exchanges code for real tokens via
// POST {APIBaseURL}/api/v1/oauth/token/. Returns *InvalidStateError on a state mismatch/missing
// code (never attempts the exchange in that case), and *TokenExchangeError carrying the real
// OAuth error/error_description on a non-2xx response.
func (c *OneHuxClient) ExchangeCode(code, state, expectedState, codeVerifier string) (*TokenResult, error) {
	if code == "" || state == "" || state != expectedState {
		return nil, &InvalidStateError{
			Message: "Callback state did not match the pending authorization, or code/state " +
				"was missing — this callback is either stale, replayed, or forged.",
		}
	}

	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  c.RedirectURI,
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
		"code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to encode token request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.APIBaseURL+"/api/v1/oauth/token/", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("onehuxsso: token request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to read token response: %w", err)
	}

	var parsed map[string]interface{}
	_ = json.Unmarshal(respBody, &parsed)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		oauthErr, _ := parsed["error"].(string)
		errDesc, _ := parsed["error_description"].(string)
		if oauthErr == "step_up_required" {
			// Deliberately distinct from TokenExchangeError: this is a recoverable, expected
			// mid-login prompt (device/location trust gate), not a failed exchange — the caller
			// (CallbackHandler) redirects the browser to complete step-up rather than showing
			// an error.
			return nil, &StepUpRequiredError{ErrorDescription: errDesc}
		}
		if oauthErr == "" {
			oauthErr = "unknown_error"
		}
		return nil, &TokenExchangeError{OAuthError: oauthErr, ErrorDescription: errDesc, StatusCode: resp.StatusCode}
	}

	accessToken, _ := parsed["access_token"].(string)
	idToken, _ := parsed["id_token"].(string)
	tokenType, _ := parsed["token_type"].(string)
	scope, _ := parsed["scope"].(string)
	expiresIn := 0
	if v, ok := parsed["expires_in"].(float64); ok {
		expiresIn = int(v)
	}

	return &TokenResult{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   tokenType,
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}, nil
}

// BuildStepUpRedirectURL builds the redirect used when ExchangeCode returns
// *StepUpRequiredError (README.md ADR-076, backend repo). Reuses this SAME pending
// authorization's ClientID/RedirectURI/Scope/state, and re-derives code_challenge from the
// already-stored codeVerifier (PKCE code_challenge is a pure function of code_verifier, so
// nothing extra needs to be persisted). Deep-links straight to the real hosted email-OTP
// step-up page — the exact same URL the platform's own first-party dashboard redirects to for
// this identical error (backend repo: frontend/src/lib/server/step-up.ts) — rather than the
// generic /login page, since the platform requires a step-up-caliber method specifically here.
// The caller MUST NOT discard the pending codeVerifier/state before calling this: the browser
// will land back on this same app's callback shortly with a brand-new code for this same
// state, and CallbackHandler needs the still-stored codeVerifier to exchange it.
func (c *OneHuxClient) BuildStepUpRedirectURL(codeVerifier, state string) string {
	challengeSum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64URLEncode(challengeSum[:])
	query := url.Values{
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {c.Scope},
		"state":                 {state},
		"reason":                {"step_up"},
	}
	return fmt.Sprintf("%s/login/email-otp?%s", c.LoginBaseURL, query.Encode())
}

// GetUserinfo calls GET {APIBaseURL}/api/v1/oauth/userinfo/ — real claims (sub, name, email,
// picture, roles, permissions, ...), recomputed live by the backend on every call, never cached
// here. Returns *TokenExpiredError on any non-2xx response: OneHux Accounts access tokens are a
// 15-minute, single-issue lifetime with no refresh token today, so an expired/invalid token
// here means "send the user through StartAuthorization() again," not "retry."
func (c *OneHuxClient) GetUserinfo(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, c.APIBaseURL+"/api/v1/oauth/userinfo/", nil)
	if err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &TokenExpiredError{Message: "The access token was rejected by /userinfo: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &TokenExpiredError{
			Message: "The access token was rejected by /userinfo — it has either expired " +
				"(15-minute lifetime, no refresh token issued by this platform today) or was " +
				"revoked. Send the user back through OneHuxClient.StartAuthorization().",
		}
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("onehuxsso: failed to decode userinfo response: %w", err)
	}
	return claims, nil
}

// BuildLogoutURL builds the RP-initiated logout redirect (README.md ADR-070, backend repo):
// PostLogoutRedirectURI must already be registered in this Application's own redirect_uris
// list — the same list the login callback uses, not a separate one — or the platform rejects
// this with a real 400.
func (c *OneHuxClient) BuildLogoutURL(state string) string {
	query := url.Values{
		"client_id":                {c.ClientID},
		"post_logout_redirect_uri": {c.PostLogoutRedirectURI},
	}
	if state != "" {
		query.Set("state", state)
	}
	return fmt.Sprintf("%s/end-session?%s", c.LoginBaseURL, query.Encode())
}

// ExtractSidFromIDToken pulls the `sid` claim out of idToken WITHOUT verifying its signature —
// this package has no way to verify an id_token's signature (OneHux Accounts signs it with a
// server-only key never shared with any client — the backend repo's oauth.services.build_jwt()
// docstring flags this as a deliberate Phase-1 gap), and doesn't need to for this purpose: the
// token was retrieved directly from a client_secret-authenticated POST to
// /api/v1/oauth/token/ over TLS, not an untrusted redirect parameter, so trusting its contents
// here (indexing a local session for a later logout_token match) is standard OIDC RP practice.
// Returns "" if the token doesn't decode or has no sid claim.
func (c *OneHuxClient) ExtractSidFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return ""
	}
	var payload struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return ""
	}
	return payload.SID
}

// VerifyLogoutToken performs real OIDC Back-Channel Logout validation (spec §2.6), HS256-
// verified by hand via crypto/hmac — this package has zero non-stdlib dependencies and a full
// JWT library isn't worth pulling in for one HMAC check. signingSecret is the dedicated secret
// shown once when you registered your backchannel_logout_uri via
// PATCH /api/v1/applications/{id}/backchannel-logout/ — deliberately NOT this client's own
// ClientSecret (the backend cannot read that back to sign anything with it; see the backend
// repo's README.md ADR-074). Returns *InvalidLogoutTokenError on any validation failure.
func (c *OneHuxClient) VerifyLogoutToken(logoutToken, signingSecret string) (*LogoutTokenPayload, error) {
	if signingSecret == "" {
		return nil, &InvalidLogoutTokenError{Message: "No backchannel logout signing secret configured."}
	}

	parts := strings.Split(logoutToken, ".")
	if len(parts) != 3 {
		return nil, &InvalidLogoutTokenError{Message: "logout_token is not a well-formed JWT."}
	}
	headerB64, payloadB64, signatureB64 := parts[0], parts[1], parts[2]

	headerBytes, err := base64URLDecode(headerB64)
	if err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token header is not valid base64url."}
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token header is not valid JSON."}
	}
	if header.Alg != "HS256" {
		return nil, &InvalidLogoutTokenError{Message: "Unsupported logout_token alg: " + header.Alg}
	}

	payloadBytes, err := base64URLDecode(payloadB64)
	if err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token payload is not valid base64url."}
	}
	var rawPayload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &rawPayload); err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token payload is not valid JSON."}
	}

	actualSignature, err := base64URLDecode(signatureB64)
	if err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token signature is not valid base64url."}
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(headerB64 + "." + payloadB64))
	expectedSignature := mac.Sum(nil)
	if subtle.ConstantTimeCompare(actualSignature, expectedSignature) != 1 {
		return nil, &InvalidLogoutTokenError{Message: "logout_token signature verification failed."}
	}

	var payload LogoutTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, &InvalidLogoutTokenError{Message: "logout_token payload is not valid JSON."}
	}

	if payload.Expiry == 0 || payload.Expiry < time.Now().Unix() {
		return nil, &InvalidLogoutTokenError{Message: "logout_token has expired."}
	}
	if payload.Audience != c.ClientID {
		return nil, &InvalidLogoutTokenError{Message: "logout_token aud does not match this client_id."}
	}
	if _, hasNonce := rawPayload["nonce"]; hasNonce {
		return nil, &InvalidLogoutTokenError{Message: "logout_token MUST NOT contain a nonce claim."}
	}
	if payload.Events == nil {
		return nil, &InvalidLogoutTokenError{
			Message: "logout_token is missing the required events claim (" + LogoutEventClaimKey + ").",
		}
	}
	if _, hasEvent := payload.Events[LogoutEventClaimKey]; !hasEvent {
		return nil, &InvalidLogoutTokenError{
			Message: "logout_token is missing the required events claim (" + LogoutEventClaimKey + ").",
		}
	}
	if payload.Subject == "" && payload.SID == "" {
		return nil, &InvalidLogoutTokenError{Message: "logout_token must contain a sub claim, a sid claim, or both."}
	}

	return &payload, nil
}
