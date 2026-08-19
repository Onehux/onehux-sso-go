// client_test.go
// Real unit tests for OneHuxClient — PKCE generation/matching, every error-type branch, every
// URL-building method, and logout_token HMAC verification. No live network calls: HTTP-hitting
// methods are tested against a local httptest.Server standing in for OneHux's API.
package onehuxsso

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(apiBaseURL string) *OneHuxClient {
	return NewClient(ClientOptions{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		RedirectURI:           "https://app.example.com/auth/callback",
		PostLogoutRedirectURI: "https://app.example.com/auth/logged-out",
		LoginBaseURL:          "https://accounts.example.com",
		APIBaseURL:            apiBaseURL,
	})
}

// --- PKCE generation/matching ---

func TestStartAuthorization_PKCEChallengeMatchesVerifier(t *testing.T) {
	client := newTestClient("https://api.example.com")
	pending, err := client.StartAuthorization()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pending.CodeVerifier == "" || pending.State == "" {
		t.Fatal("expected non-empty CodeVerifier and State")
	}

	parsed, err := url.Parse(pending.AuthorizationURL)
	if err != nil {
		t.Fatalf("AuthorizationURL is not a valid URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("state") != pending.State {
		t.Errorf("URL state %q does not match pending.State %q", query.Get("state"), pending.State)
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %q", query.Get("code_challenge_method"))
	}

	sum := sha256.Sum256([]byte(pending.CodeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if query.Get("code_challenge") != expectedChallenge {
		t.Errorf("code_challenge in URL does not match sha256(code_verifier): got %q, want %q",
			query.Get("code_challenge"), expectedChallenge)
	}
}

func TestStartAuthorization_GeneratesFreshValuesEachCall(t *testing.T) {
	client := newTestClient("https://api.example.com")
	first, _ := client.StartAuthorization()
	second, _ := client.StartAuthorization()
	if first.State == second.State {
		t.Error("expected a fresh state on each call, got the same value twice")
	}
	if first.CodeVerifier == second.CodeVerifier {
		t.Error("expected a fresh code_verifier on each call, got the same value twice")
	}
}

// --- ExchangeCode error branches ---

func TestExchangeCode_InvalidStateError_OnMismatch(t *testing.T) {
	client := newTestClient("https://api.example.com")
	_, err := client.ExchangeCode("real-code", "state-a", "state-b", "verifier")
	var invalidState *InvalidStateError
	if !errors.As(err, &invalidState) {
		t.Fatalf("expected *InvalidStateError, got %T: %v", err, err)
	}
}

func TestExchangeCode_InvalidStateError_OnMissingCode(t *testing.T) {
	client := newTestClient("https://api.example.com")
	_, err := client.ExchangeCode("", "state", "state", "verifier")
	var invalidState *InvalidStateError
	if !errors.As(err, &invalidState) {
		t.Fatalf("expected *InvalidStateError for missing code, got %T: %v", err, err)
	}
}

func TestExchangeCode_StepUpRequiredError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "step_up_required",
			"error_description": "New device or location detected.",
		})
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	_, err := client.ExchangeCode("code", "state", "state", "verifier")
	var stepUp *StepUpRequiredError
	if !errors.As(err, &stepUp) {
		t.Fatalf("expected *StepUpRequiredError, got %T: %v", err, err)
	}
	if stepUp.ErrorDescription != "New device or location detected." {
		t.Errorf("unexpected ErrorDescription: %q", stepUp.ErrorDescription)
	}
}

func TestExchangeCode_TokenExchangeError_OnOtherOAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Authorization code is expired or already used.",
		})
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	_, err := client.ExchangeCode("code", "state", "state", "verifier")
	var exchangeErr *TokenExchangeError
	if !errors.As(err, &exchangeErr) {
		t.Fatalf("expected *TokenExchangeError, got %T: %v", err, err)
	}
	if exchangeErr.OAuthError != "invalid_grant" {
		t.Errorf("expected OAuthError=invalid_grant, got %q", exchangeErr.OAuthError)
	}
	if exchangeErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected StatusCode=400, got %d", exchangeErr.StatusCode)
	}
}

func TestExchangeCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/oauth/token/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-123",
			"id_token":     "id-456",
			"token_type":   "Bearer",
			"expires_in":   900,
			"scope":        "openid profile email",
		})
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	tokens, err := client.ExchangeCode("code", "state", "state", "verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.AccessToken != "at-123" || tokens.IDToken != "id-456" || tokens.ExpiresIn != 900 {
		t.Errorf("unexpected TokenResult: %+v", tokens)
	}
}

// --- GetUserinfo ---

func TestGetUserinfo_TokenExpiredError_OnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	_, err := client.GetUserinfo("expired-token")
	var expired *TokenExpiredError
	if !errors.As(err, &expired) {
		t.Fatalf("expected *TokenExpiredError, got %T: %v", err, err)
	}
}

// --- GetPublicApplications ---

func TestGetPublicApplications_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/organizations/onehux/public-applications/" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]map[string]string{
			{"name": "ODS", "logo_url": "https://example.com/logo.png", "home_url": "https://ods.example.com"},
		})
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	apps, err := client.GetPublicApplications("onehux")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apps) != 1 || apps[0].Name != "ODS" || apps[0].HomeURL != "https://ods.example.com" {
		t.Errorf("unexpected result: %+v", apps)
	}
}

func TestGetPublicApplications_OrganizationNotFoundError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "not_found",
			"error_description": "No Organization matches that slug.",
		})
	}))
	defer server.Close()

	client := newTestClient(server.URL)
	_, err := client.GetPublicApplications("does-not-exist")
	var notFound *OrganizationNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *OrganizationNotFoundError, got %T: %v", err, err)
	}
}

// --- URL-building methods ---

func TestBuildLogoutURL(t *testing.T) {
	client := newTestClient("https://api.example.com")
	got := client.BuildLogoutURL("")
	parsed, _ := url.Parse(got)
	if !strings.HasPrefix(got, "https://accounts.example.com/end-session?") {
		t.Errorf("unexpected logout URL: %s", got)
	}
	q := parsed.Query()
	if q.Get("client_id") != "test-client-id" || q.Get("post_logout_redirect_uri") != "https://app.example.com/auth/logged-out" {
		t.Errorf("unexpected logout URL params: %v", q)
	}
	if q.Has("state") {
		t.Error("expected no state param when state is empty")
	}
}

func TestBuildLogoutURL_WithState(t *testing.T) {
	client := newTestClient("https://api.example.com")
	got := client.BuildLogoutURL("xyz")
	parsed, _ := url.Parse(got)
	if parsed.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz in logout URL, got %q", parsed.Query().Get("state"))
	}
}

func TestBuildStepUpRedirectURL(t *testing.T) {
	client := newTestClient("https://api.example.com")
	codeVerifier := "abc123verifier"
	got := client.BuildStepUpRedirectURL(codeVerifier, "state-xyz")

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("not a valid URL: %v", err)
	}
	if parsed.Host != "accounts.example.com" || parsed.Path != "/login/email-otp" {
		t.Errorf("unexpected host/path: %s%s", parsed.Host, parsed.Path)
	}
	q := parsed.Query()
	if q.Get("reason") != "step_up" {
		t.Errorf("expected reason=step_up, got %q", q.Get("reason"))
	}
	if q.Get("client_id") != "test-client-id" || q.Get("redirect_uri") != "https://app.example.com/auth/callback" {
		t.Errorf("unexpected client_id/redirect_uri: %v", q)
	}
	if q.Get("state") != "state-xyz" {
		t.Errorf("expected state=state-xyz, got %q", q.Get("state"))
	}

	sum := sha256.Sum256([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if q.Get("code_challenge") != expectedChallenge {
		t.Errorf("code_challenge does not match sha256(code_verifier): got %q, want %q",
			q.Get("code_challenge"), expectedChallenge)
	}
}

// --- logout_token HMAC verification ---

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func buildLogoutToken(t *testing.T, secret string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "logout+jwt"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := b64url(headerJSON)
	payloadB64 := b64url(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerB64 + "." + payloadB64))
	sig := b64url(mac.Sum(nil))
	return headerB64 + "." + payloadB64 + "." + sig
}

func validClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss":    "https://accounts.onehux.com",
		"aud":    "test-client-id",
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(2 * time.Minute).Unix(),
		"jti":    "unique-id",
		"events": map[string]interface{}{"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{}},
		"sid":    "session-123",
	}
}

func TestVerifyLogoutToken_ValidToken(t *testing.T) {
	client := newTestClient("https://api.example.com")
	token := buildLogoutToken(t, "shared-secret", validClaims())

	payload, err := client.VerifyLogoutToken(token, "shared-secret")
	if err != nil {
		t.Fatalf("expected valid token to verify, got error: %v", err)
	}
	if payload.SID != "session-123" {
		t.Errorf("expected sid=session-123, got %q", payload.SID)
	}
}

func TestVerifyLogoutToken_WrongSignature(t *testing.T) {
	client := newTestClient("https://api.example.com")
	token := buildLogoutToken(t, "shared-secret", validClaims())

	_, err := client.VerifyLogoutToken(token, "wrong-secret")
	if err == nil {
		t.Fatal("expected an error for a token signed with the wrong secret")
	}
}

func TestVerifyLogoutToken_Expired(t *testing.T) {
	client := newTestClient("https://api.example.com")
	claims := validClaims()
	claims["exp"] = time.Now().Add(-1 * time.Minute).Unix()
	token := buildLogoutToken(t, "shared-secret", claims)

	_, err := client.VerifyLogoutToken(token, "shared-secret")
	if err == nil {
		t.Fatal("expected an error for an expired token")
	}
}

func TestVerifyLogoutToken_WrongAudience(t *testing.T) {
	client := newTestClient("https://api.example.com")
	claims := validClaims()
	claims["aud"] = "some-other-client"
	token := buildLogoutToken(t, "shared-secret", claims)

	_, err := client.VerifyLogoutToken(token, "shared-secret")
	if err == nil {
		t.Fatal("expected an error for a token with the wrong aud")
	}
}

func TestVerifyLogoutToken_NoncePresent_Rejected(t *testing.T) {
	client := newTestClient("https://api.example.com")
	claims := validClaims()
	claims["nonce"] = "should-not-be-here"
	token := buildLogoutToken(t, "shared-secret", claims)

	_, err := client.VerifyLogoutToken(token, "shared-secret")
	if err == nil {
		t.Fatal("expected an error: logout_token MUST NOT contain a nonce claim")
	}
}

func TestVerifyLogoutToken_MissingEventsClaim(t *testing.T) {
	client := newTestClient("https://api.example.com")
	claims := validClaims()
	delete(claims, "events")
	token := buildLogoutToken(t, "shared-secret", claims)

	_, err := client.VerifyLogoutToken(token, "shared-secret")
	if err == nil {
		t.Fatal("expected an error for a token missing the required events claim")
	}
}

func TestVerifyLogoutToken_MissingSubAndSid_Rejected(t *testing.T) {
	client := newTestClient("https://api.example.com")
	claims := validClaims()
	delete(claims, "sid")
	token := buildLogoutToken(t, "shared-secret", claims)

	_, err := client.VerifyLogoutToken(token, "shared-secret")
	if err == nil {
		t.Fatal("expected an error for a token with neither sub nor sid")
	}
}

func TestVerifyLogoutToken_NoSigningSecretConfigured(t *testing.T) {
	client := newTestClient("https://api.example.com")
	token := buildLogoutToken(t, "shared-secret", validClaims())

	_, err := client.VerifyLogoutToken(token, "")
	if err == nil {
		t.Fatal("expected an error when no signing secret is configured")
	}
}
