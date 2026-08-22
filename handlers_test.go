// handlers_test.go
// Real HTTP-level tests for Handlers — proves TokenExpiredError returned deep inside
// OneHuxClient.GetUserinfo actually propagates all the way out to a real net/http response
// (401, not a silent pass-through or a 200) via UserinfoHandler. No live network calls: the
// upstream OneHux /userinfo endpoint is a local httptest.Server standing in for the real one,
// same pattern as client_test.go.
package onehuxsso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestHandlers wires a Handlers instance to a local httptest.Server standing in for OneHux's
// API, and a fresh MemorySessionStore — mirrors newTestClient's role in client_test.go.
func newTestHandlers(apiBaseURL string) (*Handlers, *MemorySessionStore) {
	client := NewClient(ClientOptions{
		ClientID:              "test-client-id",
		ClientSecret:          "test-client-secret",
		RedirectURI:           "https://app.example.com/auth/callback",
		PostLogoutRedirectURI: "https://app.example.com/auth/logged-out",
		LoginBaseURL:          "https://accounts.example.com",
		APIBaseURL:            apiBaseURL,
	})
	store := NewMemorySessionStore(false)
	handlers := NewHandlers(HandlersOptions{Client: client, Store: store})
	return handlers, store
}

// --- UserinfoHandler: TokenExpiredError propagation ---

// TestUserinfoHandler_ExpiredToken_Returns401 is the real regression test for the propagation
// path a prior investigation flagged as unverified: does *TokenExpiredError, returned deep in
// OneHuxClient.GetUserinfo, actually reach the HTTP layer as a 401 an integrating app can act on
// (redirect to login), or does it get silently absorbed somewhere in between? Confirmed here:
// UserinfoHandler (handlers.go) checks the error returned by GetUserinfo and writes a real 401
// with the TokenExpiredError's message in the body — nothing swallows it.
func TestUserinfoHandler_ExpiredToken_Returns401(t *testing.T) {
	// Stands in for OneHux's own /api/v1/oauth/userinfo/ rejecting an expired/invalid token.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	handlers, store := newTestHandlers(upstream.URL)

	// Seed a session that already has a (now-expired) access token stored — the state
	// UserinfoHandler sees on every request after the token's 15-minute lifetime has elapsed.
	sessionID := "test-session-id"
	store.sessions[sessionID] = map[string]string{"onehux_access_token": "expired-token-value"}

	req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()

	handlers.UserinfoHandler(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when the access token is expired, got %d — "+
			"TokenExpiredError is not propagating to the HTTP layer", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["detail"] == "" {
		t.Fatal("expected a non-empty \"detail\" message describing the expired token, got none")
	}
}

// TestUserinfoHandler_NoSession_Returns401 covers the companion case: no access token stored in
// the session at all (never signed in, or already cleared by /logout) — also a 401, distinct
// code path from the expired-token case above (short-circuits before ever calling GetUserinfo),
// but must not be confused with a 200 or a silent pass-through either.
func TestUserinfoHandler_NoSession_Returns401(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("GetUserinfo should never be called when there is no stored access token")
	}))
	defer upstream.Close()

	handlers, _ := newTestHandlers(upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	rec := httptest.NewRecorder()

	handlers.UserinfoHandler(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized with no session token, got %d", resp.StatusCode)
	}
}

// TestUserinfoHandler_ValidToken_Returns200 is the control case: a genuinely valid token must
// still succeed, proving the 401 above is specific to the expired/invalid case and this handler
// isn't just failing closed on every request.
func TestUserinfoHandler_ValidToken_Returns200(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer valid-token-value" {
			t.Errorf("unexpected Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": "user-123", "email": "user@example.com"})
	}))
	defer upstream.Close()

	handlers, store := newTestHandlers(upstream.URL)

	sessionID := "test-session-id"
	store.sessions[sessionID] = map[string]string{"onehux_access_token": "valid-token-value"}

	req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()

	handlers.UserinfoHandler(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for a valid token, got %d", resp.StatusCode)
	}
}

// --- MemorySessionStore cookie lifetime ---

// TestMemorySessionStore_CookieLifetime_NotWeeksLong guards against the fixed live mismatch: a
// cookie implying weeks of validity for a 15-minute access token. Doesn't assert an exact
// duration (an implementation detail free to tune) — asserts it's no longer in the "many days"
// range the old 30-day value was.
func TestMemorySessionStore_CookieLifetime_NotWeeksLong(t *testing.T) {
	store := NewMemorySessionStore(false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	if _, _, err := store.Get(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one cookie to be set, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName {
		t.Fatalf("expected cookie named %q, got %q", sessionCookieName, cookie.Name)
	}

	maxLifetime := 7 * 24 * 60 * 60 // 7 days, in seconds — generously above 24h, well below 30d.
	untilExpiry := int(cookie.Expires.Unix() - time.Now().Unix())
	if untilExpiry <= 0 {
		t.Fatal("expected a future Expires time on the session cookie")
	}
	if untilExpiry > maxLifetime {
		t.Fatalf("session cookie lifetime is %ds, still implies weeks of validity for a "+
			"15-minute access token (old bug was a 30-day cookie)", untilExpiry)
	}
}
