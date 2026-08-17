// handlers.go
// Handlers — real, runnable net/http handlers wiring OneHuxClient to a real SessionStore, the
// same BFF discipline the platform's own dashboard follows on itself: the access token lives
// only server-side, never sent to the browser. Mirrors onehux_sso.views (Django),
// createOneHuxRouter (Node.js), and OneHuxSSOController (Laravel) in shape and behavior.
package onehuxsso

import (
	"encoding/json"
	"errors"
	"net/http"
)

const (
	stateSessionKey    = "onehux_sso_state"
	verifierSessionKey = "onehux_sso_pkce_verifier"
	sidSessionKey      = "onehux_sso_sid"
)

// HandlersOptions configures Handlers. Only Client and Store are required.
type HandlersOptions struct {
	Client *OneHuxClient
	Store  SessionStore

	// SessionAccessTokenKey is the SessionStore key the access token is stored under. Default:
	// "onehux_access_token".
	SessionAccessTokenKey string
	// LoginSuccessRedirect is where a successful login redirects to. Default: "/".
	LoginSuccessRedirect string
	// BackchannelLogoutSigningSecret is the dedicated secret shown once when you registered
	// your backchannel_logout_uri via PATCH /api/v1/applications/{id}/backchannel-logout/ —
	// deliberately NOT ClientSecret. Required only if you want BackchannelLogoutHandler to
	// actually verify and act on incoming logout_token POSTs; if empty, that handler responds
	// 400 to every request rather than silently accepting an unverifiable one.
	BackchannelLogoutSigningSecret string
	// SidIndex maps a OneHux Session id to a local session id (see SidIndex's own docstring).
	// Defaults to an in-memory index, correct for a single-process deployment only.
	SidIndex SidIndex
}

// Handlers bundles a OneHuxClient + SessionStore into five real, runnable http.HandlerFuncs.
type Handlers struct {
	client                         *OneHuxClient
	store                          SessionStore
	sessionAccessTokenKey          string
	loginSuccessRedirect           string
	backchannelLogoutSigningSecret string
	sidIndex                       SidIndex
}

// NewHandlers constructs Handlers from opts, applying the same defaults documented on
// HandlersOptions.
func NewHandlers(opts HandlersOptions) *Handlers {
	sessionAccessTokenKey := opts.SessionAccessTokenKey
	if sessionAccessTokenKey == "" {
		sessionAccessTokenKey = "onehux_access_token"
	}
	loginSuccessRedirect := opts.LoginSuccessRedirect
	if loginSuccessRedirect == "" {
		loginSuccessRedirect = "/"
	}
	sidIndex := opts.SidIndex
	if sidIndex == nil {
		sidIndex = NewMemorySidIndex()
	}
	return &Handlers{
		client:                         opts.Client,
		store:                          opts.Store,
		sessionAccessTokenKey:          sessionAccessTokenKey,
		loginSuccessRedirect:           loginSuccessRedirect,
		backchannelLogoutSigningSecret: opts.BackchannelLogoutSigningSecret,
		sidIndex:                       sidIndex,
	}
}

// Mount registers all five routes on mux under prefix (e.g. "/auth"), giving you
// {prefix}/login, {prefix}/callback, {prefix}/logout, {prefix}/userinfo, and
// {prefix}/backchannel-logout.
func (h *Handlers) Mount(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/login", h.LoginHandler)
	mux.HandleFunc(prefix+"/callback", h.CallbackHandler)
	mux.HandleFunc(prefix+"/logout", h.LogoutHandler)
	mux.HandleFunc(prefix+"/userinfo", h.UserinfoHandler)
	mux.HandleFunc(prefix+"/backchannel-logout", h.BackchannelLogoutHandler)
}

// LoginHandler: GET {prefix}/login — starts the flow: generates PKCE + state, stashes them in
// the session, redirects to the real hosted login page.
func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	pending, err := h.client.StartAuthorization()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, values, err := h.store.Get(w, r)
	if err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	values[stateSessionKey] = pending.State
	values[verifierSessionKey] = pending.CodeVerifier
	if err := h.store.Save(id, values); err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, pending.AuthorizationURL, http.StatusFound)
}

// CallbackHandler: GET {prefix}/callback — verifies state, exchanges the code, stores the
// access token in the session, redirects to LoginSuccessRedirect. Also indexes the session by
// the id_token's `sid` claim (OIDC Back-Channel Logout — optional feature, see
// BackchannelLogoutHandler).
func (h *Handlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if errParam := query.Get("error"); errParam != "" {
		http.Error(w, "Sign-in failed: "+errParam+" — "+query.Get("error_description"), http.StatusBadRequest)
		return
	}

	id, values, err := h.store.Get(w, r)
	if err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	expectedState := values[stateSessionKey]
	codeVerifier := values[verifierSessionKey]
	delete(values, stateSessionKey)
	delete(values, verifierSessionKey)

	tokens, err := h.client.ExchangeCode(query.Get("code"), query.Get("state"), expectedState, codeVerifier)
	if err != nil {
		var invalidState *InvalidStateError
		var exchangeErr *TokenExchangeError
		switch {
		case errors.As(err, &invalidState):
			http.Error(w, invalidState.Message, http.StatusBadRequest)
		case errors.As(err, &exchangeErr):
			http.Error(w, exchangeErr.OAuthError+": "+exchangeErr.ErrorDescription, http.StatusBadRequest)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	values[h.sessionAccessTokenKey] = tokens.AccessToken

	// OIDC Back-Channel Logout (optional): index this session by the OneHux Session id (`sid`)
	// carried in the id_token, so a later logout_token POST to BackchannelLogoutHandler can
	// find and destroy exactly this session.
	if sid := h.client.ExtractSidFromIDToken(tokens.IDToken); sid != "" {
		values[sidSessionKey] = sid
		h.sidIndex.Set(sid, id)
	}

	if err := h.store.Save(id, values); err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.loginSuccessRedirect, http.StatusFound)
}

// LogoutHandler: GET {prefix}/logout — clears the local session access token, then redirects
// through the real RP-initiated /end-session flow, ending the platform-wide session, not just
// this app's own local one.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	id, values, err := h.store.Get(w, r)
	if err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	delete(values, h.sessionAccessTokenKey)
	if err := h.store.Save(id, values); err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.client.BuildLogoutURL(""), http.StatusFound)
}

// UserinfoHandler: GET {prefix}/userinfo — a ready-to-use JSON endpoint for your own frontend
// to call, matching the BFF pattern documented for the web-frontend integration guide: your
// frontend calls your own backend, never OneHux directly. Returns 401 with the real
// TokenExpiredError message when the session's token is expired/invalid.
func (h *Handlers) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	_, values, err := h.store.Get(w, r)
	if err != nil {
		http.Error(w, "session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	accessToken := values[h.sessionAccessTokenKey]
	if accessToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "Not signed in."})
		return
	}

	claims, err := h.client.GetUserinfo(accessToken)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

// BackchannelLogoutHandler: POST {prefix}/backchannel-logout — OIDC Back-Channel Logout
// receiving endpoint (spec: openid-connect-backchannel-1_0.html §2.6). Register this exact URL
// (e.g. https://yourapp.example.com/auth/backchannel-logout) via
// PATCH /api/v1/applications/{id}/backchannel-logout/ on OneHux, and set
// BackchannelLogoutSigningSecret to the secret returned by that call.
//
// This is what makes an IdP-initiated logout (a user clicking "log out" directly on
// accounts.onehux.com, or an admin revoking their session) actually terminate THIS app's own
// local session in real time, rather than only being discovered the next time this app happens
// to call /userinfo and gets a 401. The platform-side session is genuinely revoked immediately
// either way — without this handler mounted and registered, only the notification is missing.
//
// No CSRF protection is applied (and none should be) — this is a server-to-server POST from
// OneHux's own backend with no browser session/cookie of its own to carry a CSRF token; the
// logout_token's own HS256 signature (verified below) is this endpoint's real authenticity
// check. Per spec: responds 200 on success, 400 on any validation failure, always with
// Cache-Control: no-store.
func (h *Handlers) BackchannelLogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.backchannelLogoutError(w, "Could not parse request body: "+err.Error())
		return
	}
	logoutToken := r.PostFormValue("logout_token")
	if logoutToken == "" {
		h.backchannelLogoutError(w, "Missing logout_token.")
		return
	}

	payload, err := h.client.VerifyLogoutToken(logoutToken, h.backchannelLogoutSigningSecret)
	if err != nil {
		h.backchannelLogoutError(w, err.Error())
		return
	}

	// A miss here (already logged out locally, or this process never saw the login) is a
	// correct, spec-defined success case (§2.6: "the logout is considered to have succeeded"),
	// not an error — still responds 200 below.
	if payload.SID != "" {
		if sessionID, ok := h.sidIndex.Get(payload.SID); ok {
			_ = h.store.Destroy(sessionID)
			h.sidIndex.Delete(payload.SID)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) backchannelLogoutError(w http.ResponseWriter, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_request",
		"error_description": detail,
	})
}
