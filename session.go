// session.go
// SessionStore — the minimal server-side session abstraction Handlers (handlers.go) needs.
// Go has no single dominant session framework the way Django/Express/Laravel do, so this
// package defines the narrow interface it actually needs and ships one real, working
// implementation (MemorySessionStore) rather than assuming a specific one. A production
// deployment running more than one process should supply its own SessionStore backed by
// shared storage (Redis, a database, ...) — MemorySessionStore is correct for a single-process
// app only, the same caveat every in-memory index in this SDK family carries.
package onehuxsso

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// SessionStore is the server-side session contract Handlers relies on. Values are plain
// string->string maps — enough for what this package itself stores (an access token, an
// id_token's sid) and for a caller's own additional session data.
type SessionStore interface {
	// Get resolves the caller's session from r (via its cookie), creating a new empty one
	// (and queuing its cookie on w) if none exists yet. Returns the session id and its current
	// values.
	Get(w http.ResponseWriter, r *http.Request) (id string, values map[string]string, err error)
	// Save persists values under the given session id.
	Save(id string, values map[string]string) error
	// Destroy deletes the session identified by id outright, wherever it's stored — used both
	// by the local /logout handler and, more importantly, by OIDC Back-Channel Logout, which
	// destroys a session that has nothing to do with the current request at all.
	Destroy(id string) error
}

const sessionCookieName = "onehux_sso_session"

// sessionCookieLifetime is how long MemorySessionStore's own cookie is valid for.
//
// This is deliberately NOT tied to the 15-minute access-token lifetime: the cookie only carries
// an opaque local session id, never the token itself, and UserinfoHandler (and any caller of
// OneHuxClient.GetUserinfo) already treats a *TokenExpiredError from a stale-but-present token as
// the normal, expected case — it returns 401, not a crash, so the local session cookie safely
// outliving one token is fine as long as that safety net actually fires. What was wrong before
// was 30 days: a cookie that implies weeks of validity for a credential that dies in 15 minutes
// was misleading operationally (support tickets, security review, cookie-lifetime audits) even
// though it wasn't itself the source of stale-token bugs. 24 hours matches a normal single-day
// browser session without pretending the underlying token is anywhere near that fresh.
const sessionCookieLifetime = 24 * time.Hour

// MemorySessionStore is a real, working, in-process SessionStore — correct for the example app
// and any genuinely single-process deployment. Session ids are cryptographically random and
// carried in an HttpOnly cookie; nothing but the opaque id ever reaches the browser.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]map[string]string
	secure   bool
}

// NewMemorySessionStore constructs an empty store. Set secure=true in production (HTTPS-only
// cookie) — false is appropriate for local http://localhost development, matching the other
// SDKs' own example apps.
func NewMemorySessionStore(secure bool) *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]map[string]string), secure: secure}
}

func randomID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *MemorySessionStore) Get(w http.ResponseWriter, r *http.Request) (string, map[string]string, error) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.RLock()
		values, ok := s.sessions[cookie.Value]
		s.mu.RUnlock()
		if ok {
			return cookie.Value, values, nil
		}
	}

	id, err := randomID()
	if err != nil {
		return "", nil, err
	}
	values := make(map[string]string)
	s.mu.Lock()
	s.sessions[id] = values
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionCookieLifetime),
	})
	return id, values, nil
}

func (s *MemorySessionStore) Save(id string, values map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = values
	return nil
}

func (s *MemorySessionStore) Destroy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

// SidIndex maps a OneHux Session id (`sid`) to the local session id it's associated with — the
// bridge a real logout_token POST (which only carries `sid`) needs in order to find and destroy
// the matching local SessionStore entry. Same shape/caveat as the Node.js SDK's own
// BackchannelSidIndex: the default MemorySidIndex only works within a single process; a real
// multi-process deployment must supply a shared implementation.
type SidIndex interface {
	Set(sid, sessionID string)
	Get(sid string) (sessionID string, ok bool)
	Delete(sid string)
}

// MemorySidIndex is a real, working, in-process SidIndex — correct for the example app and any
// genuinely single-process deployment.
type MemorySidIndex struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewMemorySidIndex constructs an empty index.
func NewMemorySidIndex() *MemorySidIndex {
	return &MemorySidIndex{m: make(map[string]string)}
}

func (idx *MemorySidIndex) Set(sid, sessionID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.m[sid] = sessionID
}

func (idx *MemorySidIndex) Get(sid string) (string, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	sessionID, ok := idx.m[sid]
	return sessionID, ok
}

func (idx *MemorySidIndex) Delete(sid string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.m, sid)
}
