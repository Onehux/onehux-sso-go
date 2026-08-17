// example/main.go
// Real, runnable example — exercises onehux-sso-go end to end against production. Uses
// onehuxsso.Handlers for the five standard routes, plus its own home/logged-out pages.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	onehuxsso "github.com/onehux/onehux-sso-go"
)

const port = "4184"

const pageTemplate = `<!doctype html><html><head><meta charset="utf-8"><title>onehux-sso-go example</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:3rem auto;padding:0 1rem;color:#111}
a.btn{display:inline-block;padding:.5rem 1rem;border:1px solid #333;border-radius:4px;text-decoration:none;color:#111;margin-right:.5rem}
pre{background:#f4f4f4;padding:1rem;overflow-x:auto;white-space:pre-wrap}</style></head>
<body>%s</body></html>`

func page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, pageTemplate, body)
}

func main() {
	clientID := os.Getenv("ONEHUX_CLIENT_ID")
	clientSecret := os.Getenv("ONEHUX_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("Missing ONEHUX_CLIENT_ID / ONEHUX_CLIENT_SECRET env vars.")
	}

	client := onehuxsso.NewClient(onehuxsso.ClientOptions{
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		RedirectURI:           "http://localhost:" + port + "/auth/callback",
		PostLogoutRedirectURI: "http://localhost:" + port + "/auth/logged-out",
	})

	store := onehuxsso.NewMemorySessionStore(false) // false: local http://localhost, not https
	handlers := onehuxsso.NewHandlers(onehuxsso.HandlersOptions{
		Client:                         client,
		Store:                          store,
		BackchannelLogoutSigningSecret: os.Getenv("ONEHUX_BACKCHANNEL_LOGOUT_SIGNING_SECRET"),
	})

	mux := http.NewServeMux()
	handlers.Mount(mux, "/auth")

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, values, err := store.Get(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		accessToken := values["onehux_access_token"]
		if accessToken == "" {
			page(w, `
				<h1>onehux-sso-go example — signed out</h1>
				<p>Real end-to-end demo of the onehux-sso-go module against production.</p>
				<a class="btn" href="/auth/login">Sign in</a>
			`)
			return
		}

		claims, err := client.GetUserinfo(accessToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			page(w, fmt.Sprintf(
				`<h1>Token expired</h1><pre>%s</pre><a class="btn" href="/auth/login">Sign in again</a>`,
				err.Error(),
			))
			return
		}

		pretty, _ := json.MarshalIndent(claims, "", "  ")
		page(w, fmt.Sprintf(`
			<h1>onehux-sso-go example — signed in</h1>
			<p>Real claims from GET /api/v1/oauth/userinfo/:</p>
			<pre>%s</pre>
			<a class="btn" href="/auth/logout">Log out (RP-initiated SLO)</a>
			<p style="margin-top:2rem;color:#666">To confirm true single-logout, separately open
			<a href="https://accounts.onehux.com/dashboard" target="_blank">accounts.onehux.com/dashboard</a>
			after logging out — it should demand login again.</p>
		`, string(pretty)))
	})

	mux.HandleFunc("/auth/logged-out", func(w http.ResponseWriter, r *http.Request) {
		page(w, `
			<h1>Logged out</h1>
			<p>Redirected back here by OneHux's own RP-initiated logout.</p>
			<a class="btn" href="/">Home</a>
		`)
	})

	log.Printf("onehux-sso-go example listening on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
