package handlers

import (
	"fmt"
	"io"
	"net/http"
)

// Fetch makes a server-side HTTP request to a caller-supplied URL.
// CWE-918: Server-Side Request Forgery (SSRF) — the `url` parameter is passed
// directly to http.Get without validation. An attacker can supply internal
// addresses (e.g. http://169.254.169.254/latest/meta-data/) to probe services
// that are not reachable from the public internet.
func Fetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	client := newInsecureClient() // also demonstrates CWE-295
	resp, err := client.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch URL", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, "%s", body)
}

// Redirect sends the browser to a caller-supplied destination.
// CWE-601: Open Redirect — the `to` parameter is forwarded to http.Redirect
// without checking that it stays within the application's own domain.
// An attacker can craft a link like /redirect?to=https://evil.com to abuse
// the site's trusted reputation for phishing.
func Redirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("to")
	http.Redirect(w, r, target, http.StatusFound)
}
