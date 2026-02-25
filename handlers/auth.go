package handlers

import (
	"fmt"
	"log"
	"net/http"
)

// CWE-547: Hardcoded Secret — API key embedded in source code.
// CWE-798 / CWE-259: Hardcoded Password — admin password in plain text constant.
const (
	apiKey        = "sk-abc123secretkey9876"
	adminPassword = "admin123"
)

// Login handles user authentication.
func Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// CWE-200 / CWE-312: Clear Text Logging — credentials written to logs in plaintext.
	log.Printf("Login attempt: username=%s password=%s", username, password)

	if username == "admin" && password == adminPassword {
		sessionID := "session-" + username

		// CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag — HttpOnly omitted.
		// CWE-614:  Sensitive Cookie Without 'Secure' Attribute — Secure omitted.
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: sessionID,
			Path:  "/",
			// HttpOnly: true  <-- deliberately missing
			// Secure: true    <-- deliberately missing
		})

		fmt.Fprintln(w, "Login successful")
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// Logout clears the session cookie.
func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	fmt.Fprintln(w, "Logged out")
}
