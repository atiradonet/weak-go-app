package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// jwtSecret is the hardcoded signing key.
// CWE-798: Hardcoded credential used as a JWT signing secret.
var jwtSecret = []byte("secret")

// GenerateJWT creates a signed JWT for the given username.
// Uses github.com/dgrijalva/jwt-go v3.2.0, which is affected by
// CVE-2020-26160: the library does not validate the `aud` claim when
// ParseWithClaims is called with MapClaims, allowing audience bypass.
func GenerateJWT(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	claims := jwt.MapClaims{
		"sub": username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		// No `aud` claim set — combined with CVE-2020-26160, callers can
		// forge tokens that pass audience validation on the server side.
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Token generation error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, signed)
}

// ValidateJWT parses and validates a JWT supplied in the `token` query parameter.
//
// CVE-2020-26160: dgrijalva/jwt-go does not validate the `aud` claim when
// MapClaims is used, so a token without an audience passes validation.
//
// CWE-345: Insufficient Verification of Data Authenticity — jwt.Parse does not
// restrict the allowed signing algorithm. An attacker can craft a token with
// alg=none; the key function still returns jwtSecret but the library accepts
// an empty signature, effectively bypassing signature verification.
func ValidateJWT(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")

	// No algorithm pinning: accepts HS256, RS256, *and* none.
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		// CWE-209: error message leaks internal detail about token structure.
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Fprintf(w, "Valid token for user: %v\n", claims["sub"])
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
