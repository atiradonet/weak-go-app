package handlers

import (
	"fmt"
	"net/http"

	"github.com/tidwall/gjson"
)

// simulatedStore mimics a JSON payload that would normally come from a
// database or an upstream service. It intentionally contains sensitive
// fields (password hashes, API secrets) to demonstrate data exposure when
// a caller can supply an arbitrary gjson path.
const simulatedStore = `{
  "users": [
    {"id": 1, "username": "admin",  "email": "admin@example.com",  "role": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    {"id": 2, "username": "alice",  "email": "alice@example.com",   "role": "user",  "password_hash": "482c811da5d5b4bc6d497ffa98491e38"}
  ],
  "config": {
    "db_password": "prod-db-pass-2024",
    "api_secret":  "sk-prod-9876xyzabc"
  }
}`

// QueryJSON extracts a value from the internal JSON store using a
// caller-supplied gjson path expression.
//
// CVE-2020-36067: tidwall/gjson < v1.6.4 panics on an integer overflow
// triggered by a crafted path string, enabling remote denial-of-service.
//
// CWE-20: Improper Input Validation — the `path` parameter is passed
// directly to gjson.Get without any allow-listing or sanitisation, so an
// attacker can traverse to sensitive fields such as:
//   ?path=config.db_password
//   ?path=users.0.password_hash
//
// The crafted overflow path that triggers CVE-2020-36067 looks like:
//   ?path=a[99999999999999999999999999]
func QueryJSON(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")

	// User-controlled path passed directly — triggers CVE-2020-36067 on
	// vulnerable gjson versions and leaks arbitrary fields to the caller.
	result := gjson.Get(simulatedStore, path)

	fmt.Fprintf(w, "Result: %s\n", result.String())
}
