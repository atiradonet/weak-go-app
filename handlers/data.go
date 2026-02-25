package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/antchfx/xmlquery"

	"weak-go-app/db"
)

// GetUser fetches a user record by ID.
// CWE-89: SQL Injection — user-supplied `id` is concatenated directly into
// the query string instead of using a parameterised query ($1 placeholder).
func GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT id, username, email FROM users WHERE id = " + id
	rows, err := db.DB.Query(query)
	if err != nil {
		http.Error(w, "Query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var uid, username, email string
		if err := rows.Scan(&uid, &username, &email); err != nil {
			continue
		}
		fmt.Fprintf(w, "User: %s %s %s\n", uid, username, email)
	}
}

// Search returns an HTML page reflecting the user's search query.
// CWE-79: Cross-site Scripting (XSS) — the query parameter is written
// directly into the HTML response without escaping, allowing script injection.
func Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Search results for: %s</h1></body></html>", q)
}

// QueryXML queries an XML document using a user-supplied XPath expression.
// CWE-643: XPath Injection — the username parameter is concatenated directly
// into the XPath expression, allowing logic manipulation (e.g. ' or '1'='1).
func QueryXML(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	xmlData := `<?xml version="1.0"?>
<users>
  <user name="admin" role="administrator" password="secret"/>
  <user name="guest" role="viewer" password="guest123"/>
</users>`

	doc, err := xmlquery.Parse(strings.NewReader(xmlData))
	if err != nil {
		http.Error(w, "XML parse error", http.StatusInternalServerError)
		return
	}

	// Unsanitised user input concatenated directly into the XPath expression.
	xpath := "/users/user[@name='" + username + "']"
	nodes := xmlquery.Find(doc, xpath)
	for _, node := range nodes {
		fmt.Fprintln(w, node.OutputXML(true))
	}
}
