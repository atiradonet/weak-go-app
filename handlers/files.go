package handlers

import (
	"fmt"
	"net/http"
	"os"
	"text/template"
)

// ServeFile reads and returns a file from the data directory.
// CWE-23: Path Traversal — the `file` parameter is appended to the base path
// without sanitisation, allowing an attacker to escape the directory with
// sequences like `../../etc/passwd`.
func ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := os.ReadFile("/var/app/data/" + filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s", data)
}

// RenderTemplate parses and executes a Go template supplied by the caller.
// CWE-96: Improper Neutralisation of Directives in Statically Saved Code
// (Server-Side Template Injection) — the `template` parameter is used as the
// template source. An attacker can inject template directives such as
// {{.}} to leak data, or use `text/template` actions to call arbitrary
// functions exposed in the data map.
func RenderTemplate(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.URL.Query().Get("template")
	name := r.URL.Query().Get("name")

	// text/template does not auto-escape; user-controlled template string
	// is parsed and executed directly.
	tmpl, err := template.New("user").Parse(tmplStr)
	if err != nil {
		http.Error(w, "Template parse error", http.StatusBadRequest)
		return
	}
	tmpl.Execute(w, map[string]string{"Name": name, "Secret": "db-password-leaked"})
}
