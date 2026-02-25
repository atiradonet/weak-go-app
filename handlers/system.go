package handlers

import (
	"fmt"
	"net/http"
	"os/exec"
)

// Exec runs a shell command supplied by the caller.
// CWE-78: Command Injection — the `cmd` parameter is passed verbatim to
// `sh -c`, so an attacker can chain arbitrary commands with ; & | etc.
func Exec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		// CWE-209: Generation of Error Message Containing Sensitive Information
		// — the raw error and captured output (which may include stack traces,
		// file paths, or secret environment variables) are returned to the client.
		http.Error(w,
			fmt.Sprintf("Command failed: %v — output: %s", err, out),
			http.StatusInternalServerError,
		)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

// Report fetches an internal report and returns it to the caller.
// CWE-209: Sensitive Information in Error Messages — on failure the handler
// echoes the raw database error and the caller-supplied ID back in the HTTP
// response body, leaking internal implementation details.
func Report(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	data, err := fetchInternalReport(id)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Internal database error: %v — failed for report ID: %s", err, id),
			http.StatusInternalServerError,
		)
		return
	}
	fmt.Fprintln(w, data)
}

func fetchInternalReport(id string) (string, error) {
	return "Report data for " + id, nil
}
