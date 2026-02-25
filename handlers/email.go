package handlers

import (
	"fmt"
	"net/http"
	"net/smtp"
)

// SendEmail sends a message using fields supplied by the caller.
// CWE-284: Improper Access Control / Email Content Injection — the `to`,
// `subject`, and `body` parameters are embedded directly in raw SMTP headers
// without sanitisation. An attacker can inject newline characters (\r\n) to
// add arbitrary headers (e.g. Bcc, CC) or alter the message body, turning the
// server into an open mail relay.
func SendEmail(w http.ResponseWriter, r *http.Request) {
	to := r.FormValue("to")
	subject := r.FormValue("subject")
	body := r.FormValue("body")

	message := []byte(
		"From: noreply@app.com\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n\r\n" +
			body,
	)

	auth := smtp.PlainAuth("", "noreply@app.com", "smtp-password", "mail.example.com")
	err := smtp.SendMail(
		"mail.example.com:587",
		auth,
		"noreply@app.com",
		[]string{to},
		message,
	)
	if err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Email sent")
}
