package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"weak-go-app/db"
	"weak-go-app/handlers"
)

func main() {
	db.Init()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlers.Login)
	mux.HandleFunc("/logout", handlers.Logout)
	mux.HandleFunc("/user", handlers.GetUser)
	mux.HandleFunc("/search", handlers.Search)
	mux.HandleFunc("/file", handlers.ServeFile)
	mux.HandleFunc("/template", handlers.RenderTemplate)
	mux.HandleFunc("/exec", handlers.Exec)
	mux.HandleFunc("/report", handlers.Report)
	mux.HandleFunc("/fetch", handlers.Fetch)
	mux.HandleFunc("/redirect", handlers.Redirect)
	mux.HandleFunc("/hash", handlers.Hash)
	mux.HandleFunc("/encrypt", handlers.Encrypt)
	mux.HandleFunc("/token", handlers.GenerateToken)
	mux.HandleFunc("/key", handlers.GenerateKey)
	mux.HandleFunc("/email", handlers.SendEmail)
	mux.HandleFunc("/xml", handlers.QueryXML)
	mux.HandleFunc("/jwt-generate", handlers.GenerateJWT)
	mux.HandleFunc("/jwt-validate", handlers.ValidateJWT)
	mux.HandleFunc("/config", handlers.ParseConfig)
	mux.HandleFunc("/json", handlers.QueryJSON)

	// CWE-327: Insecure TLS Configuration
	// MinVersion set to TLS 1.0 (deprecated) and weak cipher suites included.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("Starting weak-go-app on :8443")
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
