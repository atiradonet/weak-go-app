package handlers

import (
	"crypto/des"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	mathrand "math/rand" // CWE-330: math/rand is not cryptographically secure
	"net/http"
)

// Hash hashes a password using MD5.
// CWE-916: MD5 has insufficient computational effort for password storage.
// CWE-327: MD5 is a broken cryptographic algorithm.
func Hash(w http.ResponseWriter, r *http.Request) {
	password := r.URL.Query().Get("password")
	hash := md5.Sum([]byte(password))
	fmt.Fprintf(w, "Hash: %x", hash)
}

// Encrypt encrypts data using DES.
// CWE-327: DES is a broken/risky cryptographic algorithm (56-bit key, deprecated).
func Encrypt(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	key := []byte("8bytekey")
	block, err := des.NewCipher(key)
	if err != nil {
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}
	padded := make([]byte, 8)
	copy(padded, []byte(data))
	ciphertext := make([]byte, 8)
	block.Encrypt(ciphertext, padded)
	fmt.Fprintf(w, "Encrypted: %x", ciphertext)
}

// GenerateToken creates a session token using a weak random source.
// CWE-330: Use of Insufficiently Random Values — math/rand is seeded predictably
// and must never be used for security-sensitive values like tokens.
func GenerateToken(w http.ResponseWriter, r *http.Request) {
	token := fmt.Sprintf("%d", mathrand.Int63())
	fmt.Fprintf(w, "Token: %s", token)
}

// GenerateKey generates an RSA key pair.
// CWE-326: Inadequate Encryption Strength — 512-bit RSA is far below the
// 2048-bit minimum recommended by NIST.
func GenerateKey(w http.ResponseWriter, r *http.Request) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 512)
	if err != nil {
		http.Error(w, "Key generation error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Generated RSA key of size: %d bits", privateKey.N.BitLen())
}

// newInsecureClient returns an HTTP client that skips TLS certificate verification.
// CWE-295: Improper Certificate Validation — InsecureSkipVerify disables all
// certificate and hostname checks, allowing MITM attacks.
func newInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
