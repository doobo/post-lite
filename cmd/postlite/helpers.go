package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"postlite/internal/auth"
	"postlite/internal/repository"
)

// bootstrapAdmin creates the initial admin account on first start and prints
// its one-time password.
func bootstrapAdmin(store *repository.Store, log *slog.Logger) {
	n, err := store.Users.Count()
	if err != nil {
		log.Error("count users", "err", err)
		return
	}
	if n > 0 {
		return
	}
	pwd, err := auth.RandomPassword(16)
	if err != nil {
		log.Error("generate admin password", "err", err)
		return
	}
	hash, salt, err := auth.HashPassword(pwd)
	if err != nil {
		log.Error("hash admin password", "err", err)
		return
	}
	id, err := store.Users.Create("admin", "admin", salt, hash)
	if err != nil {
		log.Error("create admin user", "err", err)
		return
	}
	msg := fmt.Sprintf("first start: created admin user (id=%d) with one-time password: %s", id, pwd)
	log.Info(msg)
	fmt.Fprintln(os.Stderr, "  "+msg)
	fmt.Fprintln(os.Stderr, "  change it after first login (Users -> reset-password).")
}

// ensureCert generates a self-signed server certificate (ECDSA P-256) when the
// cert/key files do not exist yet. CN=postlite, SAN: localhost, 127.0.0.1, ::1.
func ensureCert(certFile, keyFile string, log *slog.Logger) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(1_000_000_000))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "postlite", Organization: []string{"postlite"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "postlite"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return err
	}
	log.Info("generated self-signed certificate", "cert", certFile, "key", keyFile)
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// withRecover turns panics into 500s and logs them.
func withRecover(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				log.Error("panic recovered", "value", fmt.Sprint(p), "path", r.URL.Path)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
