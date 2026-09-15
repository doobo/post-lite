package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"postlite/internal/auth"
	"postlite/internal/config"
	"postlite/internal/crypto"
	"postlite/internal/db"
	"postlite/internal/executor"
	"postlite/internal/httpapi"
	"postlite/internal/repository"
	"postlite/internal/web"
)

func main() {
	var (
		addr       = flag.String("addr", ":5680", "listen address")
		dataDir    = flag.String("data", "./data", "data dir (db, master key, certs)")
		certFile   = flag.String("cert", "", "TLS cert PEM (default: auto self-signed in data dir)")
		keyFile    = flag.String("key", "", "TLS key PEM (default: auto self-signed in data dir)")
		plain      = flag.Bool("plain", false, "run plain HTTP (insecure, dev only)")
		timeout    = flag.Duration("timeout", 60*time.Second, "default execution timeout")
		maxHistory = flag.Int("max-history", 1000, "max history rows to keep")
		masterKey  = flag.String("master-key", "", "vault master key (32B hex/base64); overrides env and file")
		masterKeyF = flag.String("master-key-file", "", "master key file (created if missing)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Error("create data dir", "err", err)
		os.Exit(1)
	}

	sdb, err := db.Open(*dataDir)
	if err != nil {
		log.Error("open db", "err", err)
		os.Exit(1)
	}
	defer sdb.Close()
	store := repository.New(sdb)

	// Master key: --master-key flag > POSTLITE_MASTER_KEY env > file (auto-gen).
	var key []byte
	if *masterKey != "" {
		if key, err = crypto.DecodeMasterKey(*masterKey); err != nil {
			log.Error("master key flag", "err", err)
			os.Exit(1)
		}
	} else if envKey := os.Getenv("POSTLITE_MASTER_KEY"); envKey != "" {
		if key, err = crypto.DecodeMasterKey(envKey); err != nil {
			log.Error("POSTLITE_MASTER_KEY", "err", err)
			os.Exit(1)
		}
	} else {
		mkf := *masterKeyF
		if mkf == "" {
			mkf = filepath.Join(*dataDir, "master.key")
		}
		if key, err = crypto.LoadOrCreateMasterKey(mkf); err != nil {
			log.Error("load master key", "err", err)
			os.Exit(1)
		}
	}
	vlt, err := crypto.New(key)
	if err != nil {
		log.Error("init vault", "err", err)
		os.Exit(1)
	}
	log.Info("vault ready", "key_fingerprint", crypto.KeyFingerprint(key))

	// First start: create the admin account; print the one-time password.
	bootstrapAdmin(store, log)

	cfg := config.Config{
		Addr:         *addr,
		DataDir:      *dataDir,
		Timeout:      *timeout,
		MaxHistory:   *maxHistory,
		SecureCookie: !*plain,
	}

	exec := executor.NewExecutor(cfg.Timeout)
	limiter := auth.NewRateLimiter()
	srv := httpapi.New(store, vlt, exec, cfg, limiter)
	srv.SetLog(log)
	srv.SetAuditFunc(func(actor, action, detail string) {
		line := auth.AuditLine(actor, action, detail)
		log.Info(line)
		if err := store.Settings.AppendAudit(line, 500); err != nil {
			log.Warn("audit store", "err", err)
		}
	})

	// API routes wrapped by the session middleware.
	apiMux := http.NewServeMux()
	registerAPIRoutes(apiMux, srv)
	apiHandler := auth.Middleware(auth.SessionDeps{Sessions: store.Sessions, Users: store.Users})(apiMux)

	mux := http.NewServeMux()
	mux.Handle("/api/", withRecover(apiHandler, log))
	mux.Handle("/", web.Handler())

	if *plain {
		log.Info("starting plain HTTP", "addr", *addr)
		if err := http.ListenAndServe(*addr, withRecover(mux, log)); err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		return
	}

	cf, kf := *certFile, *keyFile
	if cf == "" {
		cf = filepath.Join(*dataDir, "cert.pem")
	}
	if kf == "" {
		kf = filepath.Join(*dataDir, "key.pem")
	}
	if err := ensureCert(cf, kf, log); err != nil {
		log.Error("tls cert", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{Addr: *addr, Handler: withRecover(mux, log)}
	log.Info("starting HTTPS", "addr", *addr, "cert", cf)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	if err := httpSrv.ListenAndServeTLS(cf, kf); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

// registerAPIRoutes mounts the REST API on the mux.
func registerAPIRoutes(mux *http.ServeMux, s *httpapi.Server) {
	// Auth (public).
	mux.HandleFunc("POST /api/auth/login", s.Login)
	mux.HandleFunc("POST /api/auth/logout", s.Logout)
	mux.HandleFunc("GET /api/auth/me", s.Me)

	// Users (admin).
	mux.HandleFunc("GET /api/users", s.ListUsers)
	mux.HandleFunc("POST /api/users", s.CreateUser)
	mux.HandleFunc("DELETE /api/users/{id}", s.DeleteUser)
	mux.HandleFunc("POST /api/users/{id}/disable", s.DisableUser)
	mux.HandleFunc("POST /api/users/{id}/enable", s.EnableUser)
	mux.HandleFunc("POST /api/users/{id}/reset-password", s.ResetUserPassword)

	// Collections.
	mux.HandleFunc("GET /api/collections", s.ListCollections)
	mux.HandleFunc("POST /api/collections", s.CreateCollection)
	mux.HandleFunc("GET /api/collections/{id}", s.GetCollection)
	mux.HandleFunc("PUT /api/collections/{id}", s.UpdateCollection)
	mux.HandleFunc("DELETE /api/collections/{id}", s.DeleteCollection)
	mux.HandleFunc("POST /api/collections/{id}/export", s.ExportCollection)
	mux.HandleFunc("POST /api/collections/import", s.ImportCollection)
	mux.HandleFunc("GET /api/collections/{id}/folders", s.ListFolders)
	mux.HandleFunc("POST /api/collections/{id}/folders", s.CreateFolder)

	// Requests.
	mux.HandleFunc("GET /api/requests", s.ListRequests)
	mux.HandleFunc("POST /api/requests", s.CreateRequest)
	mux.HandleFunc("GET /api/requests/{id}", s.GetRequest)
	mux.HandleFunc("PUT /api/requests/{id}", s.UpdateRequest)
	mux.HandleFunc("DELETE /api/requests/{id}", s.DeleteRequest)

	// Environments.
	mux.HandleFunc("GET /api/environments", s.ListEnvironments)
	mux.HandleFunc("POST /api/environments", s.CreateEnvironment)
	mux.HandleFunc("GET /api/environments/{id}", s.GetEnvironment)
	mux.HandleFunc("PUT /api/environments/{id}", s.UpdateEnvironment)
	mux.HandleFunc("DELETE /api/environments/{id}", s.DeleteEnvironment)
	mux.HandleFunc("POST /api/environments/activate", s.ActivateEnvironment)

	// Secrets (admin, write-only).
	mux.HandleFunc("POST /api/secrets", s.CreateSecret)
	mux.HandleFunc("PUT /api/secrets/{name}", s.UpdateSecret)
	mux.HandleFunc("GET /api/secrets", s.ListSecrets)
	mux.HandleFunc("DELETE /api/secrets/{id}", s.DeleteSecret)

	// Execute + history.
	mux.HandleFunc("POST /api/execute", s.Execute)
	mux.HandleFunc("GET /api/history", s.ListHistory)
	mux.HandleFunc("GET /api/history/{id}", s.GetHistory)
	mux.HandleFunc("DELETE /api/history/{id}", s.DeleteHistory)

	// Settings (admin).
	mux.HandleFunc("GET /api/settings", s.GetSettings)
	mux.HandleFunc("PUT /api/settings", s.PutSettings)
}
