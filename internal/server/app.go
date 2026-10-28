package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nananek/remote-gpg-agent/internal/store"
)

type Server struct {
	cfg   *Config
	db    *store.Store
	wa    webAuthnAPI
	log   *slog.Logger
	vapid vapidKeys
}

func New(cfg *Config, log *slog.Logger) (*Server, error) {
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Server{
		cfg: cfg, db: db, wa: wa, log: log,
		vapid: vapidKeys{subject: cfg.VAPIDSubject, public: cfg.VAPIDPublic, private: cfg.VAPIDPrivate},
	}, nil
}

func (s *Server) Close() error { return s.db.Close() }

// DB はテストやデモが直接データを仕込むためのアクセサ。
func (s *Server) DB() *store.Store { return s.db }

// ListenAndServe は 2 つの listener を bind し、実際のアドレスを返してから serve する。
// テストやデモから使う（Run はこれと serve をまとめただけ）。
func (s *Server) ListenAndServe(ctx context.Context) (webAddr, clientAddr string, err error) {
	webLn, clientLn, err := s.listeners()
	if err != nil {
		return "", "", err
	}
	go func() { _ = s.serve(ctx, webLn, clientLn) }()
	return webLn.Addr().String(), clientLn.Addr().String(), nil
}

// Run は PWA 用（http）とクライアント用（mTLS）の 2 つの listener を同時に動かす。
func (s *Server) Run(ctx context.Context) error {
	webLn, clientLn, err := s.listeners()
	if err != nil {
		return err
	}
	return s.serve(ctx, webLn, clientLn)
}

func (s *Server) listeners() (net.Listener, net.Listener, error) {
	webLn, err := net.Listen("tcp", s.cfg.WebAddr)
	if err != nil {
		return nil, nil, err
	}
	clientLn, err := net.Listen("tcp", s.cfg.ClientAddr)
	if err != nil {
		webLn.Close()
		return nil, nil, err
	}
	return webLn, clientLn, nil
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	pem, err := os.ReadFile(s.cfg.TLSCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("RGA_TLS_CA is not a valid PEM bundle")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// serve は既に bind 済みの listener で 2 つのサーバを動かす（テストから使う）。
func (s *Server) serve(ctx context.Context, webLn, clientLn net.Listener) error {
	tlsCfg, err := s.tlsConfig()
	if err != nil {
		webLn.Close()
		clientLn.Close()
		return err
	}

	webSrv := &http.Server{Handler: s.webHandler(), ReadHeaderTimeout: 10 * time.Second}
	clientSrv := &http.Server{Handler: s.clientHandler(), ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 2)
	go func() { errCh <- webSrv.Serve(webLn) }()
	go func() { errCh <- clientSrv.Serve(tls.NewListener(clientLn, tlsCfg)) }()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = webSrv.Shutdown(shutCtx)
		_ = clientSrv.Shutdown(shutCtx)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}
