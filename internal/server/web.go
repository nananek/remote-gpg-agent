package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/nananek/remote-gpg-agent/internal/store"
	webdist "github.com/nananek/remote-gpg-agent/web"
)

func (s *Server) webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "web"})
	})
	mux.HandleFunc("GET /api/v1/push/vapid-public-key", s.handleVapidPublicKey)
	mux.HandleFunc("POST /api/v1/push/subscribe", s.handleSubscribe)
	s.registerAuthRoutes(mux)
	s.registerVaultRoutes(mux)
	s.registerPwaRequestRoutes(mux)

	dist, err := fs.Sub(webdist.FS, "dist")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(dist)))
	return mux
}

// sessionCredential はクッキーから credentialID を引く。
func (s *Server) sessionCredential(r *http.Request) (string, error) {
	c, err := r.Cookie(store.SessionCookie)
	if err != nil {
		return "", store.ErrNoSession
	}
	return store.SessionCredential(r.Context(), s.db, c.Value)
}

func (s *Server) cookieSecure() bool {
	return strings.HasPrefix(s.cfg.Origin, "https://")
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: store.SessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure(),
		MaxAge: 7 * 24 * 3600,
	})
}

// clearSessionCookie はログアウト時にセッションクッキーを失効させる。
// 属性は setSessionCookie と揃える（Secure を含む）。
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: store.SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cookieSecure(),
	})
}
