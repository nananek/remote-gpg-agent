package server

import (
	"io/fs"
	"net/http"
	"net/url"
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
	return securityHeaders(s.requireSameOrigin(mux))
}

// securityHeaders は承認 UI を埋め込ませないための最低限のヘッダを付ける。
// CSP は index.html の meta と併用される（両方の制約が積み重なる）。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// requireSameOrigin は状態変更 API の CSRF 面を SameSite だけに頼らない。
// ブラウザは POST に Origin を付けるので、設定した PWA の origin と
// 一致しない要求を拒否する。Origin を送らない非ブラウザ利用は通す。
func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, s.cfg.Origin) {
			writeError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
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
