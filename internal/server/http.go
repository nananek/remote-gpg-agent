package server

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	// 認証済みデータをブラウザの HTTP キャッシュに残さない。
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
