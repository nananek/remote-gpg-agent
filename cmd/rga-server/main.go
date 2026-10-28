package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"github.com/SherClockHolmes/webpush-go"

	"github.com/nananek/remote-gpg-agent/internal/server"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "vapid":
			priv, pub, err := webpush.GenerateVAPIDKeys()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("RGA_VAPID_PUBLIC=%s\nRGA_VAPID_PRIVATE=%s\n", pub, priv)
			return
		case "healthcheck":
			// distroless には shell も curl も無いので、自分で /healthz を叩く。
			addr := os.Getenv("RGA_WEB_ADDR")
			if addr == "" {
				addr = "127.0.0.1:3080"
			}
			resp, err := http.Get("http://" + addr + "/healthz")
			if err != nil {
				fmt.Fprintln(os.Stderr, "healthcheck:", err)
				os.Exit(1)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
				os.Exit(1)
			}
			return
		}
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := server.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	srv, err := server.New(cfg, log)
	if err != nil {
		log.Error("startup", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Info("listening", "web", cfg.WebAddr, "client", cfg.ClientAddr)
	if err := srv.Run(ctx); err != nil {
		log.Error("run", "err", err)
		os.Exit(1)
	}
}
