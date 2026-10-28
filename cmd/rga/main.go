// rga は remote-gpg-agent のクライアント。
//
//	rga ping                      接続確認
//	rga sign                      stdin を署名して stdout に armored 署名
//	rga gpg-compat <gpg args>     git / makepkg の gpg 互換モード
//	rga keys                      サーバにある鍵の一覧
//	rga public-key <fpr>          armored 公開鍵を stdout へ
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/client"
	"github.com/nananek/remote-gpg-agent/internal/pgpverify"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rga <ping|sign|gpg-compat|keys|public-key>")
	os.Exit(64)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	cfg, err := client.LoadConfig()
	if err != nil {
		fail(err)
	}
	c, err := client.New(cfg)
	if err != nil {
		fail(err)
	}

	switch cmd {
	case "ping":
		var out map[string]any
		if err := c.Do("GET", "/healthz", nil, &out); err != nil {
			fail(err)
		}
		raw, _ := json.Marshal(out)
		fmt.Println(string(raw))

	case "keys":
		var out struct {
			Keys []struct {
				KeyID       string `json:"keyId"`
				Fingerprint string `json:"fingerprint"`
				Label       string `json:"label"`
			} `json:"keys"`
		}
		if err := c.Do("GET", "/api/v1/keys", nil, &out); err != nil {
			fail(err)
		}
		if len(out.Keys) == 0 {
			fmt.Println("鍵がまだありません。PWA で作成してください。")
			return
		}
		for _, k := range out.Keys {
			fmt.Printf("%-16s %s\n", k.Label, k.Fingerprint)
		}

	case "public-key":
		ref := ""
		if len(args) > 0 {
			ref = args[0]
		}
		fpr, err := client.ResolveFingerprint(c, ref, cfg.DefaultKeyFingerprint)
		if err != nil {
			fail(err)
		}
		var out struct {
			PublicKeyArmored string `json:"publicKeyArmored"`
		}
		if err := c.Do("GET", "/api/v1/keys/"+fpr, nil, &out); err != nil {
			fail(err)
		}
		fmt.Print(out.PublicKeyArmored)

	case "sign":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail(err)
		}
		fpr, err := client.ResolveFingerprint(c, "", cfg.DefaultKeyFingerprint)
		if err != nil {
			fail(err)
		}
		sig, err := client.RequestSignature(context.Background(), c, client.SignInput{
			Purpose: "sign", Description: description(), Fingerprint: fpr,
			Data: data, Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		})
		if err != nil {
			fail(err)
		}
		if err := verify(c, fpr, data, sig); err != nil {
			fail(err)
		}
		fmt.Print(ensureNL(sig))

	case "gpg-compat":
		inv := client.ParseGpgArgs(args)
		// gpg.program には --verify なども飛んでくる。署名以外は本物の gpg に投げる。
		if !inv.Detach {
			os.Exit(delegateToRealGPG(args))
		}
		data, err := readInput(inv.File)
		if err != nil {
			fail(err)
		}
		fpr, err := client.ResolveFingerprint(c, inv.LocalUser, cfg.DefaultKeyFingerprint)
		if err != nil {
			fail(err)
		}
		sig, err := client.RequestSignature(context.Background(), c, client.SignInput{
			Purpose: purposeFor(inv), Description: description(), Fingerprint: fpr,
			Data: data, Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		})
		if err != nil {
			fail(err)
		}
		if err := verify(c, fpr, data, sig); err != nil {
			fail(err)
		}
		if inv.StatusSet {
			writeStatus(inv.StatusFD, fpr)
		}
		// gpg は `--detach-sign <file>` のとき <file>.sig を書く（stdout には出さない）。
		// makepkg はこの .sig を探すので、ファイル入力のときは同じ場所に書く。
		if inv.File != "" {
			if err := os.WriteFile(inv.File+".sig", []byte(ensureNL(sig)), 0o644); err != nil {
				fail(err)
			}
			return
		}
		fmt.Print(ensureNL(sig))

	default:
		usage()
	}
}

func description() string {
	if d := os.Getenv("RGA_DESCRIPTION"); d != "" {
		return d
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "rga"
	}
	return cwd
}

func purposeFor(inv client.GpgInvocation) string {
	if inv.File != "" && strings.HasSuffix(inv.File, ".zst") {
		return "makepkg"
	}
	return "git-commit"
}

func readInput(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func verify(c *client.Client, fpr string, data []byte, sig string) error {
	var out struct {
		PublicKeyArmored string `json:"publicKeyArmored"`
	}
	if err := c.Do("GET", "/api/v1/keys/"+fpr, nil, &out); err != nil {
		return err
	}
	if out.PublicKeyArmored == "" {
		return fmt.Errorf("サーバが公開鍵を返しませんでした")
	}
	return pgpverify.ArmoredDetached(out.PublicKeyArmored, fpr, data, sig)
}

func writeStatus(fd int, fpr string) {
	line := fmt.Sprintf("[GNUPG:] SIG_CREATED D 1 8 00 %d %s\n", time.Now().Unix(), fpr)
	f := os.NewFile(uintptr(fd), "status-fd")
	if f == nil {
		return
	}
	_, _ = f.WriteString(line)
}

func ensureNL(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// delegateToRealGPG は `gpg` と同じ引数・同じ標準入出力で本物の gpg を動かし、終了コードをそのまま返す。
// これがないと `git log --show-signature`（gpg --verify）が壊れる。
func delegateToRealGPG(args []string) int {
	real := os.Getenv("REAL_GPG")
	if real == "" {
		real = "/usr/bin/gpg"
	}
	cmd := exec.Command(real, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "rga: %v\n", err)
		return 1
	}
	return 0
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "rga: %v\n", err)
	os.Exit(1)
}
