package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/client"
	"github.com/nananek/remote-gpg-agent/internal/pgpverify"
)

// ブラウザ側（OpenPGP.js v6 / curve25519Legacy）が作った署名を、本物の gpg が
// 受け入れることを固定する。fixture は web/scripts/gen-openpgp-fixture.mjs で生成。
func TestOpenPGPJSFixtureVerifiesWithGPG(t *testing.T) {
	requireBinary(t, "gpg")

	pub, err := os.ReadFile("testdata/openpgpjs-public.asc")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/openpgpjs-data.bin")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/openpgpjs-data.asc")
	if err != nil {
		t.Fatal(err)
	}
	fprRaw, err := os.ReadFile("testdata/openpgpjs-fingerprint.txt")
	if err != nil {
		t.Fatal(err)
	}
	fpr := strings.TrimSpace(string(fprRaw))

	// まず自前の検証器で通ること
	if err := pgpverify.ArmoredDetached(string(pub), fpr, data, string(sig)); err != nil {
		t.Fatalf("pgpverify: %v", err)
	}

	// 次に本物の gpg で通ること
	home, env := gpgEnv(t)
	run(t, env, "", "gpg", "--batch", "--import", "testdata/openpgpjs-public.asc")
	out := run(t, env, "", "gpg", "--batch", "--status-fd=1",
		"--verify", "testdata/openpgpjs-data.asc", "testdata/openpgpjs-data.bin")
	if !strings.Contains(out, "[GNUPG:] GOODSIG") {
		t.Fatalf("gpg did not accept the OpenPGP.js signature (GNUPGHOME=%s):\n%s", home, out)
	}
}

// 署名ループ全体: mTLS クライアント → 要求 → 偽 PWA が署名 → クライアントが検証 → gpg が GOODSIG。
func TestSignLoopProducesGPGVerifiableSignature(t *testing.T) {
	requireBinary(t, "gpg")
	s := startStack(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go s.autoApprove(t, ctx)

	c, err := client.New(mustConfig(t, s))
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("tree 0000000000000000000000000000000000000000\n\nmsg\n")
	sig, err := client.RequestSignature(ctx, c, client.SignInput{
		Purpose: "git-commit", Description: "e2e", Fingerprint: s.fingerprint,
		Data: data, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	home := filepath.Join(dir, "gnupg")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GNUPGHOME="+home)
	pubPath := filepath.Join(dir, "pub.asc")
	if err := os.WriteFile(pubPath, []byte(s.publicArmored), 0o600); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dir, "data")
	sigPath := filepath.Join(dir, "data.asc")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}

	run(t, env, "", "gpg", "--batch", "--import", pubPath)
	out := run(t, env, "", "gpg", "--batch", "--status-fd=1", "--verify", sigPath, dataPath)
	if !strings.Contains(out, "[GNUPG:] GOODSIG") {
		t.Fatalf("gpg rejected the signature:\n%s", out)
	}
}

// git commit 相当: gpg.program に rga を挿し、--show-signature が通ることを見る。
func TestGitCommitWithRemoteSigning(t *testing.T) {
	requireBinary(t, "git")
	requireBinary(t, "gpg")
	s := startStack(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go s.autoApprove(t, ctx)

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	build := execCommand("go", "build", "-mod=vendor", "-o", filepath.Join(bin, "rga"), "./cmd/rga")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("rga をビルドできません: %v\n%s", err, out)
	}

	wrapper := filepath.Join(bin, "rga-gpg-sign")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+filepath.Join(bin, "rga")+" gpg-compat \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	home := filepath.Join(dir, "gnupg")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"GNUPGHOME="+home,
		"RGA_CONFIG="+s.clientConfig(t),
		"PATH="+bin+":"+os.Getenv("PATH"),
		// gpg のメッセージを英語に固定する（"Good signature" を検査するため）
		"LC_ALL=C",
		"LANG=C",
	)

	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, env, "", "git", "init", "-q", "-b", "main", repo)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, env, repo, "git", "config", "user.email", "e2e@example.com")
	run(t, env, repo, "git", "config", "user.name", "e2e")
	run(t, env, repo, "git", "config", "gpg.program", wrapper)
	run(t, env, repo, "git", "config", "user.signingkey", s.fingerprint)
	run(t, env, repo, "git", "add", "a.txt")
	run(t, env, repo, "git", "commit", "-q", "-S", "-m", "signed commit")

	// 検証表示のため公開鍵を gpg の keyring に入れる
	pubPath := filepath.Join(dir, "pub.asc")
	if err := os.WriteFile(pubPath, []byte(s.publicArmored), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, env, "", "gpg", "--batch", "--import", pubPath)

	log := run(t, env, repo, "git", "log", "--show-signature", "-1")
	if !strings.Contains(log, "Good signature") {
		t.Fatalf("git did not verify the commit:\n%s", log)
	}
}
