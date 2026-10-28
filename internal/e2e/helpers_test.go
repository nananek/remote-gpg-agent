package e2e

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/hkdf"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/nananek/remote-gpg-agent/internal/client"
	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/server"
	"github.com/nananek/remote-gpg-agent/internal/store"
	"github.com/nananek/remote-gpg-agent/internal/testcert"
)

const wrapInfo = "remote-gpg-agent:v1:vault-wrap"

type stack struct {
	srv           *server.Server
	webAddr       string
	clientAddr    string
	certs         testcert.Files
	cfg           *server.Config
	fingerprint   string
	publicArmored string
	sessionID     string
	envelope      protocol.Envelope
	prf           []byte
	secretArmored string
}

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func startStack(t *testing.T) *stack {
	t.Helper()
	dir := t.TempDir()
	certs, err := testcert.Write(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &server.Config{
		DataDir: dir, DBPath: filepath.Join(dir, "e2e.db"),
		WebAddr: "127.0.0.1:0", ClientAddr: "127.0.0.1:0",
		Origin: "http://localhost:3080", RPID: "localhost", RPName: "rga-e2e",
		TLSCert: certs.ServerCert, TLSKey: certs.ServerKey, TLSCA: certs.CAPath,
		BootstrapToken: "e2e-bootstrap",
		VAPIDSubject:   "mailto:e2e@example.com", VAPIDPublic: "pub", VAPIDPrivate: "priv",
		PollInterval: 20 * time.Millisecond, PollDeadline: 2 * time.Second, RequestTTL: time.Minute,
	}
	srv, err := server.New(cfg, silent())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); srv.Close() })
	webAddr, clientAddr, err := srv.ListenAndServe(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 偽 PWA が持つ鍵（Go の openpgp で作る。curve25519 の互換性は fixture テストで見る）。
	ent, err := openpgp.NewEntity("E2E User", "", "e2e@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	secretArmored := armorPrivate(t, ent)
	publicArmored := armorPublic(t, ent)
	fpr := strings.ToUpper(fmt.Sprintf("%X", ent.PrimaryKey.Fingerprint))
	prf := make([]byte, 32)
	_, _ = rand.Read(prf)

	ctxDB := context.Background()
	credID := "e2e-cred"
	if err := store.InsertCredential(ctxDB, srv.DB(), store.CredentialRecord{
		CredentialID: credID, Label: "e2e", PRFEnabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	envelope, err := sealEnvelope(secretArmored, prf, fpr)
	if err != nil {
		t.Fatal(err)
	}
	envelope.CredentialID = credID
	envelope.KeyID = protocol.KeyIDFromFingerprint(fpr)
	if err := store.UpsertKey(ctxDB, srv.DB(), protocol.KeyMeta{
		KeyID: envelope.KeyID, Fingerprint: fpr, Label: "e2e", PublicKeyArmored: publicArmored,
	}, envelope); err != nil {
		t.Fatal(err)
	}
	sid, err := store.CreateSession(ctxDB, srv.DB(), credID)
	if err != nil {
		t.Fatal(err)
	}

	return &stack{
		srv: srv, webAddr: webAddr, clientAddr: clientAddr, certs: certs, cfg: cfg,
		fingerprint: fpr, publicArmored: publicArmored, sessionID: sid,
		envelope: envelope, prf: prf, secretArmored: secretArmored,
	}
}

func (s *stack) clientConfig(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"url":                   "https://" + s.clientAddr,
		"caCert":                s.certs.CAPath,
		"clientCert":            s.certs.ClientCert,
		"clientKey":             s.certs.ClientKey,
		"defaultKeyFingerprint": s.fingerprint,
		"timeoutSec":            20,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func armorPrivate(t *testing.T, ent *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.String()
}

func armorPublic(t *testing.T, ent *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.String()
}

func sealEnvelope(secretArmored string, prf []byte, fingerprint string) (protocol.Envelope, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return protocol.Envelope{}, err
	}
	key, err := hkdf.Key(sha256.New, prf, salt, wrapInfo, 32)
	if err != nil {
		return protocol.Envelope{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return protocol.Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return protocol.Envelope{}, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return protocol.Envelope{}, err
	}
	payload, _ := json.Marshal(map[string]string{"secret": secretArmored, "revocation": ""})
	ct := gcm.Seal(nil, iv, payload, []byte(fingerprint))
	return protocol.Envelope{
		HKDFSaltB64:   base64.StdEncoding.EncodeToString(salt),
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func openEnvelope(env protocol.Envelope, prf []byte, fingerprint string) (string, error) {
	salt, err := base64.StdEncoding.DecodeString(env.HKDFSaltB64)
	if err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, prf, salt, wrapInfo, 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(env.IVB64)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(env.CiphertextB64)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, ct, []byte(fingerprint))
	if err != nil {
		return "", err
	}
	var payload struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(plain, &payload); err != nil {
		return "", err
	}
	return payload.Secret, nil
}

// autoApprove は偽 PWA。pending を拾って署名し、/sign に投げる。
func (s *stack) autoApprove(t *testing.T, ctx context.Context) {
	t.Helper()
	secret, err := openEnvelope(s.envelope, s.prf, s.fingerprint)
	if err != nil {
		t.Errorf("envelope を開けません: %v", err)
		return
	}
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(secret))
	if err != nil {
		t.Errorf("秘密鍵を読めません: %v", err)
		return
	}
	sign := func(data []byte) (string, error) {
		var buf bytes.Buffer
		if err := openpgp.ArmoredDetachSign(&buf, el[0], bytes.NewReader(data), nil); err != nil {
			return "", err
		}
		return buf.String(), nil
	}

	base := "http://" + s.webAddr
	client := &http.Client{Timeout: 5 * time.Second}

	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/requests?status=pending", nil)
		req.Header.Set("cookie", "rga_session="+s.sessionID)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var list struct {
			Requests []protocol.PendingSignRequest `json:"requests"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&list)
		resp.Body.Close()

		for _, r := range list.Requests {
			data, err := base64.StdEncoding.DecodeString(r.DataB64)
			if err != nil {
				continue
			}
			sig, err := sign(data)
			if err != nil {
				t.Errorf("署名できません: %v", err)
				continue
			}
			body, _ := json.Marshal(map[string]string{"signatureArmored": sig})
			post, _ := http.NewRequestWithContext(ctx, "POST", base+"/api/v1/requests/"+r.ID+"/sign", bytes.NewReader(body))
			post.Header.Set("cookie", "rga_session="+s.sessionID)
			post.Header.Set("content-type", "application/json")
			if pr, err := client.Do(post); err == nil {
				pr.Body.Close()
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s が無いのでスキップ（ホストで実行してください）", name)
	}
}

func gpgEnv(t *testing.T) (string, []string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "gnupg")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return home, append(os.Environ(), "GNUPGHOME="+home)
}

func run(t *testing.T, env []string, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func execCommand(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }

// mustConfig はスタックに繋ぐクライアント設定を読み込む（RGA_CONFIG 経由）。
func mustConfig(t *testing.T, s *stack) *client.Config {
	t.Helper()
	path := s.clientConfig(t)
	t.Setenv("RGA_CONFIG", path)
	cfg, err := client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
