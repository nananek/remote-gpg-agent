package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

type testStack struct {
	server    *Server
	webAddr   string
	clientAddr string
	caPath    string
	clientCert string
	clientKey  string
	cfg       *Config
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeTestCerts(t *testing.T, dir string) (caPath, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rga test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(cn string, usage x509.ExtKeyUsage, dns []string, ips []net.IP) (certPath, keyPath string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     dns,
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPath = filepath.Join(dir, cn+"-cert.pem")
		keyPath = filepath.Join(dir, cn+"-key.pem")
		certOut, _ := os.Create(certPath)
		_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		certOut.Close()
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyOut, _ := os.Create(keyPath)
		_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		keyOut.Close()
		return certPath, keyPath
	}

	caPath = filepath.Join(dir, "ca.pem")
	caOut, _ := os.Create(caPath)
	_ = pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caOut.Close()

	serverCert, serverKey = issue("localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey = issue("test-client", x509.ExtKeyUsageClientAuth, nil, nil)
	return caPath, serverCert, serverKey, clientCert, clientKey
}

func newTestServer(t *testing.T) *testStack {
	t.Helper()
	dir := t.TempDir()
	caPath, serverCert, serverKey, clientCert, clientKey := writeTestCerts(t, dir)

	cfg := &Config{
		DataDir:        dir,
		DBPath:         filepath.Join(dir, "test.db"),
		WebAddr:        "127.0.0.1:0",
		ClientAddr:     "127.0.0.1:0",
		Origin:         "http://localhost:3080",
		RPID:           "localhost",
		RPName:         "remote-gpg-agent-test",
		TLSCert:        serverCert,
		TLSKey:         serverKey,
		TLSCA:          caPath,
		BootstrapToken: "test-bootstrap",
		VAPIDSubject:   "mailto:test@example.com",
		VAPIDPublic:    "test-public",
		VAPIDPrivate:   "test-private",
		PollInterval:   20 * time.Millisecond,
		PollDeadline:   300 * time.Millisecond,
		RequestTTL:     time.Minute,
	}

	srv, err := New(cfg, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	webLn, clientLn, err := srv.listeners()
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.serve(ctx, webLn, clientLn)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		srv.Close()
	})

	return &testStack{
		server:     srv,
		webAddr:    webLn.Addr().String(),
		clientAddr: clientLn.Addr().String(),
		caPath:     caPath,
		clientCert: clientCert,
		clientKey:  clientKey,
		cfg:        cfg,
	}
}

func (h *testStack) caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(h.caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad CA pem")
	}
	return pool
}

func (h *testStack) mtlsClient(t *testing.T) *http.Client {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(h.clientCert, h.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      h.caPool(t),
		Certificates: []tls.Certificate{cert},
	}}}
}

func (h *testStack) plainClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.caPool(t)}}}
}

func (h *testStack) webClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func (h *testStack) clientURL(path string) string   { return "https://" + h.clientAddr + path }
func (h *testStack) webURL(path string) string      { return "http://" + h.webAddr + path }

func (h *testStack) store() *store.Store { return h.server.db }

// テストで共通に使う fingerprint（実在の鍵ではなく形式だけ正しい値）。
const fprForTest = "0123456789ABCDEF0123456789ABCDEF01234567"

func checkPending(h *testStack) ([]*store.Request, error) {
	return store.ListPending(context.Background(), h.server.db)
}

func completeRequestForTest(h *testStack, id, sig string) (bool, error) {
	return store.CompleteRequest(context.Background(), h.server.db, id, sig)
}

// seedKey は credential と鍵（envelope 込み）を直接入れる。mTLS の API は
// 鍵を作らないので、クライアント側のテストにはこれで足りる。
func seedKey(t *testing.T, h *testStack) {
	t.Helper()
	ctx := context.Background()
	if err := store.InsertCredential(ctx, h.server.db, store.CredentialRecord{
		CredentialID: "cred-a", Label: "cred-a", PRFEnabled: true,
		Record: webauthn.Credential{ID: []byte("cred-a"), PublicKey: []byte{1}},
	}); err != nil {
		t.Fatal(err)
	}
	keyID := protocol.KeyIDFromFingerprint(fprForTest)
	if err := store.UpsertKey(ctx, h.server.db,
		protocol.KeyMeta{
			KeyID: keyID, Fingerprint: fprForTest, Label: "personal",
			PublicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----",
		},
		protocol.Envelope{CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "a", IVB64: "b", CiphertextB64: "c"},
	); err != nil {
		t.Fatal(err)
	}
}
