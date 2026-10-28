// Package testcert はテスト用の CA・サーバ証明書・クライアント証明書を作る。
// 本番の証明書は scripts/gen-ca.sh と scripts/issue-client-cert.sh で発行する。
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Files struct {
	CAPath     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// Write は dir に CA と証明書一式を書き出す。サーバ証明書の SAN は
// localhost と 127.0.0.1。
func Write(dir string) (Files, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Files{}, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, err
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
		return Files{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Files{}, err
	}

	files := Files{
		CAPath: filepath.Join(dir, "ca.pem"),
	}
	if err := writePEM(files.CAPath, "CERTIFICATE", caDER); err != nil {
		return Files{}, err
	}

	issue := func(cn string, usage x509.ExtKeyUsage, dns []string, ips []net.IP) (string, string, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", "", err
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
			return "", "", err
		}
		certPath := filepath.Join(dir, cn+"-cert.pem")
		keyPath := filepath.Join(dir, cn+"-key.pem")
		if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
			return "", "", err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", "", err
		}
		if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}

	if files.ServerCert, files.ServerKey, err = issue("localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return Files{}, err
	}
	if files.ClientCert, files.ClientKey, err = issue("test-client", x509.ExtKeyUsageClientAuth, nil, nil); err != nil {
		return Files{}, err
	}
	return files, nil
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
