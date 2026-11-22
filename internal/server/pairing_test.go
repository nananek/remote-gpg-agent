package server

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/cryptoutil"
	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func pairIDs() (string, string) {
	return cryptoutil.B64URL(bytes.Repeat([]byte{0x11}, protocol.PairingIDBytes)),
		cryptoutil.B64URL(bytes.Repeat([]byte{0x22}, protocol.PairingProofBytes))
}

func TestPairCreateRequiresSession(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)
	id, proof := pairIDs()
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestPairCreateValidatesShapes(t *testing.T) {
	h := newTestServer(t)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)
	_, proof := pairIDs()

	resp, _ := pwaPost(t, c, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": "short", "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short pairingId must be rejected, got %d", resp.StatusCode)
	}
}

func TestPairJoinRejectsWrongProofAndExpiredPairing(t *testing.T) {
	h := newTestServer(t)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)
	id, proof := pairIDs()
	if resp, _ := pwaPost(t, c, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create failed: %d", resp.StatusCode)
	}

	j := h.pwaClient(t)
	otherProof := cryptoutil.B64URL(bytes.Repeat([]byte{0x33}, protocol.PairingProofBytes))
	resp, _ := pwaPost(t, j, h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": id, "joinProof": otherProof}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong proof must be 403, got %d", resp.StatusCode)
	}

	// 期限切れは存在しないのと同じ扱いにする。
	expiredID := cryptoutil.B64URL(bytes.Repeat([]byte{0x44}, protocol.PairingIDBytes))
	if _, err := store.CreatePairing(context.Background(), h.server.DB(), expiredID, "cred-a", proof, -time.Minute); err != nil {
		t.Fatal(err)
	}
	resp, _ = pwaPost(t, j, h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": expiredID, "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expired pairing must be rejected, got %d", resp.StatusCode)
	}
}

func TestPairFlowRegistersJoinerAndCarriesReceipt(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-join"), prfEnabled: true}

	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	creator := h.pwaClient(t)
	setCookie(t, creator, h, sid)

	id, proof := pairIDs()
	resp, body := pwaPost(t, creator, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %v", resp.StatusCode, body)
	}

	joiner := h.pwaClient(t)
	resp, body = pwaPost(t, joiner, h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("join: %d %v", resp.StatusCode, body)
	}
	ceremonyID, _ := body["ceremonyId"].(string)

	resp, body = pwaPost(t, joiner, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-join"},
		"label":      "Android",
		"envelopes":  []any{},
		"pairingId":  id,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pairing verify: %d %v", resp.StatusCode, body)
	}
	joinerCred, _ := body["credentialId"].(string)
	if joinerCred == "" {
		t.Fatalf("missing credentialId: %v", body)
	}

	_, status := pwaGet(t, creator, h.webURL("/api/v1/pair/"+id))
	if status["state"] != protocol.PairingJoined {
		t.Fatalf("state = %v, want joined", status["state"])
	}
	if status["joinerCredentialId"] != joinerCred || status["joinerLabel"] != "Android" {
		t.Fatalf("unexpected status: %v", status)
	}

	offer := cryptoutil.B64URL([]byte("v=0\r\n"))
	resp, _ = pwaPost(t, creator, h.webURL("/api/v1/pair/"+id+"/signal"),
		map[string]string{"kind": protocol.PairingSignalOffer, "blob": offer}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("creator signal: %d", resp.StatusCode)
	}
	_, signals := pwaGet(t, joiner, h.webURL("/api/v1/pair/"+id+"/signal?after=0"))
	list, _ := signals["signals"].([]any)
	if len(list) != 1 {
		t.Fatalf("joiner must see the offer: %v", signals)
	}
	first, _ := list[0].(map[string]any)
	if first["from"] != "creator" || first["kind"] != protocol.PairingSignalOffer {
		t.Fatalf("unexpected signal: %v", first)
	}

	resp, _ = pwaPost(t, joiner, h.webURL("/api/v1/pair/"+id+"/signal"),
		map[string]string{"kind": protocol.PairingSignalAnswer, "blob": offer}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("joiner signal: %d", resp.StatusCode)
	}

	// 当事者以外はシグナリングに触れない。
	thirdSid, err := createSessionFor(t, h, "cred-third")
	if err != nil {
		t.Fatal(err)
	}
	third := h.pwaClient(t)
	setCookie(t, third, h, thirdSid)
	resp, _ = pwaPost(t, third, h.webURL("/api/v1/pair/"+id+"/signal"),
		map[string]string{"kind": protocol.PairingSignalOffer, "blob": offer}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("third party must be rejected, got %d", resp.StatusCode)
	}

	// 受領書は参加側だけが書ける。
	resp, _ = pwaPost(t, creator, h.webURL("/api/v1/pair/"+id+"/complete"),
		map[string]string{"receipt": "forged"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("creator must not complete, got %d", resp.StatusCode)
	}
	resp, _ = pwaPost(t, joiner, h.webURL("/api/v1/pair/"+id+"/complete"),
		map[string]string{"receipt": "receipt-v1"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete: %d", resp.StatusCode)
	}
	_, status = pwaGet(t, creator, h.webURL("/api/v1/pair/"+id))
	if status["state"] != protocol.PairingDelivered || status["receipt"] != "receipt-v1" {
		t.Fatalf("receipt must reach the creator: %v", status)
	}

	// 2 台目は入れない。
	resp, _ = pwaPost(t, h.pwaClient(t), h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second join must be 409, got %d", resp.StatusCode)
	}
}

func TestPairSignalRejectsUnknownKindAndLargeBlob(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-join"), prfEnabled: true}
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	creator := h.pwaClient(t)
	setCookie(t, creator, h, sid)
	id, proof := pairIDs()
	if resp, _ := pwaPost(t, creator, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatal("create failed")
	}
	joiner := h.pwaClient(t)
	_, body := pwaPost(t, joiner, h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	ceremonyID, _ := body["ceremonyId"].(string)
	if resp, _ := pwaPost(t, joiner, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID, "response": map[string]any{"id": "cred-join"},
		"envelopes": []any{}, "pairingId": id,
	}, nil); resp.StatusCode != http.StatusOK {
		t.Fatal("verify failed")
	}

	resp, _ := pwaPost(t, creator, h.webURL("/api/v1/pair/"+id+"/signal"),
		map[string]string{"kind": "exec", "blob": cryptoutil.B64URL([]byte("x"))}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown kind must be 400, got %d", resp.StatusCode)
	}
	big := cryptoutil.B64URL([]byte(strings.Repeat("x", protocol.MaxPairingSignalBytes+1)))
	resp, _ = pwaPost(t, creator, h.webURL("/api/v1/pair/"+id+"/signal"),
		map[string]string{"kind": protocol.PairingSignalCandidate, "blob": big}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized blob must be 400, got %d", resp.StatusCode)
	}
}

func TestPairRejectsNonPRFAuthenticator(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-join"), prfEnabled: false}
	sid, _ := createSessionFor(t, h, "cred-a")
	creator := h.pwaClient(t)
	setCookie(t, creator, h, sid)
	id, proof := pairIDs()
	pwaPost(t, creator, h.webURL("/api/v1/pair/create"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)

	joiner := h.pwaClient(t)
	_, body := pwaPost(t, joiner, h.webURL("/api/v1/pair/join"),
		map[string]string{"pairingId": id, "joinProof": proof}, nil)
	ceremonyID, _ := body["ceremonyId"].(string)
	resp, _ := pwaPost(t, joiner, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID, "response": map[string]any{"id": "cred-join"},
		"envelopes": []any{}, "pairingId": id,
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PRF-less authenticator must be rejected, got %d", resp.StatusCode)
	}
	if n := len(mustListCredentials(t, h)); n != 1 {
		t.Fatalf("joiner credential must not be stored, got %d", n)
	}
}
