package server

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnAPI は go-webauthn の典礼をテストで差し替えられるようにする最小の面。
// *webauthn.WebAuthn がそのまま満たす。
type webAuthnAPI interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, r *http.Request) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishLogin(user webauthn.User, session webauthn.SessionData, r *http.Request) (*webauthn.Credential, error)
}
