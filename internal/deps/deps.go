//go:build tools

// Package deps pins the modules that the real packages will import, so that
// `go mod vendor` keeps them in vendor/ before any code exists. The VM used for
// implementation has no network, so the build must work from vendor/ alone.
//
// Storage is bbolt (pure Go, ~2MB) rather than modernc.org/sqlite: the latter
// vendors 129MB of generated C bindings (modernc.org/libc + sqlite), which is
// not worth committing to keep an offline build working.
//
// This file is excluded from normal builds by the `tools` tag.
package deps

import (
	_ "github.com/ProtonMail/go-crypto/openpgp"
	_ "github.com/SherClockHolmes/webpush-go"
	_ "github.com/go-webauthn/webauthn/webauthn"
	_ "go.etcd.io/bbolt"
)
