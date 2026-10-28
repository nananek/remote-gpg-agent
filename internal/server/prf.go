package server

import "crypto/sha256"

// PRFSalt は envelope の封印鍵を導く PRF 入力。**変更禁止**
// （変えると既存の鍵が全部開かなくなる）。
var PRFSalt = func() []byte {
	sum := sha256.Sum256([]byte("remote-gpg-agent:v1:prf"))
	return sum[:]
}()
