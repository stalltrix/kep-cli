package keygen

import (
    "crypto/ed25519"
    "crypto/rand"
)

func Gen_mainkey() ([]byte,[]byte,error) {
	mainPub, mainPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil,nil,err
    }
	return mainPub,mainPriv,nil
}

func Gen_pkey() ([]byte,[]byte,error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil,nil,err
    }
	return pub, priv, nil
}

func Sig_pkey(pub, mainPriv []byte) []byte {
	 signKey := ed25519.Sign(mainPriv, pub)
	 return signKey
}