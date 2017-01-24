package main

import (
	basecrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Sign rsa sign
// hashed := md5.Sum(src)
// hashed := sha256.Sum256(src)

func RsaSign(hash basecrypto.Hash, hashed, privateKey []byte) ([]byte, error) {
	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed)
	// return rsa.SignPKCS1v15(rand.Reader, priv, crypto.MD5, hashed[:])
	// return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// Verify rsa verify
// hashed := md5.Sum(src)
// hashed := sha256.Sum256(src)
// signature is a valid signature of message from the public key.
func RsaVerify(hash basecrypto.Hash, hashed, publicKey, signature []byte) bool {

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pub := pubInterface.(*rsa.PublicKey)

	err = rsa.VerifyPKCS1v15(pub, hash, hashed, signature)
	if err != nil {
		return false
	}
	return true
	// return rsa.VerifyPKCS1v15(pub, crypto.MD5, hashed[:], signature)
	// return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}
