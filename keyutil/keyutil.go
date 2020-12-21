package keyutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"okcoder.com/jwt-test/testkeys"
)

func RSAPublicKeyFromPEMBytes(b []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to locate RSA public key in PEM block, got %v", block.Type)
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key from PEM block: %v", err.Error())
	}
	return key, nil
}

func RSAPrivateKeyFromPEMBytes(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(testkeys.RSAPrivKey)
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Failed to locate RSA Private key in PEM block, got %v", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key from PEM block: %v", err.Error())
	}

	return key, nil
}

func ECDSAPrivateKeyFromPKCS8Bytes(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("Failed to locate key information")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse encoded private key: %v", err.Error())
	}

	switch t := key.(type) {
	case *ecdsa.PrivateKey:
		return t, nil
	default:
		return nil, fmt.Errorf("Not an ECDSA private key: %T", t)
	}
}

func ECDSAPublicKeyFromPKCS8Bytes(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("Failed to locate key information")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse DER encoded public key: %v", err.Error())
	}

	switch t := key.(type) {
	case *ecdsa.PublicKey:
		return t, nil
	default:
		return nil, fmt.Errorf("Not an ECDSA public key: %T", key)
	}
}
