package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"okcoder.com/jwt-test/simplejwt"
	"okcoder.com/jwt-test/testkeys"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

func main() {
	block, _ := pem.Decode(testkeys.RSAPrivKey)
	if block.Type != "RSA PRIVATE KEY" {
		log.Fatal("failed to load private key")
	}

	rsaPrivKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// rsaPrivKey, cok := pub.(*rsa.PrivateKey)
	if err != nil {
		log.Fatalf("Unable to load private key: %v", err.Error())
	}

	rsaSigner, err := simplejwt.SignerWithCommonClaims(
		crypto.SigningMethodRS384,
		rsaPrivKey,
		func(in jws.Claims) (jws.Claims, error) {
			in.SetIssuer("simplejwt-main")
			in.SetIssuedAt(time.Now())
			return in, nil
		},
	)
	if err != nil {
		panic(err)
	}

	b, err := rsaSigner.Sign(map[string]interface{}{
		"roles":   []string{"admin", "db_org"},
		"admin":   true,
		"user":    "falun",
		"user_id": 1312,
	})

	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", string(b))

	token, err := simplejwt.FromBytes(b)
	if err != nil {
		panic(err)
	}

	block, _ = pem.Decode(testkeys.RSAPubKey)
	if block.Type != "RSA PUBLIC KEY" {
		log.Fatal("Failed to load public key")
	}

	rsaPubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	err = token.Validate(
		simplejwt.WithPublicKeyRSA(rsaPubKey),
		simplejwt.HasClaims("roles", "user", "user_id"),
	)
	if err != nil {
		fmt.Printf("Failed to validate token: %v\n", err)
	} else {
		fmt.Printf("Token was valid\n")
	}

	claimBytes, _ := token.ClaimJSON()
	fmt.Printf("claims: %v\n", string(claimBytes))
}
