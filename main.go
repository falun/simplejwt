package main

import (
	"fmt"
	"log"
	"time"

	"okcoder.com/jwt-test/keyutil"
	"okcoder.com/jwt-test/simplejwt"
	"okcoder.com/jwt-test/simplejwt/signer"
	"okcoder.com/jwt-test/simplejwt/validator"
	"okcoder.com/jwt-test/testkeys"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

func main() {
	isValid := func(err error) {
		if err != nil {
			fmt.Printf("Failed to validate token: %v\n", err)
		} else {
			fmt.Printf("Token was valid\n")
		}
	}

	rsaPrivKey, err := keyutil.RSAPrivateKeyFromPEMBytes(testkeys.RSAPrivKey)
	if err != nil {
		log.Fatalf("Unable to load private key: %v", err.Error())
	}

	rsaSigner, err := signer.NewWithCommonClaims(
		crypto.SigningMethodRS384,
		rsaPrivKey,
		func(in jws.Claims) (jws.Claims, error) {
			in.SetIssuer("simplejwt-main")
			in.SetIssuedAt(time.Now())
			in.Set("user", "falun")
			return in, nil
		},
	)
	if err != nil {
		panic(err)
	}

	b, err := rsaSigner.Sign(nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%v\n", string(b))

	token, err := simplejwt.FromBytes(b)
	if err != nil {
		panic(err)
	}

	rsaPubKey, err := keyutil.RSAPublicKeyFromPEMBytes(testkeys.RSAPubKey)
	if err != nil {
		log.Fatal(err)
	}

	v := validator.New()

	err = v.Validate(
		*token,
		validator.KeyPublicRSA(rsaPubKey),
		validator.HasClaims("roles", "user", "user_id"),
	)
	isValid(err)

	claimBytes, _ := token.ClaimsJSON()
	fmt.Printf("claims: %v\n", string(claimBytes))

	token = simplejwt.MustParse(testkeys.RSA512Token)
	err = v.Validate(*token, validator.KeyPublicRSA(rsaPubKey))
	claimBytes, _ = token.ClaimsJSON()
	fmt.Printf("%v\n", string(claimBytes))
	isValid(err)

	fmt.Printf("\n\n\n")

	t := simplejwt.MustParse([]byte(`eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN`))
	cb, _ := t.ClaimsJSON()
	fmt.Printf("claims: %v\n", string(cb))

	// ugh. https://github.com/SermoDigital/jose/issues/40
	// Not worth fixing for now; maybe return when I'm bored
	ecdsaPubKey := []byte(`-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----`)

	k, e := keyutil.ECDSAPublicKeyFromPKCS8Bytes(ecdsaPubKey)
	if e != nil {
		log.Fatal(e)
	}

	e = v.Validate(*t, validator.KeyPublicECDSA(k))
	isValid(e)
}
