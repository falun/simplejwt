package simplejwt

import (
	"fmt"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

// JWTSigner is an interface that enables producing JWT style signed tokens.
type JWTSigner interface {
	// Sign produces a signed byte array based on the provided attributes.
	Sign(map[string]interface{}) ([]byte, error)

	// SignWithClaims produces a signed byte array based on the provided claims.
	SignWithClaims(jws.Claims) ([]byte, error)
}

// Signer produces a JWTSigner for a given key and method. If a signer could
// not be constructed an error is returned.
func Signer(method crypto.SigningMethod, key interface{}) (JWTSigner, error) {
	return SignerWithCommonClaims(method, key, nil)
}

// SignerWithCommonClaims produces a JWTSigner for a given key and method.
// Additionally when each set of payload/claims are signed a function will
// be called allowing modification to the claims being attested.
//
// If a signer can not be constructed an error is returned.
func SignerWithCommonClaims(
	method crypto.SigningMethod,
	key interface{},
	applyCommonClaims func(jws.Claims) (jws.Claims, error),
) (JWTSigner, error) {
	// attempt to sign trash just to ensure the key is valid
	_, err := method.Sign([]byte("aoeu"), key)
	if err != nil {
		return nil, fmt.Errorf("Error validate key: %v", err.Error())
	}
	return signer{method, key, applyCommonClaims}, nil
}

type signer struct {
	method        crypto.SigningMethod
	key           interface{}
	commonClaimFn func(jws.Claims) (jws.Claims, error)
}

// Sign implements JWTSigner interface.
func (s signer) Sign(payload map[string]interface{}) ([]byte, error) {
	return s.SignWithClaims(jws.Claims(payload))
}

// SignWithClaims implements JWTSigner interface.
func (s signer) SignWithClaims(claims jws.Claims) ([]byte, error) {
	if s.commonClaimFn != nil {
		newClaims, err := s.commonClaimFn(claims)
		if err != nil {
			return nil, fmt.Errorf("Unable to apply common claims: %v", err.Error())
		}
		claims = newClaims
	}

	jwt := jws.NewJWT(claims, s.method)
	signed, err := jwt.Serialize(s.key)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign JWT: %v", err.Error())
	}
	return signed, nil
}
