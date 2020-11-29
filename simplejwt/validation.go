package simplejwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// SetAllowedSignatureTypes sets the set of signing methods that can be used
// to validate a SimpleJWT.
func (sj *SimpleJWT) SetAllowedSignatureTypes(methods ...crypto.SigningMethod) {
	sj.allowableSigningMethods = map[string]bool{}
	for _, m := range methods {
		sj.allowableSigningMethods[m.Alg()] = true
	}
}

type validationKey interface {
	isValidationKey()
}

// WithSharedSecret constructs a symmetric validation key that is a shared
// between the signer and validator.
func WithSharedSecret(pk []byte) validationKey { return sharedSecret{pk} }

// WithPublicKeyRSA constructs an asymmetric validation key using an RSA PublicKey.
func WithPublicKeyRSA(ss *rsa.PublicKey) validationKey { return publicKey{ss} }

// WithPublicKeyECDSA constructs an asymmetric validation key using an ECDSA PublicKey.
func WithPublicKeyECDSA(pk *ecdsa.PublicKey) validationKey { return publicKey{pk} }

type sharedSecret struct {
	secret []byte
}

func (sharedSecret) isValidationKey() {}

type publicKey struct {
	publicKey interface{}
}

func (publicKey) isValidationKey() {}

// SimpleValidate takes a validation key (c.f. WithSharedSecret, WithPublicKeyRSA,
// etc) and verifies the JWT signature using that key. It will also ensure that
// the signing algorithm is one that has been declared acceptable for this JWT.
func (sj SimpleJWT) SimpleValidate(vk validationKey) error {
	return sj.Validate(vk)
}

// validate takes a validation key and series of validation options. Options
// may or may not be additive, see each option function for details.
func (sj SimpleJWT) Validate(vk validationKey, opts ...validationOption) error {
	if err := sj.validateSignatureType(); err != nil {
		return fmt.Errorf("Unsuported signature type: %v", err.Error())
	}

	expLeeway := time.Duration(0)
	nbfLeeway := time.Duration(0)
	var matchClaims map[string]interface{}
	validators := []jwt.ValidateFunc{}

	for _, opt := range opts {
		switch t := opt.(type) {
		case leeway:
			expLeeway = t.exp
			nbfLeeway = t.nbf
		case expectClaims:
			if matchClaims == nil {
				matchClaims = map[string]interface{}{}
			}
			for k, v := range t.expected {
				matchClaims[k] = v
			}
		case hasClaims:
			validators = append(validators, t.validator())

		default:
			return fmt.Errorf("Unexpected validation option specified: %T", opt)
		}
	}

	var key interface{}

	switch t := vk.(type) {
	case sharedSecret:
		key = t.secret
	case publicKey:
		key = t.publicKey
	default:
		return fmt.Errorf("Unsupported signing method: %T", vk)
	}

	method, err := sj.getSigningMethod()
	if err != nil {
		return err
	}

	validator := &jwt.Validator{
		Expected: matchClaims,
		EXP:      expLeeway,
		NBF:      nbfLeeway,
	}
	if len(validators) != 0 {
		validator.Fn = func(c jwt.Claims) error {
			for _, fn := range validators {
				if err := fn(c); err != nil {
					return err
				}
			}
			return nil
		}
	}

	return sj.parsedJWT.Validate(key, method, validator)
}

type validationOption interface{ isValidationOption() }

type hasClaims struct {
	claims []string
}

func (hasClaims) isValidationOption() {}

// HasClaims rejects a JWT that does not have the specifed claims defined.
// Multiple has claims are additive and will require the aggregate of all
// specified claim keys.
func HasClaims(claims ...string) validationOption { return hasClaims{claims} }

func (hc hasClaims) validator() jwt.ValidateFunc {
	return func(c jwt.Claims) error {
		missing := []string{}
		for _, cKey := range hc.claims {
			if !c.Has(cKey) {
				missing = append(missing, cKey)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		return fmt.Errorf("Required claims not present: %v", strings.TrimSpace(strings.Join(missing, ", ")))
	}
}

type leeway struct {
	nbf time.Duration
	exp time.Duration
}

func (leeway) isValidationOption() {}

// Leeway indicates how much wiggle room the JWT will be granted between a
// specified NotBefore (nbf) or Expiration (exp) time when it will still be
// considered valid.
//
// If multiple Leeway options are provided only the last will be applied.
func Leeway(nbf, exp time.Duration) validationOption { return leeway{nbf, exp} }

type expectClaims struct{ expected map[string]string }

func (expectClaims) isValidationOption() {}

func ExpectClaims(expected map[string]string) validationOption { return expectClaims{expected} }

func (sj *SimpleJWT) getSigningMethod() (crypto.SigningMethod, error) {
	algInterface, ok := sj.parsedJWS.Protected()["alg"]
	alg, cok := algInterface.(string)
	if !ok || !cok {
		return nil, fmt.Errorf("Could not find signing algorithm in header")
	}

	method := jws.GetSigningMethod(alg)
	if method == nil {
		return nil, fmt.Errorf("Unknown signing algorithm specified: %v", alg)
	}

	return method, nil
}

func (sj *SimpleJWT) validateSignatureType() error {
	method, err := sj.getSigningMethod()
	if err != nil {
		return err
	}

	if len(sj.allowableSigningMethods) == 0 {
		return nil
	}

	if !sj.allowableSigningMethods[method.Alg()] {
		return fmt.Errorf("Disallowed signing algorithm: %v", method.Alg())
	}

	return nil
}
