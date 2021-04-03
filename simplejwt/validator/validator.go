package validator

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jwt"

	"github.com/falun/simplejwt/simplejwt"
)

// New returns a JWT validator. It can be configured to take a limited set of
// signing methods, see SetAllowedSignatureTypes for details. Token validation
// is handled by SimpleValidate or Validate.
func New() *ValidatorImpl {
	return &ValidatorImpl{}
}

// ValidatorImpl provides
type ValidatorImpl struct {
	allowableSigningMethods map[string]bool
}

// SetAllowedSignatureTypes sets the set of signing methods that can be used
// to validate a SimpleJWT.
func (v *ValidatorImpl) SetAllowedSignatureTypes(methods ...crypto.SigningMethod) {
	v.allowableSigningMethods = map[string]bool{}
	for _, m := range methods {
		v.allowableSigningMethods[m.Alg()] = true
	}
}

type validationKey interface {
	isValidationKey()
}

// KeySharedSecret constructs a symmetric validation key that is a shared
// between the signer and validator.
func KeySharedSecret(pk []byte) validationKey { return sharedSecret{pk} }

// KeyPublicRSA constructs an asymmetric validation key using an RSA PublicKey.
func KeyPublicRSA(ss *rsa.PublicKey) validationKey { return publicKey{ss} }

// KeyPublicECDSA constructs an asymmetric validation key using an ECDSA PublicKey.
func KeyPublicECDSA(pk *ecdsa.PublicKey) validationKey { return publicKey{pk} }

type sharedSecret struct {
	secret []byte
}

func (sharedSecret) isValidationKey() {}

type publicKey struct {
	publicKey interface{}
}

func (publicKey) isValidationKey() {}

// SimpleValidate takes a JWT + validation key (c.f. KeySharedSecret, KeyPublicRSA,
// etc) and verifies the JWT signature using that key. It will also ensure that
// the signing algorithm is one that has been declared acceptable for this JWT.
func (v ValidatorImpl) SimpleValidate(jwt simplejwt.SimpleJWT, vk validationKey) error {
	return v.Validate(jwt, vk)
}

// Validate takes a JWT + validation key and series of validation options.
// Options may or may not be additive, see each option function for details.
func (v ValidatorImpl) Validate(
	token simplejwt.SimpleJWT,
	vk validationKey,
	opts ...validationOption,
) error {
	if err := validateSignatureType(token, v); err != nil {
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

	method, err := token.SigningMethod()
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

	return token.JWT().Validate(key, method, validator)
}

type validationOption interface{ isValidationOption() }

type hasClaims struct {
	claims []string
}

func (hasClaims) isValidationOption() {}

// HasClaims rejects a JWT that does not have the specifed claims defined.
// Multiple has claims are additive and will require the aggregate of all
// provided claim keys. The value of a particular claim is not enforced only
// that the claim is present.
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

// ExpectClaims constructs a JWT validation option that requires the validated
// token to have an explicit set of claim/values.
func ExpectClaims(expected map[string]string) validationOption { return expectClaims{expected} }

func validateSignatureType(sj simplejwt.SimpleJWT, v ValidatorImpl) error {
	method, err := sj.SigningMethod()
	if err != nil {
		return err
	}

	if len(v.allowableSigningMethods) == 0 {
		return nil
	}

	if !v.allowableSigningMethods[method.Alg()] {
		return fmt.Errorf("Disallowed signing algorithm: %v", method.Alg())
	}

	return nil
}
