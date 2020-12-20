package simplejwt

import (
	"time"

	"gopkg.in/jose.v1/jwt"
)

type CommonClaims interface {
	Has(string) bool
	Get(string) interface{}

	String(string) (string, bool)
	Time(string) (time.Time, bool)
	Bool(string) (bool, bool)

	Audience() ([]string, bool)
	Issuer() (string, bool)
	Subject() (string, bool)
	JWTID() (string, bool)
	Expiration() (time.Time, bool)
	NotBefore() (time.Time, bool)
	IssuedAt() (time.Time, bool)

	Underlying() jwt.Claims
}

type simpleClaims struct {
	jwt.Claims
}

func (sc simpleClaims) String(key string) (string, bool) {
	raw := sc.Claims.Get(key)
	if raw == nil {
		return "", false
	}

	s, ok := raw.(string)
	if !ok {
		return "", false
	}

	return s, true
}

func (sc simpleClaims) Bool(key string) (bool, bool) {
	raw := sc.Claims.Get(key)
	if raw == nil {
		return false, false
	}

	b, ok := raw.(bool)
	if !ok {
		return false, false
	}

	return b, true
}

func (sc simpleClaims) Time(key string) (time.Time, bool) {
	return sc.GetTime(key)
}

func (sc simpleClaims) Underlying() jwt.Claims {
	return sc.Claims
}
