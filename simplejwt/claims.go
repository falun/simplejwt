package simplejwt

import (
	"fmt"
	"strings"

	"gopkg.in/jose.v1"
)

func (sj *SimpleJWT) RawClaims() map[string]interface{} {
	return sj.parsedJWT.Claims()
}

func (sj *SimpleJWT) HasClaim(key string) bool {
	return sj.parsedJWT.Claims().Has(key)
}

func (sj *SimpleJWT) ClaimStr(key string) (string, bool) {
	raw, ok := sj.parsedJWT.Claims()[key]
	if !ok {
		return "", false
	}

	s, ok := raw.(string)
	if !ok {
		return "", false
	}

	return s, true
}

func (sj *SimpleJWT) ClaimBool(key string) (bool, bool) {
	raw, ok := sj.parsedJWT.Claims()[key]
	if !ok {
		return false, false
	}

	b, ok := raw.(bool)
	if !ok {
		return false, false
	}

	return b, true
}

func (sj *SimpleJWT) Claim(key string) (interface{}, bool) {
	if raw, ok := sj.parsedJWT.Claims()[key]; ok {
		return raw, true
	}

	return nil, false
}

func (sj *SimpleJWT) ClaimJSON() ([]byte, error) {
	base := sj.UnderlyingBytes()
	parts := strings.Split(string(base), ".")
	payload, err := jose.DecodeEscaped([]byte(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("Unable to extract payload from JWT: %v", err.Error())
	}
	return payload, nil
}
