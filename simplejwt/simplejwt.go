package simplejwt

import (
	"fmt"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// type SimpleJWT interface {
// 	UnderlyingBytes() []byte
// }

func init() {
	// by default don't support validation unsigned tokens
	jws.RemoveSigningMethod(crypto.Unsecured)
}

func FromBytes(b []byte) (*SimpleJWT, error) {
	s := &SimpleJWT{
		underlying: b,
	}

	jwsToken, err := jws.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err.Error())
	}

	jwtToken, err := jws.ParseJWT(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err.Error())
	}

	s.parsedJWS = jwsToken
	s.parsedJWT = jwtToken

	return s, nil
}

type SimpleJWT struct {
	underlying              []byte
	parsedJWS               jws.JWS
	parsedJWT               jwt.JWT
	allowableSigningMethods map[string]bool
}

// UnderlyingBytes return the unmodified bytes used to construct the SimpleJWT.
func (sj *SimpleJWT) UnderlyingBytes() []byte { return sj.underlying }
func (sj *SimpleJWT) JWS() jws.JWS            { return sj.parsedJWS }
func (sj *SimpleJWT) JWT() jwt.JWT            { return sj.parsedJWT }
