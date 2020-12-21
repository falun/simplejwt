package simplejwt

import (
	"fmt"
	"strings"

	"gopkg.in/jose.v1"
	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

func init() {
	// by default don't support validation unsigned tokens
	jws.RemoveSigningMethod(crypto.Unsecured)
}

func MustParse(b []byte) *SimpleJWT {
	token, err := FromBytes(b)
	if err != nil {
		panic(err)
	}
	return token
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

// SimpleJWT is a container for the necessary config / state parsed from a
// potential token. It should only be constructed via FromBytes.
type SimpleJWT struct {
	underlying              []byte
	parsedJWS               jws.JWS
	parsedJWT               jwt.JWT
	allowableSigningMethods map[string]bool
}

// UnderlyingBytes return the unmodified bytes used to construct the SimpleJWT.
func (sj *SimpleJWT) UnderlyingBytes() []byte { return sj.underlying }

// JWS returns the underlying JWS model used by simplejwt.
func (sj *SimpleJWT) JWS() jws.JWS { return sj.parsedJWS }

// JWT returns the underlying JWT model used by simplejwt.
func (sj *SimpleJWT) JWT() jwt.JWT { return sj.parsedJWT }

func (sj *SimpleJWT) SigningMethod() (crypto.SigningMethod, error) {
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

func (sj *SimpleJWT) Claims() CommonClaims {
	return simpleClaims{sj.parsedJWT.Claims()}
}

// ClaimsJSON returns the JSON string of all claims presented in the JWT.
func (sj *SimpleJWT) ClaimsJSON() ([]byte, error) {
	base := sj.UnderlyingBytes()
	parts := strings.Split(string(base), ".")
	payload, err := jose.DecodeEscaped([]byte(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("Unable to extract payload from JWT: %v", err.Error())
	}
	return payload, nil
}
