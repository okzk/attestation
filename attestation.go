package attestation

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"regexp"
)

func keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	x5c, ok := token.Header["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return nil, fmt.Errorf("missing certification")
	}

	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, raw := range x5c {
		rawStr, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("missing certification")
		}
		cert, err := parseCert(rawStr)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		DNSName:       "attest.android.com",
		Intermediates: intermediates,
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return nil, err
	}

	rsaKey, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid certification")
	}
	return rsaKey, nil
}

// Parse validates SafetyNet Attestation API response JWS and returns claims.
func Parse(jws string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(jws, keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

var base64TrimRegexp = regexp.MustCompile("[^a-zA-Z0-9+/=]]")

func parseCert(raw string) (*x509.Certificate, error) {
	rawBuf, err := base64.StdEncoding.DecodeString(base64TrimRegexp.ReplaceAllString(raw, ""))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(rawBuf)
}
