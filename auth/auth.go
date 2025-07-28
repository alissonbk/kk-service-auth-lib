package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alissonbk/kk-service-auth-lib/types"
	"github.com/golang-jwt/jwt/v5"
)

// publicKeyPath is the path containing the .pem file with the keycloak public key example: "/certs/public.pem"
func AuthRequired(publicKeyPath string) types.HandlerFunc {
	return func(c types.ContextWithHeader) {
		authHeader := c.GetHeader("Authorization")
		split := strings.Split(authHeader, " ")
		if len(split) != 2 {
			c.JSON(http.StatusUnauthorized, map[string]string{"message": "could not find token in the header"})
			c.Abort()
			return
		}
		token := split[1]
		if split[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, map[string]string{"message": "not a Bearer token"})
			c.Abort()
			return
		}

		if isTokenValid, err := validateToken(token, publicKeyPath); err != nil || !isTokenValid {
			if err != nil {
				fmt.Fprint(os.Stderr, err.Error())
			}
			c.JSON(http.StatusUnauthorized, map[string]string{"message": "failed to validate token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func validateToken(token string, publicKeyPath string) (bool, error) {
	publicKey, err := getPublicKey(publicKeyPath)
	if err != nil {
		return false, err
	}

	parts, err := validateTokenExpiration(token)
	if err != nil {
		return false, err
	}
	if len(parts) < 3 {
		return false, errors.New("token invalid, it must have 3 parts")
	}

	signingString := strings.Join(parts[0:2], ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("failed to decode signature from the token, cause: %s", err)
	}

	err = jwt.SigningMethodRS256.Verify(signingString, sig, publicKey)
	if err != nil {
		return false, err
	}

	return true, nil
}

func validateTokenExpiration(token string) (parts []string, err error) {
	claims := &jwt.MapClaims{}
	parsedToken, parts, err := new(jwt.Parser).ParseUnverified(token, claims)
	if err != nil {
		return nil, err
	}

	exp, err := parsedToken.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	if exp.Before(time.Now()) {
		return nil, errors.New("token is expired")
	}

	return parts, nil
}

func getPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to read current working dir, cause: %s", err)
	}

	pemContent, err := os.ReadFile(wd + publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read .pem file, cause: %s", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(pemContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rsa from .pem, cause: %s", err)
	}

	return key, nil
}
