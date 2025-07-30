package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alissonbk/kk-service-auth-lib/types"
	"github.com/golang-jwt/jwt/v5"
)

// PublicKey can be one of each:
// PublicKeyPath: path to a .pem file with the public key (will take current working dir as start point) (should start with /) example: /keys/pub.pem
// PublicKeyString: a string containg the public key (file headers excluded for this)
// PublicKeyFileBytes: the []byte from a file which has the key (formatted with the header)
type PublicKey struct {
	PublicKeyPath      string
	PublicKeyString    string
	PublicKeyFileBytes []byte
}

func (pk *PublicKey) validatePublicKey() error {
	if pk.PublicKeyPath == "" && pk.PublicKeyString == "" && pk.PublicKeyFileBytes == nil {
		return fmt.Errorf("the PublicKey struct must contain 1 valid value to retrieve the public key correctly.")
	}

	return nil
}

// publicKeyPath is the path containing the .pem file with the keycloak public key example: "/certs/public.pem"
func AuthRequired(pk *PublicKey) types.HandlerFunc {
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

		publicKey, err := getPublicKey(pk)
		if err != nil {
			fmt.Fprint(os.Stderr, err.Error())
			c.JSON(http.StatusUnauthorized, map[string]string{"message": "failed to validate token"})
			c.Abort()
		}

		if isTokenValid, err := validateToken(token, publicKey); err != nil || !isTokenValid {
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

func validateToken(token string, publicKey *rsa.PublicKey) (bool, error) {

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

func getPublicKeyContentFromFilePath(filePath string) ([]byte, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to read current working dir, cause: %s", err)
	}

	return os.ReadFile(wd + filePath)
}

// pkString: a string containing the public key without the header
func getPublicKeyContentFromString(pkString string) []byte {
	str := "-----BEGIN PUBLIC KEY-----\r\n" + pkString + "\r\n-----END PUBLIC KEY-----"
	return []byte(str)
}

func getPublicKey(pk *PublicKey) (*rsa.PublicKey, error) {
	err := pk.validatePublicKey()
	if err != nil {
		return nil, err
	}

	var content []byte
	if pk.PublicKeyFileBytes != nil {
		content = pk.PublicKeyFileBytes
	} else if strings.Trim(pk.PublicKeyString, " ") != "" {
		content = getPublicKeyContentFromString(pk.PublicKeyString)
	} else if strings.Trim(pk.PublicKeyPath, " ") != "" {
		c, err := getPublicKeyContentFromFilePath(pk.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key content from file path, cause: %s", err)
		}
		content = c
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rsa from content %s, cause: %s", hex.EncodeToString(content), err)
	}

	return key, nil
}
