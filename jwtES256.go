package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type customClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

// GenerateJWT generates token string
func GenerateJWT() (tokenString string, err error) {
	// Create the Claims
	claims := customClaims{
		UserID: "user1",
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute * 60).Unix(),
		},
	}

	// Create token object with claims and ES256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Read the private key file
	key, err := ioutil.ReadFile("ec256-private.pem")
	if err != nil {
		fmt.Println("Error in reading private key")
		return "", err
	}

	// Parse private key into ecdsaKey
	var ecdsaKey *ecdsa.PrivateKey
	if ecdsaKey, err = jwt.ParseECPrivateKeyFromPEM(key); err != nil {
		fmt.Println("Unable to parse ECDSA private key:", err.Error())
		return "", err
	}

	// use ecdsaKey to create the signed token
	tokenString, err = token.SignedString(ecdsaKey)
	if err != nil {
		fmt.Println("SignedString failed with error", err.Error())
		return "", err
	}

	return tokenString, err
}

// ParseJWT parses JWT token
func ParseJWT(tokenString string) (bool, error) {

	// Parse Unverified parses just claims parts and does not verify the signature part
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &customClaims{})
	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(*customClaims); ok {
		fmt.Println("User ID:", claims.UserID)
	} else {
		fmt.Println("Error in custom claims")
		return false, err
	}

	key, err := ioutil.ReadFile("ec256-public.pem")
	if err != nil {
		fmt.Println("Error in reading public key")
		return false, err
	}

	var ecdsaKey *ecdsa.PublicKey
	if ecdsaKey, err = jwt.ParseECPublicKeyFromPEM(key); err != nil {
		fmt.Printf("Unable to parse ECDSA public key: %v", err)
		return false, err
	}

	parts := strings.Split(tokenString, ".")
	method := jwt.GetSigningMethod("ES256")
	err = method.Verify(strings.Join(parts[0:2], "."), parts[2], ecdsaKey)
	if err != nil {
		fmt.Printf("Error while verifying key: %v", err)
		return false, err
	}
	return true, nil
}

func main() {
	token, err := GenerateJWT()
	if err != nil {
		fmt.Println("Error in GenerateJWT", err.Error())
		return
	}
	fmt.Println("The token:", token)

	if success, err := ParseJWT(token); success == true {
		fmt.Println("Success in parsing")
	} else {
		fmt.Println("Error in parsing", err.Error())
		return
	}
}
