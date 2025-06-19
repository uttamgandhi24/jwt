package main

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type customClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateJWT generates token string
func GenerateJWT() (tokenString string, err error) {
	// Create the Claims
	claims := customClaims{
		UserID: "user1",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
		},
	}

	// Create token object with claims and ES256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Read the private key file
	key, err := os.ReadFile("ec256-private.pem")
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

	key, err := os.ReadFile("ec256-public.pem")
	if err != nil {
		fmt.Println("Error in reading public key")
		return false, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseECPublicKeyFromPEM(key)
	})
	if err != nil {
		fmt.Println("Error in parsing JWT:", err.Error())
		return false, err
	} else if claims, ok := token.Claims.(*customClaims); ok && token.Valid {
		fmt.Println("User ID:", claims.UserID)
	} else {
		fmt.Println("Error in custom claims or token is invalid")
		return false, fmt.Errorf("invalid token")
	}
	if !token.Valid {
		fmt.Println("Token is invalid")
		return false, fmt.Errorf("invalid token")
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
