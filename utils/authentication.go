package utils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"

	"mytselapp-new/config"
)

func Authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Missing token"})
		}

		// Extract the token by removing the "Bearer " prefix
		token = strings.TrimPrefix(token, "Bearer ")

		// Parse the token
		claims := jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			// Replace with your actual secret key used for signing the tokens
			return []byte(config.SecretKey), nil
		})
		fmt.Println("Token String:", token)
		fmt.Println("Parsed Token:", parsedToken.Valid)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Invalid token"})
		}
		// Extract the user_id from claims
		userID, ok := claims["user_id"].(float64)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "user_id not found in token"})
		}

		// Set the user_id in the context
		c.Set("user_id", int(userID))
		// Check expiration
		if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Token has expired"})
		}

		// If the token is valid, call the next handler
		return next(c)
	}
}

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateAuthToken(userId uint) (string, error) {
	// Create a new token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims (payload)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userId
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expiration time (1 day)

	// Sign the token with a secret key
	secretKey := []byte(config.SecretKey)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	// Token validation
	claimed := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claimed, func(token *jwt.Token) (interface{}, error) {
		// Replace with your actual secret key used for signing the tokens
		return []byte(config.SecretKey), nil
	})

	if err != nil {
		fmt.Println("Token validation error:", err)
	}

	fmt.Println("Parsed Token:", parsedToken.Valid)
	fmt.Println("Token String:", tokenString)

	return tokenString, nil
}
