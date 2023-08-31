package main

import (
	"crypto/rand"
	"encoding/base64"
)

func generateRandomSecretKey(length int) (string, error) {
	// Generate a random byte slice
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Convert the byte slice to a base64-encoded string
	secretKey := base64.URLEncoding.EncodeToString(randomBytes)
	return secretKey, nil
}

var SecretKey, err = generateRandomSecretKey(32)
