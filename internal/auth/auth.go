package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort = errors.New("password must be at least 12 characters")
)

// HashAdminPassword hashes an administrator password using bcrypt.
func HashAdminPassword(password string, minLen int) (string, error) {
	if len(password) < minLen {
		return "", ErrPasswordTooShort
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckAdminPassword verifies a plaintext password against a bcrypt hash.
func CheckAdminPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashAccessKey creates a fast keyed HMAC-SHA256 hash using the server pepper.
// Extremely lightweight (<0.01ms CPU, 0 MB RAM) to prevent CPU starvation attacks.
func HashAccessKey(pepper, password string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(password))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAccessKey compares candidate password HMAC against stored hash in constant time.
func VerifyAccessKey(pepper, candidatePassword, storedHash string) bool {
	candidateHash := HashAccessKey(pepper, candidatePassword)
	return subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1
}

// GenerateRandomToken generates cryptographically secure hex tokens.
func GenerateRandomToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken generates a SHA256 hex hash of an opaque token for database lookups.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateBootstrapToken creates a 32-character hex bootstrap token.
func GenerateBootstrapToken() (string, error) {
	return GenerateRandomToken(16) // 16 bytes = 32 hex chars
}
