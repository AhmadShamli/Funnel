package auth

import (
	"testing"
	"time"
)

func TestAuthPrimitives(t *testing.T) {
	pepper := "secret-pepper-key"
	password := "visitor-pass-123"

	// 1. Access key HMAC hashing
	hash1 := HashAccessKey(pepper, password)
	hash2 := HashAccessKey(pepper, password)
	if hash1 != hash2 {
		t.Fatalf("hashes should match")
	}

	if !VerifyAccessKey(pepper, password, hash1) {
		t.Fatalf("VerifyAccessKey should succeed for correct password")
	}

	if VerifyAccessKey(pepper, "wrong-password", hash1) {
		t.Fatalf("VerifyAccessKey should fail for incorrect password")
	}

	// 2. Admin password bcrypt hashing
	adminPw := "secure-admin-pass-123"
	adminHash, err := HashAdminPassword(adminPw, 12)
	if err != nil {
		t.Fatalf("HashAdminPassword failed: %v", err)
	}

	if !CheckAdminPassword(adminHash, adminPw) {
		t.Fatalf("CheckAdminPassword should succeed for correct password")
	}

	if CheckAdminPassword(adminHash, "wrong-pass") {
		t.Fatalf("CheckAdminPassword should fail for wrong password")
	}

	// Password too short
	if _, err := HashAdminPassword("short", 12); err != ErrPasswordTooShort {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}

	// 3. Tokens
	token, err := GenerateRandomToken(16)
	if err != nil || len(token) != 32 {
		t.Fatalf("GenerateRandomToken failed: %v, len: %d", err, len(token))
	}

	tokenHash := HashToken(token)
	if len(tokenHash) != 64 {
		t.Fatalf("HashToken expected 64 hex chars, got %d", len(tokenHash))
	}
}

func TestRateLimiterLevel1(t *testing.T) {
	rl := NewRateLimiter(5, 60*time.Second, 5, 5*time.Minute, 15*time.Minute)
	ip := "198.51.100.1"
	now := time.Now()

	// 4 failures should not block
	for i := 0; i < 4; i++ {
		rl.RecordVisitorFailure(ip, now)
		res := rl.CheckVisitor(ip, now)
		if res.Blocked {
			t.Fatalf("attempt %d should not be blocked", i+1)
		}
	}

	// 5th failure should trigger Level 1 block
	rl.RecordVisitorFailure(ip, now)
	res := rl.CheckVisitor(ip, now)
	if !res.Blocked || res.Level != 1 {
		t.Fatalf("expected Level 1 block after 5 failures, got %+v", res)
	}

	// Different IP should NOT be blocked
	res2 := rl.CheckVisitor("198.51.100.2", now)
	if res2.Blocked {
		t.Fatalf("distinct IP should not be blocked under Level 1")
	}

	// After block expiry
	future := now.Add(35 * time.Second)
	resExpired := rl.CheckVisitor(ip, future)
	if resExpired.Blocked {
		t.Fatalf("IP should be unblocked after delay")
	}
}

func TestRateLimiterLevel2CircuitBreaker(t *testing.T) {
	rl := NewRateLimiter(5, 60*time.Second, 3, 5*time.Minute, 15*time.Minute)
	now := time.Now()

	// 3 distinct IPs fail
	rl.RecordVisitorFailure("10.0.0.1", now)
	rl.RecordVisitorFailure("10.0.0.2", now)
	tripped := rl.RecordVisitorFailure("10.0.0.3", now)

	if !tripped {
		t.Fatalf("circuit breaker should have tripped on 3rd distinct IP")
	}

	// Any IP is now blocked under Level 2
	res := rl.CheckVisitor("10.0.0.99", now)
	if !res.Blocked || res.Level != 2 {
		t.Fatalf("expected Level 2 block, got %+v", res)
	}

	// Reset
	rl.ResetCircuitBreaker()
	resReset := rl.CheckVisitor("10.0.0.99", now)
	if resReset.Blocked {
		t.Fatalf("expected unblocked after reset")
	}
}
