package emailpass

import (
	"context"
	"testing"
	"time"

	"github.com/GoHyperrr/auth"
	"github.com/GoHyperrr/auth/jwt"
	"github.com/GoHyperrr/mdk/mdktest"
)

func TestEmailPassModule(t *testing.T) {
	rt, err := mdktest.NewInMemoryTestRuntime()
	if err != nil {
		t.Fatalf("failed to setup test runtime: %v", err)
	}
	db := rt.DB()

	mod := NewModule("this_is_a_secret_that_is_32_characters_long", "1h")
	rt.SetConfig("auth.emailpass.secret", "this_is_a_secret_that_is_32_characters_long")
	rt.SetConfig("auth.emailpass.expiration", "1h")

	// Migrate manually for the test
	err = db.AutoMigrate(mod.Models()...)
	if err != nil {
		t.Fatalf("failed to migrate models: %v", err)
	}

	err = mod.Init(context.Background(), rt)
	if err != nil {
		t.Fatalf("failed to init module: %v", err)
	}
	defer mod.Shutdown(context.Background())

	// Test 1: Validate minimum secret length check
	t.Run("Min Secret Length Check", func(t *testing.T) {
		badMod := NewModule("short", "1h")
		badRt := mdktest.NewTestRuntime(db)
		badRt.SetConfig("app_env", "production")
		badRt.SetConfig("auth.emailpass.secret", "short")
		err := badMod.Init(context.Background(), badRt)
		if err == nil {
			t.Error("expected error for short secret length")
		}
	})

	// Test 2: User Registration & Login CLI command helper (using CLI function)
	t.Run("User Registration CLI", func(t *testing.T) {
		err := RunEmailPassCmd(rt, []string{"register", "test@test.com", "mypassword", "John Doe"})
		if err != nil {
			t.Fatalf("CLI registration failed: %v", err)
		}

		// Verify duplicate registration fails
		err = RunEmailPassCmd(rt, []string{"register", "test@test.com", "mypassword", "John Doe"})
		if err == nil {
			t.Error("expected error when registering duplicate user")
		}
	})

	// Test 3: JWT Generation, validation and actor retrieval
	t.Run("JWT Validation", func(t *testing.T) {
		actor := &auth.Actor{
			ID:   "act_123",
			Type: "human",
			Name: "John Doe",
		}
		
		token, err := mod.Store().GenerateToken(actor)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		decodedActor, err := mod.ValidateToken(context.Background(), token)
		if err != nil {
			t.Fatalf("failed to validate token: %v", err)
		}

		if decodedActor.GetID() != actor.ID {
			t.Errorf("expected actor ID %s, got %s", actor.ID, decodedActor.GetID())
		}
	})

	// Test 4: Blacklisting and Token Expiry Pruning
	t.Run("Blacklist and Pruning", func(t *testing.T) {
		jti := "test-jti-123"
		
		// Blacklist the token
		err := mod.Store().Blacklist(context.Background(), jti, time.Now().Add(-1*time.Minute)) // expired already
		if err != nil {
			t.Fatalf("failed to blacklist token: %v", err)
		}

		blacklisted, err := mod.Store().IsBlacklisted(context.Background(), jti)
		if err != nil {
			t.Fatalf("failed to check blacklist: %v", err)
		}
		if !blacklisted {
			t.Error("expected token to be blacklisted")
		}

		// Also insert an expired refresh token
		err = mod.Store().SaveRefreshToken(context.Background(), &jwt.RefreshToken{
			ID:        "ref-123",
			ActorID:   "act_123",
			Token:     "ref-token-123",
			ExpiresAt: time.Now().Add(-10 * time.Minute),
			CreatedAt: time.Now().Add(-20 * time.Minute),
		})
		if err != nil {
			t.Fatalf("failed to save refresh token: %v", err)
		}

		// Call prune manually
		mod.pruneExpiredTokens(context.Background())

		// Verify blacklist item and refresh token were deleted
		blacklisted, err = mod.Store().IsBlacklisted(context.Background(), jti)
		if err != nil {
			t.Fatalf("failed to check blacklist: %v", err)
		}
		if blacklisted {
			t.Error("expected expired blacklist entry to be pruned")
		}

		_, err = mod.Store().GetRefreshToken(context.Background(), "ref-token-123")
		if err == nil {
			t.Error("expected expired refresh token to be pruned")
		}
	})
}
