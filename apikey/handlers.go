package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/GoHyperrr/mdk"
	"github.com/google/uuid"
)

// GetActorByAPIKey retrieves an actor associated with a given API key.
func (m *Module) GetActorByAPIKey(ctx context.Context, key string) (mdk.Actor, error) {
	var apiKey APIKey
	err := m.database.WithContext(ctx).Preload("Actor").First(&apiKey, "key = ?", key).Error
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}
	// Check expiration
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("API key is expired")
	}
	return &apiKey.Actor, nil
}

// CreateAPIKey generates a new secure API key for the given actor.
func (m *Module) CreateAPIKey(ctx context.Context, actorID string, name string, expiresAt *time.Time) (*APIKey, error) {
	if name == "" {
		return nil, fmt.Errorf("API key name is required")
	}

	// Generate secure random key
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	keyVal := "hk_" + hex.EncodeToString(b)

	apiKey := APIKey{
		ID:        "key_" + uuid.New().String(),
		Name:      name,
		Key:       keyVal,
		ActorID:   actorID,
		ExpiresAt: expiresAt,
	}

	if err := m.database.WithContext(ctx).Create(&apiKey).Error; err != nil {
		return nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return &apiKey, nil
}

// RevokeAPIKey deletes/revokes an API key.
func (m *Module) RevokeAPIKey(ctx context.Context, actorID string, keyID string) (bool, error) {
	result := m.database.WithContext(ctx).Where("id = ? AND actor_id = ?", keyID, actorID).Delete(&APIKey{})
	if result.Error != nil {
		return false, fmt.Errorf("failed to revoke API key: %w", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// ListAPIKeys lists all active API keys for the given actor.
func (m *Module) ListAPIKeys(ctx context.Context, actorID string) ([]*APIKey, error) {
	var keys []*APIKey
	if err := m.database.WithContext(ctx).Where("actor_id = ?", actorID).Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	return keys, nil
}

