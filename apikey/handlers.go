package apikey

import (
	"context"
	"fmt"

	ident "github.com/GoHyperrr/hyperrr/pkg/identity"
)

// GetActorByAPIKey retrieves an actor associated with a given API key.
func (m *Module) GetActorByAPIKey(ctx context.Context, key string) (*ident.Actor, error) {
	var apiKey APIKey
	err := m.database.WithContext(ctx).Preload("Actor").First(&apiKey, "key = ?", key).Error
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}
	return &apiKey.Actor, nil
}
