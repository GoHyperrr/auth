package apikey

import (
	"context"
	"fmt"
	"time"

	"github.com/GoHyperrr/mdk"
)

func (m *Module) Queries() map[string]any {
	return map[string]any{
		"listAPIKeys": m.ListAPIKeysResolver,
	}
}

func (m *Module) Mutations() map[string]any {
	return map[string]any{
		"createAPIKey": m.CreateAPIKeyResolver,
		"revokeAPIKey": m.RevokeAPIKeyResolver,
	}
}

func (m *Module) FieldResolvers() map[string]any {
	return nil
}

func (m *Module) CreateAPIKeyResolver(ctx context.Context, name string, expiresAt *time.Time) (*GeneratedAPIKey, error) {
	actor, ok := mdk.ActorFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthorized")
	}

	key, err := m.CreateAPIKey(ctx, actor.ID, name, expiresAt)
	if err != nil {
		return nil, err
	}

	return &GeneratedAPIKey{
		ID:        key.ID,
		Name:      key.Name,
		Key:       key.Key,
		ActorID:   key.ActorID,
		ExpiresAt: key.ExpiresAt,
		CreatedAt: key.CreatedAt,
	}, nil
}

func (m *Module) RevokeAPIKeyResolver(ctx context.Context, id string) (bool, error) {
	actor, ok := mdk.ActorFromContext(ctx)
	if !ok {
		return false, fmt.Errorf("unauthorized")
	}

	return m.RevokeAPIKey(ctx, actor.ID, id)
}

func (m *Module) ListAPIKeysResolver(ctx context.Context) ([]*APIKeyInfo, error) {
	actor, ok := mdk.ActorFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthorized")
	}

	keys, err := m.ListAPIKeys(ctx, actor.ID)
	if err != nil {
		return nil, err
	}

	res := make([]*APIKeyInfo, len(keys))
	for i, key := range keys {
		res[i] = &APIKeyInfo{
			ID:        key.ID,
			Name:      key.Name,
			ActorID:   key.ActorID,
			ExpiresAt: key.ExpiresAt,
			CreatedAt: key.CreatedAt,
		}
	}
	return res, nil
}


