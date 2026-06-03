package emailpass

import (
	"context"
	"fmt"

	"github.com/GoHyperrr/hyperrr/api/graph/model"
	"github.com/GoHyperrr/hyperrr/api/middleware"
	"github.com/GoHyperrr/hyperrr/pkg/registry"
)

// Ensure Module implements registry.GraphQLProvider at compile time.
var _ registry.GraphQLProvider = (*Module)(nil)

func (m *Module) Queries() map[string]any {
	return map[string]any{
		"me": m.Me,
	}
}

func (m *Module) Mutations() map[string]any {
	return map[string]any{
		"register": m.RegisterResolver,
		"login":    m.LoginResolver,
	}
}

func (m *Module) FieldResolvers() map[string]any {
	return nil
}

func (m *Module) RegisterResolver(ctx context.Context, email string, password string, name string) (*model.AuthResponse, error) {
	actor, err := m.Register(ctx, email, password, name)
	if err != nil {
		return nil, err
	}

	token, err := m.store.GenerateToken(*actor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &model.AuthResponse{
		Token: token,
		Actor: &model.Actor{
			ID:   actor.ID,
			Type: string(actor.Type),
			Name: actor.Name,
		},
	}, nil
}

func (m *Module) LoginResolver(ctx context.Context, email string, password string) (*model.AuthResponse, error) {
	actor, err := m.Login(ctx, email, password)
	if err != nil {
		return nil, err
	}

	token, err := m.store.GenerateToken(*actor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &model.AuthResponse{
		Token: token,
		Actor: &model.Actor{
			ID:   actor.ID,
			Type: string(actor.Type),
			Name: actor.Name,
		},
	}, nil
}

func (m *Module) Me(ctx context.Context) (*model.Actor, error) {
	actor, ok := middleware.ForContext(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthorized")
	}

	return &model.Actor{
		ID:   actor.ID,
		Type: string(actor.Type),
		Name: actor.Name,
	}, nil
}
