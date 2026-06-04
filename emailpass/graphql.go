package emailpass

import (
	"context"
	"fmt"

	"github.com/GoHyperrr/mdk"
)

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

func (m *Module) RegisterResolver(ctx context.Context, email string, password string, name string) (*AuthResponse, error) {
	actor, err := m.Register(ctx, email, password, name)
	if err != nil {
		return nil, err
	}

	token, err := m.store.GenerateToken(*actor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &AuthResponse{
		Token: token,
		Actor: actor,
	}, nil
}

func (m *Module) LoginResolver(ctx context.Context, email string, password string) (*AuthResponse, error) {
	actor, err := m.Login(ctx, email, password)
	if err != nil {
		return nil, err
	}

	token, err := m.store.GenerateToken(*actor)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &AuthResponse{
		Token: token,
		Actor: actor,
	}, nil
}

func (m *Module) Me(ctx context.Context) (*mdk.Actor, error) {
	actor, ok := mdk.ActorFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("unauthorized")
	}

	return actor, nil
}

