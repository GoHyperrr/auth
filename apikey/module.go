package apikey

import (
	"context"

	"github.com/GoHyperrr/hyperrr/pkg/db"
	"github.com/GoHyperrr/hyperrr/pkg/registry"
	"github.com/GoHyperrr/hyperrr/pkg/workflow"
)

type Module struct {
	database *db.DB
}

func NewModule() *Module {
	return &Module{}
}

func (m *Module) ID() string {
	return "auth.apikey"
}

func (m *Module) Init(ctx context.Context, deps *registry.Dependencies) error {
	m.database = deps.DB
	return nil
}

func (m *Module) Shutdown(ctx context.Context) error {
	return nil
}

func (m *Module) Models() []any {
	return []any{
		&APIKey{},
	}
}

func (m *Module) Handlers() map[string]workflow.TaskHandler {
	return nil
}

func init() {
	registry.RegisterFactory("auth.apikey", func(options map[string]any) (registry.Module, error) {
		return NewModule(), nil
	})
}
