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
	factory := func(options map[string]any) (registry.Module, error) {
		return NewModule(), nil
	}
	registry.RegisterFactory("auth.apikey", factory)
	registry.RegisterFactory("github.com/GoHyperrr/auth/apikey", factory)

	registry.RegisterCommand(registry.CLICommand{
		Group:       "auth",
		Name:        "apikey",
		Usage:       "generate",
		Short:       "Generate a new secure API key on-demand",
		Long:        "Generate a new secure API key on-demand and write it to the database.",
		NeedsDB:     true,
		Run:         runAPIKeyCmd,
	})
}
