package apikey

import (
	"context"

	"github.com/GoHyperrr/mdk"
	"gorm.io/gorm"
)

type Module struct {
	database *gorm.DB
}

func NewModule() *Module {
	return &Module{}
}

func (m *Module) ID() string {
	return "auth.apikey"
}

func (m *Module) Init(ctx context.Context, rt mdk.Runtime) error {
	m.database = rt.DB()
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

func (m *Module) Routes() []mdk.Route {
	return nil
}

func init() {
	mdk.Register(func() mdk.Module {
		return NewModule()
	})

	mdk.RegisterCommand(mdk.CLICommand{
		Group:       "auth",
		Name:        "apikey",
		Usage:       "generate",
		Short:       "Generate a new secure API key on-demand",
		Long:        "Generate a new secure API key on-demand and write it to the database.",
		NeedsDB:     true,
		Run:         runAPIKeyCmd,
	})
}

