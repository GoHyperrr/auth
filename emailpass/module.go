package emailpass

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/GoHyperrr/auth/jwt"
	"github.com/GoHyperrr/hyperrr/api/middleware"
	"github.com/GoHyperrr/hyperrr/pkg/db"
	"github.com/GoHyperrr/hyperrr/pkg/eventbus"
	"github.com/GoHyperrr/hyperrr/pkg/logger"
	"github.com/GoHyperrr/hyperrr/pkg/registry"
	"github.com/GoHyperrr/hyperrr/pkg/workflow"
	"github.com/google/uuid"
)

type Module struct {
	database   *db.DB
	bus        eventbus.EventBus
	store      *jwt.AuthStore
	secret     string
	expiration string
}

func NewModule(secret, expiration string) *Module {
	return &Module{
		secret:     secret,
		expiration: expiration,
	}
}

func (m *Module) ID() string {
	return "auth.emailpass"
}

func (m *Module) Init(ctx context.Context, deps *registry.Dependencies) error {
	m.database = deps.DB
	m.bus = deps.EventBus

	exp, err := time.ParseDuration(m.expiration)
	if err != nil {
		return fmt.Errorf("invalid JWT_EXPIRATION format: %w", err)
	}
	m.store = jwt.NewAuthStore(deps.DB, m.secret, exp)

	// Register Auth Middleware
	registry.RegisterMiddleware("auth", func(next http.Handler) http.Handler {
		return middleware.AuthMiddleware(m.store)(next)
	})

	return nil
}

func (m *Module) Shutdown(ctx context.Context) error {
	return nil
}

func (m *Module) Store() *jwt.AuthStore {
	return m.store
}

func (m *Module) Models() []any {
	return []any{
		&User{},
		&jwt.RefreshToken{},
		&jwt.Blacklist{},
	}
}

func (m *Module) Handlers() map[string]workflow.TaskHandler {
	return map[string]workflow.TaskHandler{
		"identity.validate_actor": m.ValidateActor,
	}
}

func (m *Module) emit(ctx context.Context, eventType string, payload any) {
	if m.bus == nil {
		return
	}
	event := eventbus.Event{
		ID:        "evt_" + uuid.New().String(),
		Type:      eventType,
		Payload:   payload,
		Timestamp: time.Now(),
	}
	if err := m.bus.Publish(ctx, event); err != nil {
		logger.Error("failed to publish auth event", "type", eventType, "error", err)
	}
}

func init() {
	factory := func(options map[string]any) (registry.Module, error) {
		secret, _ := options["secret"].(string)
		if secret == "" {
			secret = os.Getenv("JWT_SECRET")
		}
		if secret == "" {
			return nil, fmt.Errorf("auth.emailpass: JWT_SECRET is required (specify in module options or JWT_SECRET env var)")
		}

		expiration, _ := options["expiration"].(string)
		if expiration == "" {
			expiration = os.Getenv("JWT_EXPIRATION")
		}
		if expiration == "" {
			expiration = "24h" // Default expiration
		}

		return NewModule(secret, expiration), nil
	}

	registry.RegisterFactory("auth.emailpass", factory)
	registry.RegisterFactory("github.com/GoHyperrr/auth/emailpass", factory)

	registry.RegisterCommand(registry.CLICommand{
		Group:       "auth",
		Name:        "user",
		Usage:       "register <email> <password> <name>",
		Short:       "Register a new user via email/password",
		Long:        "Register a new user dynamically via email/password and write it to the database.",
		NeedsDB:     true,
		Run:         runEmailPassCmd,
	})
}
