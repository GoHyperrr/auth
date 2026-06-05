package emailpass

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GoHyperrr/auth/jwt"
	"github.com/GoHyperrr/mdk"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Module struct {
	database   *gorm.DB
	bus        mdk.EventBus
	store      *jwt.AuthStore
	secret     string
	expiration string
	rt         mdk.Runtime
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

func (m *Module) Init(ctx context.Context, rt mdk.Runtime) error {
	m.rt = rt
	m.database = rt.DB()
	m.bus = rt.Bus()

	if s, ok := rt.Config("auth.emailpass.secret").(string); ok && s != "" {
		m.secret = s
	} else if envSecret := os.Getenv("JWT_SECRET"); envSecret != "" {
		m.secret = envSecret
	}

	if m.secret == "" {
		return fmt.Errorf("auth.emailpass: JWT_SECRET is required (specify in config or JWT_SECRET env var)")
	}

	if e, ok := rt.Config("auth.emailpass.expiration").(string); ok && e != "" {
		m.expiration = e
	} else if envExp := os.Getenv("JWT_EXPIRATION"); envExp != "" {
		m.expiration = envExp
	}
	if m.expiration == "" {
		m.expiration = "24h"
	}

	exp, err := time.ParseDuration(m.expiration)
	if err != nil {
		return fmt.Errorf("invalid JWT_EXPIRATION format: %w", err)
	}
	m.store = jwt.NewAuthStore(rt.DB(), m.secret, exp)

	if rt.Workflows() != nil {
		if err := rt.Workflows().RegisterHandler("auth.validate_actor", m.ValidateActorStep); err != nil {
			return fmt.Errorf("failed to register validate actor step handler: %w", err)
		}
	}

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

func (m *Module) Routes() []mdk.Route {
	return nil
}

// ValidateToken implements mdk.TokenValidator interface.
func (m *Module) ValidateToken(ctx context.Context, token string) (*mdk.Actor, error) {
	return m.store.ValidateToken(ctx, token)
}

// ValidateActorStep wraps ValidateActor to conform to mdk.StepHandler.
func (m *Module) ValidateActorStep(sCtx mdk.StepContext) mdk.StepResult {
	res, err := m.ValidateActor(sCtx.Ctx, sCtx.Input)
	if err != nil {
		return mdk.StepResult{Err: err}
	}
	resMap, ok := res.(map[string]any)
	if !ok {
		return mdk.StepResult{Err: fmt.Errorf("invalid result format from ValidateActor")}
	}
	return mdk.StepResult{Output: resMap}
}

func (m *Module) emit(ctx context.Context, eventType string, payload any) {
	if m.bus == nil {
		return
	}
	var payloadMap map[string]any
	if bytes, err := json.Marshal(payload); err == nil {
		_ = json.Unmarshal(bytes, &payloadMap)
	}
	parts := strings.SplitN(eventType, ".", 2)
	var ns, et string
	if len(parts) == 2 {
		ns, et = parts[0], parts[1]
	} else {
		ns, et = "auth.emailpass", eventType
	}
	event := mdk.Event{
		ID:         "evt_" + uuid.New().String(),
		Namespace:  ns,
		Type:       et,
		Payload:    payloadMap,
		OccurredAt: time.Now(),
	}
	if err := m.bus.Publish(ctx, event); err != nil {
		if m.rt != nil && m.rt.Logger() != nil {
			m.rt.Logger().Error("failed to publish auth event", "type", eventType, "error", err)
		}
	}
}

func init() {
	mdk.Register(func() mdk.Module {
		return NewModule("", "")
	})
}

