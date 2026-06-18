package apikey

import (
	"context"
	"net/http"
	"strings"

	"github.com/GoHyperrr/auth"
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
		&auth.Actor{},
		&APIKey{},
	}
}

func (m *Module) Routes() []mdk.Route {
	return nil
}

// Middlewares implements mdk.MiddlewareProvider interface.
func (m *Module) Middlewares() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		m.APIKeyMiddleware,
	}
}

func (m *Module) APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If already authenticated by another middleware, skip.
		if _, ok := mdk.ActorFromContext(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Also check Authorization header
			header := r.Header.Get("Authorization")
			if strings.HasPrefix(header, "Bearer ") {
				tokenVal := strings.TrimPrefix(header, "Bearer ")
				// If the token starts with hk_, it's an API Key.
				if strings.HasPrefix(tokenVal, "hk_") {
					apiKey = tokenVal
				}
			}
		}

		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		resActor, err := m.GetActorByAPIKey(r.Context(), apiKey)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := mdk.WithActor(r.Context(), resActor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func init() {
	mdk.Register(func() mdk.Module {
		return NewModule()
	})
}

