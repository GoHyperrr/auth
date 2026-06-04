package apikey

import (
	"time"

	"github.com/GoHyperrr/mdk"
	"gorm.io/gorm"
)

// APIKey represents a secret key used for authentication.
type APIKey struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	Name      string         `gorm:"default:'';not null" json:"name"`
	Key       string         `gorm:"uniqueIndex;not null" json:"key"`
	ActorID   string         `gorm:"not null" json:"actor_id"`
	Actor     mdk.Actor      `gorm:"foreignKey:ActorID" json:"actor"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type APIKeyInfo struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	ActorID   string     `json:"actorId"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type GeneratedAPIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Key       string     `json:"key"`
	ActorID   string     `json:"actorId"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}


