package auth

import (
	"time"

	"github.com/GoHyperrr/mdk"
)

// Actor is the concrete GORM database model representing a security principal.
// It implements the mdk.Actor interface.
type Actor struct {
	ID        string        `gorm:"primaryKey" json:"id"`
	Type      mdk.ActorType `gorm:"index" json:"type"`
	Name      string        `json:"name"`
	Metadata  mdk.JSONMap   `gorm:"type:text" json:"metadata,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// Ensure Actor implements mdk.Actor.
var _ mdk.Actor = (*Actor)(nil)

func (a *Actor) GetID() string {
	return a.ID
}

func (a *Actor) GetType() mdk.ActorType {
	return a.Type
}

func (a *Actor) GetName() string {
	return a.Name
}

func (a *Actor) GetMetadata() map[string]string {
	return a.Metadata
}
