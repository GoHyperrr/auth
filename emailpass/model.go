package emailpass

import (
	"time"

	"github.com/GoHyperrr/mdk"
	"gorm.io/gorm"
)

// User represents a human entity in the system.
type User struct {
	ID           string         `gorm:"primaryKey" json:"id"`
	Email        string         `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string         `gorm:"not null" json:"-"`
	ActorID      string         `gorm:"not null" json:"actor_id"`
	Actor        mdk.Actor      `gorm:"foreignKey:ActorID" json:"actor"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type AuthResponse struct {
	Token string     `json:"token"`
	Actor *mdk.Actor `json:"actor"`
}


