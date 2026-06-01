package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GoHyperrr/hyperrr/pkg/db"
	"github.com/GoHyperrr/hyperrr/pkg/identity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RefreshToken represents a long-lived token used to generate new JWTs.
type RefreshToken struct {
	ID        string    `gorm:"primaryKey"`
	ActorID   string    `gorm:"index;not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
	CreatedAt time.Time
}

// Blacklist tracks revoked JWT IDs.
type Blacklist struct {
	ID        string    `gorm:"primaryKey"`
	JTI       string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
}

// Claims represents the JWT actor payload claims.
type Claims struct {
	ActorID   string             `json:"actor_id"`
	ActorType identity.ActorType `json:"actor_type"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidToken = errors.New("invalid token")
)

// AuthStore handles persistence for authentication tokens.
type AuthStore struct {
	db            *db.DB
	signingKey    []byte
	jwtExpiration time.Duration
}

func NewAuthStore(database *db.DB, signingKey string, expiration time.Duration) *AuthStore {
	return &AuthStore{
		db:            database,
		signingKey:    []byte(signingKey),
		jwtExpiration: expiration,
	}
}

const (
	PrefixBlacklist = "bl_"
)

func (s *AuthStore) Blacklist(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.db.WithContext(ctx).Create(&Blacklist{
		ID:        PrefixBlacklist + uuid.New().String(),
		JTI:       jti,
		ExpiresAt: expiresAt,
	}).Error
}

func (s *AuthStore) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	var b Blacklist
	err := s.db.WithContext(ctx).First(&b, "jti = ?", jti).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *AuthStore) SaveRefreshToken(ctx context.Context, t *RefreshToken) error {
	return s.db.WithContext(ctx).Save(t).Error
}

func (s *AuthStore) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var t RefreshToken
	err := s.db.WithContext(ctx).Where("token = ?", token).First(&t).Error
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *AuthStore) RevokeRefreshToken(ctx context.Context, token string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&RefreshToken{}).Where("token = ?", token).Update("revoked_at", &now).Error
}

func (s *AuthStore) DeleteExpiredTokens(ctx context.Context, now time.Time) error {
	return s.db.WithContext(ctx).Where("expires_at < ? OR revoked_at IS NOT NULL", now).Delete(&RefreshToken{}).Error
}

// GenerateToken creates a new JWT for an actor.
func (s *AuthStore) GenerateToken(actor identity.Actor) (string, error) {
	jti := uuid.New().String()
	claims := Claims{
		ActorID:   actor.ID,
		ActorType: actor.Type,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}

// ValidateToken parses and validates a JWT string.
func (s *AuthStore) ValidateToken(ctx context.Context, tokenString string) (*identity.Actor, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check blacklist
		revoked, err := s.IsBlacklisted(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if revoked {
			return nil, errors.New("token is revoked")
		}

		return &identity.Actor{
			ID:   claims.ActorID,
			Type: claims.ActorType,
		}, nil
	}

	return nil, ErrInvalidToken
}
