package emailpass

import (
	"fmt"
	"strings"

	"github.com/GoHyperrr/auth"
	"github.com/GoHyperrr/mdk"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// RunEmailPassCmd registers a new user via CLI.
func RunEmailPassCmd(rt mdk.Runtime, args []string) error {
	if len(args) < 4 || args[0] != "register" {
		fmt.Println("Usage: hyperrr emailpass register <email> <password> <name>")
		return fmt.Errorf("invalid arguments")
	}

	email := args[1]
	password := args[2]
	name := strings.Join(args[3:], " ")

	database := rt.DB()
	if database == nil {
		return fmt.Errorf("database connection is not available in dependencies")
	}

	// Auto-migrate tables locally to ensure Actor and User exist
	err := database.AutoMigrate(&auth.Actor{}, &User{})
	if err != nil {
		return fmt.Errorf("failed to run migrations for emailpass models: %w", err)
	}

	// Check if user already exists
	var count int64
	database.Model(&User{}).Where("email = ?", email).Count(&count)
	if count > 0 {
		return fmt.Errorf("user with email '%s' already exists", email)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	actorID := "act_" + uuid.New().String()
	actor := auth.Actor{
		ID:   actorID,
		Type: mdk.ActorHuman,
		Name: name,
	}

	user := User{
		ID:           "usr_" + uuid.New().String(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		ActorID:      actorID,
	}

	err = database.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&actor).Error; err != nil {
			return err
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Println("\n👤 User Registered successfully!")
	fmt.Printf("Email:     %s\n", email)
	fmt.Printf("Name:      %s\n", name)
	fmt.Printf("Actor ID:  %s\n", actorID)
	return nil
}

