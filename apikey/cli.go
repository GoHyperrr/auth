package apikey

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/GoHyperrr/auth"
	"github.com/GoHyperrr/mdk"
	"github.com/google/uuid"
)

// RunAPIKeyCmd executes the CLI logic to generate a new API key.
func RunAPIKeyCmd(rt mdk.Runtime, args []string) error {
	if len(args) < 1 || args[0] != "generate" {
		fmt.Println("Usage: hyperrr apikey generate")
		return fmt.Errorf("invalid arguments")
	}

	database := rt.DB()
	if database == nil {
		return fmt.Errorf("database connection is not available in dependencies")
	}

	// Seed default MCP Developer Actor if not already present
	var actorCount int64
	database.Model(&auth.Actor{}).Where("id = ?", "act_mcp_developer").Count(&actorCount)
	if actorCount == 0 {
		devActor := auth.Actor{
			ID:   "act_mcp_developer",
			Type: mdk.ActorAIAgent,
			Name: "Developer Agent",
		}
		if err := database.Create(&devActor).Error; err != nil {
			return fmt.Errorf("failed to create developer actor: %w", err)
		}
		fmt.Println("Created Developer Agent actor (act_mcp_developer).")
	}

	// Generate secure key
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	keyVal := "hk_" + hex.EncodeToString(b)

	newKey := APIKey{
		ID:        "key_" + uuid.New().String(),
		Name:      "Developer Key",
		Key:       keyVal,
		ActorID:   "act_mcp_developer",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := database.Create(&newKey).Error; err != nil {
		return fmt.Errorf("failed to save API key to database: %w", err)
	}

	fmt.Println("\n🔑 Secure API Key Generated successfully!")
	fmt.Printf("Key:       %s\n", keyVal)
	fmt.Printf("Actor ID:  %s\n", newKey.ActorID)
	fmt.Println("\nKeep this key safe! You can use this key to authenticate with the MCP SSE gateway.")
	return nil
}

