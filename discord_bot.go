package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/bwmarrin/discordgo"
)

// toTitle converts the first letter of s to upper case and the rest to lower case.
func toTitle(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// Command represents a Discord slash command
type Command struct {
	Name        string
	Description string
	Options     []*discordgo.ApplicationCommandOption
	Handler     CommandHandler
	AdminOnly   bool
}

// SubscriptionManager manages user subscriptions with thread-safe operations
type SubscriptionManager struct {
	UserSubscriptions map[string][]SubscriptionType
	filePath          string
	mu                sync.RWMutex
}

// SubscriptionType represents different types of cricket alerts users can subscribe to
type SubscriptionType string

const (
	SubMilestones SubscriptionType = "milestones"
	SubWickets    SubscriptionType = "wickets"
	SubToss       SubscriptionType = "toss"
	SubStart      SubscriptionType = "start"
)

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager(filePath string) *SubscriptionManager {
	sm := &SubscriptionManager{
		UserSubscriptions: make(map[string][]SubscriptionType),
		filePath:          filePath,
	}

	// Load existing subscriptions from file
	if err := sm.loadFromFile(); err != nil {
		log.Printf("Error loading subscriptions: %v", err)
	}

	return sm
}

// ValidateSubscriptionType checks if a subscription type is valid
func ValidateSubscriptionType(subType string) (SubscriptionType, bool) {
	switch SubscriptionType(subType) {
	case SubMilestones, SubWickets, SubToss, SubStart:
		return SubscriptionType(subType), true
	default:
		return "", false
	}
}

// Subscribe adds a user to a specific subscription type
func (sm *SubscriptionManager) Subscribe(userID string, subType SubscriptionType) error {
	// Validate subscription type
	if _, valid := ValidateSubscriptionType(string(subType)); !valid {
		return fmt.Errorf("invalid subscription type: %s", subType)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Get current subscriptions for user
	userSubs := sm.UserSubscriptions[userID]

	// Check if user is already subscribed to this type
	for _, existing := range userSubs {
		if existing == subType {
			return fmt.Errorf("user %s is already subscribed to %s", userID, subType)
		}
	}

	// Add subscription
	sm.UserSubscriptions[userID] = append(userSubs, subType)

	// Persist to file
	return sm.saveToFile()
}

// Unsubscribe removes a user from a specific subscription type
func (sm *SubscriptionManager) Unsubscribe(userID string, subType SubscriptionType) error {
	// Validate subscription type
	if _, valid := ValidateSubscriptionType(string(subType)); !valid {
		return fmt.Errorf("invalid subscription type: %s", subType)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	userSubs := sm.UserSubscriptions[userID]

	// Find and remove the subscription
	found := false
	newSubs := make([]SubscriptionType, 0, len(userSubs))
	for _, existing := range userSubs {
		if existing != subType {
			newSubs = append(newSubs, existing)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("user %s is not subscribed to %s", userID, subType)
	}

	// Update subscriptions
	if len(newSubs) == 0 {
		delete(sm.UserSubscriptions, userID)
	} else {
		sm.UserSubscriptions[userID] = newSubs
	}

	// Persist to file
	return sm.saveToFile()
}

// GetUserSubscriptions returns all subscription types for a user
func (sm *SubscriptionManager) GetUserSubscriptions(userID string) []SubscriptionType {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	userSubs := sm.UserSubscriptions[userID]
	if userSubs == nil {
		return []SubscriptionType{}
	}

	// Return a copy to prevent external modification
	result := make([]SubscriptionType, len(userSubs))
	copy(result, userSubs)
	return result
}

// IsUserSubscribed checks if a user is subscribed to a specific type
func (sm *SubscriptionManager) IsUserSubscribed(userID string, subType SubscriptionType) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	userSubs := sm.UserSubscriptions[userID]
	for _, existing := range userSubs {
		if existing == subType {
			return true
		}
	}
	return false
}

// GetSubscribedUsers returns all users subscribed to a specific type
func (sm *SubscriptionManager) GetSubscribedUsers(subType SubscriptionType) []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var users []string
	for userID, subs := range sm.UserSubscriptions {
		for _, sub := range subs {
			if sub == subType {
				users = append(users, userID)
				break
			}
		}
	}
	return users
}

// GetAllSubscriptions returns a copy of all subscriptions (for admin purposes)
func (sm *SubscriptionManager) GetAllSubscriptions() map[string][]SubscriptionType {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string][]SubscriptionType)
	for userID, subs := range sm.UserSubscriptions {
		result[userID] = make([]SubscriptionType, len(subs))
		copy(result[userID], subs)
	}
	return result
}

// loadFromFile loads subscriptions from JSON file
func (sm *SubscriptionManager) loadFromFile() error {
	if sm.filePath == "" {
		return nil // No file path specified, skip loading
	}

	data, err := os.ReadFile(sm.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, start with empty subscriptions
			log.Printf("Subscription file %s doesn't exist, starting with empty subscriptions", sm.filePath)
			return nil
		}
		return fmt.Errorf("error reading subscription file: %v", err)
	}

	if len(data) == 0 {
		// Empty file, start with empty subscriptions
		return nil
	}

	var subscriptions map[string][]SubscriptionType
	err = json.Unmarshal(data, &subscriptions)
	if err != nil {
		return fmt.Errorf("error unmarshaling subscription data: %v", err)
	}

	// Validate loaded subscriptions
	validatedSubs := make(map[string][]SubscriptionType)
	for userID, subs := range subscriptions {
		var validSubs []SubscriptionType
		for _, sub := range subs {
			if _, valid := ValidateSubscriptionType(string(sub)); valid {
				validSubs = append(validSubs, sub)
			} else {
				log.Printf("Warning: Invalid subscription type %s for user %s, skipping", sub, userID)
			}
		}
		if len(validSubs) > 0 {
			validatedSubs[userID] = validSubs
		}
	}

	sm.UserSubscriptions = validatedSubs
	log.Printf("Loaded %d user subscriptions from %s", len(sm.UserSubscriptions), sm.filePath)
	return nil
}

// saveToFile saves subscriptions to JSON file
func (sm *SubscriptionManager) saveToFile() error {
	if sm.filePath == "" {
		return nil // No file path specified, skip saving
	}

	data, err := json.MarshalIndent(sm.UserSubscriptions, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling subscription data: %v", err)
	}

	err = os.WriteFile(sm.filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("error writing subscription file: %v", err)
	}

	log.Printf("Saved %d user subscriptions to %s", len(sm.UserSubscriptions), sm.filePath)
	return nil
}

// Enhanced DiscordBot struct with command system and subscription management
type EnhancedDiscordBot struct {
	Session           *discordgo.Session
	Config            *BotConfig
	Subscribers       *SubscriptionManager
	Commands          map[string]*Command
	StartTime         time.Time
	mu                sync.RWMutex
	rateLimiter       *RateLimiter
	circuitBreaker    *CircuitBreaker
	securityValidator *SecurityValidator
	permissionChecker *PermissionChecker
	logger            *EnhancedLogger
	securityConfig    SecurityConfig
}

// NewDiscordBot creates a new enhanced Discord bot instance
func NewDiscordBot(config *BotConfig) (*EnhancedDiscordBot, error) {
	// Validate token security
	tokenHandler := NewSecureTokenHandler()
	if err := tokenHandler.ValidateToken(config.Token); err != nil {
		return nil, fmt.Errorf("invalid bot token: %v", err)
	}

	session, err := discordgo.New("Bot " + config.Token)
	if err != nil {
		return nil, fmt.Errorf("error creating Discord session: %v", err)
	}

	// Create subscription manager
	subscribers := NewSubscriptionManager("subscriptions.json")

	// Initialize security and reliability components
	securityConfig := DefaultSecurityConfig()
	logger := NewEnhancedLogger("DISCORD_BOT")

	bot := &EnhancedDiscordBot{
		Session:           session,
		Config:            config,
		Subscribers:       subscribers,
		Commands:          make(map[string]*Command),
		StartTime:         time.Now(),
		rateLimiter:       NewRateLimiter(securityConfig.MaxRequestsPerMinute, time.Minute),
		circuitBreaker:    NewCircuitBreaker("discord_api", securityConfig.CircuitBreakerConfig.MaxFailures, time.Duration(securityConfig.CircuitBreakerConfig.ResetTimeout)*time.Second),
		securityValidator: NewSecurityValidator(),
		permissionChecker: NewPermissionChecker(),
		logger:            logger,
		securityConfig:    securityConfig,
	}

	// Register command handlers
	bot.registerCommands()

	// Set up event handlers
	session.AddHandler(bot.handleInteraction)

	logger.LogInfo("NewDiscordBot", "Discord bot initialized successfully", map[string]interface{}{
		"guild_id":   config.GuildID,
		"channel_id": config.ChannelID,
	})

	return bot, nil
}

// registerCommands registers all available slash commands
func (bot *EnhancedDiscordBot) registerCommands() {
	// Score command - get live cricket scores
	bot.registerCommand(&Command{
		Name:        "score",
		Description: "Get live cricket scores for monitored matches",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "team",
				Description: "Filter scores by team (optional)",
				Required:    false,
			},
		},
		Handler:   bot.handleScoreCommand,
		AdminOnly: false,
	})

	// Matches command - list all tracked matches with IDs
	bot.registerCommand(&Command{
		Name:        "matches",
		Description: "List all currently tracked live matches with their IDs",
		Handler:     bot.handleMatchesCommand,
		AdminOnly:   false,
	})

	// Match command - get detailed match information by ID
	bot.registerCommand(&Command{
		Name:        "match",
		Description: "Get detailed match information using match ID",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "matchid",
				Description: "Match ID from /matches command",
				Required:    true,
			},
		},
		Handler:   bot.handleMatchCommand,
		AdminOnly: false,
	})

	// Scoreboard command - get detailed scorecard for current match
	bot.registerCommand(&Command{
		Name:        "scoreboard",
		Description: "Get detailed cricket scorecard for the current tracked match",
		Handler:     bot.handleScoreboardCommand,
		AdminOnly:   false,
	})

	// Monitor command - manage monitored teams (admin only)
	bot.registerCommand(&Command{
		Name:        "monitor",
		Description: "Manage monitored cricket teams (admin only)",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "action",
				Description: "Action to perform",
				Required:    true,
				Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "add", Value: "add"},
					{Name: "remove", Value: "remove"},
					{Name: "list", Value: "list"},
				},
			},
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "team",
				Description: "Team name (required for add/remove)",
				Required:    false,
			},
		},
		Handler:   bot.handleMonitorCommand,
		AdminOnly: true,
	})

	// Alerts command - configure alert preferences (admin only)
	bot.registerCommand(&Command{
		Name:        "alerts",
		Description: "Configure alert preferences (admin only)",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "action",
				Description: "Action to perform",
				Required:    true,
				Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "config", Value: "config"},
				},
			},
		},
		Handler:   bot.handleAlertsCommand,
		AdminOnly: true,
	})

	// Subscribe command - manage personal subscriptions
	bot.registerCommand(&Command{
		Name:        "subscribe",
		Description: "Subscribe to specific types of cricket alerts",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "type",
				Description: "Type of alerts to subscribe to",
				Required:    true,
				Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "milestones", Value: "milestones"},
					{Name: "wickets", Value: "wickets"},
					{Name: "toss", Value: "toss"},
					{Name: "start", Value: "start"},
				},
			},
		},
		Handler:   bot.handleSubscribeCommand,
		AdminOnly: false,
	})

	// Unsubscribe command - remove personal subscriptions
	bot.registerCommand(&Command{
		Name:        "unsubscribe",
		Description: "Unsubscribe from specific types of cricket alerts",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "type",
				Description: "Type of alerts to unsubscribe from",
				Required:    true,
				Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "milestones", Value: "milestones"},
					{Name: "wickets", Value: "wickets"},
					{Name: "toss", Value: "toss"},
					{Name: "start", Value: "start"},
				},
			},
		},
		Handler:   bot.handleUnsubscribeCommand,
		AdminOnly: false,
	})

	// Subscriptions command - view current subscriptions
	bot.registerCommand(&Command{
		Name:        "subscriptions",
		Description: "View your current subscription status",
		Handler:     bot.handleSubscriptionsCommand,
		AdminOnly:   false,
	})

	// Bot command - control bot monitoring status (admin only)
	bot.registerCommand(&Command{
		Name:        "bot",
		Description: "Control bot monitoring status (admin only)",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "action",
				Description: "Action to perform",
				Required:    true,
				Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "start", Value: "start"},
					{Name: "stop", Value: "stop"},
					{Name: "status", Value: "status"},
					{Name: "restart", Value: "restart"},
				},
			},
		},
		Handler:   bot.handleBotCommand,
		AdminOnly: true,
	})

	// Scrape command - manually trigger a scrape (admin only)
	bot.registerCommand(&Command{
		Name:        "scrape",
		Description: "Force an immediate cricket score scrape",
		Handler:     bot.handleScrapeCommand,
		AdminOnly:   true,
	})

	// Help command - get help information
	bot.registerCommand(&Command{
		Name:        "help",
		Description: "Get help information about bot commands",
		Options: []*discordgo.ApplicationCommandOption{
			{
				Type:        discordgo.ApplicationCommandOptionString,
				Name:        "command",
				Description: "Get help for a specific command (optional)",
				Required:    false,
			},
		},
		Handler:   bot.handleHelpCommand,
		AdminOnly: false,
	})
}

// registerCommand adds a command to the bot's command registry
func (bot *EnhancedDiscordBot) registerCommand(cmd *Command) {
	bot.mu.Lock()
	defer bot.mu.Unlock()
	bot.Commands[cmd.Name] = cmd
}

// handleInteraction handles incoming Discord interactions (slash commands)
func (bot *EnhancedDiscordBot) handleInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Handle different interaction types
	switch i.Type {
	case discordgo.InteractionApplicationCommand:
		bot.handleSlashCommand(s, i)
	case discordgo.InteractionMessageComponent:
		bot.handleButtonInteraction(s, i)
	default:
		bot.logger.LogWarning("handleInteraction", "Unknown interaction type", map[string]interface{}{
			"type":    i.Type,
			"user_id": getInteractionUserID(i),
		})
	}
}

// handleSlashCommand processes slash commands with enhanced security
func (bot *EnhancedDiscordBot) handleSlashCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	commandName := i.ApplicationCommandData().Name

	bot.mu.RLock()
	command, exists := bot.Commands[commandName]
	bot.mu.RUnlock()

	if !exists {
		bot.logger.LogWarning("handleSlashCommand", "Unknown command attempted", map[string]interface{}{
			"command": commandName,
			"user_id": getInteractionUserID(i),
		})
		bot.respondWithError(s, i, "Unknown command")
		return
	}

	// Enhanced permission validation
	if err := bot.validateCommandPermissions(i, command); err != nil {
		bot.respondWithUserFriendlyError(s, i, err)
		return
	}

	// Log command execution
	bot.logger.LogInfo("handleSlashCommand", "Executing command", map[string]interface{}{
		"command":    commandName,
		"user_id":    getInteractionUserID(i),
		"admin_only": command.AdminOnly,
	})

	// Execute command with rate limiting and error handling
	err := bot.executeWithRateLimit(func() error {
		command.Handler(s, i)
		return nil
	})

	if err != nil {
		bot.logger.LogError("handleSlashCommand", err, map[string]interface{}{
			"command": commandName,
			"user_id": getInteractionUserID(i),
		})

		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "rate limit") {
			bot.respondWithUserFriendlyError(s, i, NewRateLimitError())
		} else {
			bot.respondWithUserFriendlyError(s, i, NewAPIConnectionError(err))
		}
	}
}

// handleButtonInteraction handles button interactions for alert configuration
func (bot *EnhancedDiscordBot) handleButtonInteraction(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Only handle message component interactions (buttons)
	if i.Type != discordgo.InteractionMessageComponent {
		return
	}

	// Check admin permissions for alert configuration buttons
	if !bot.isAdmin(i.Member) {
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "❌ You need administrator permissions to modify alert settings",
				Flags:   discordgo.MessageFlagsEphemeral,
			},
		})
		if err != nil {
			log.Printf("Error responding to button interaction: %v", err)
		}
		return
	}

	customID := i.MessageComponentData().CustomID

	switch customID {
	case "toggle_toss":
		bot.handleToggleToss(s, i)
	case "toggle_start":
		bot.handleToggleStart(s, i)
	case "toggle_wicket":
		bot.handleToggleWicket(s, i)
	case "score_freq_decrease":
		bot.handleScoreFreqDecrease(s, i)
	case "score_freq_increase":
		bot.handleScoreFreqIncrease(s, i)
	default:
		log.Printf("Unknown button interaction: %s", customID)
	}
}

// isAdmin checks if a user has admin permissions
func (bot *EnhancedDiscordBot) isAdmin(member *discordgo.Member) bool {
	if member == nil {
		return false
	}

	// Check if user has administrator permission
	for _, roleID := range member.Roles {
		if roleID == bot.Config.AdminRoleID {
			return true
		}
	}

	// Check for administrator permission bit
	permissions, err := bot.Session.UserChannelPermissions(member.User.ID, bot.Config.ChannelID)
	if err != nil {
		log.Printf("Error checking permissions: %v", err)
		return false
	}

	return permissions&discordgo.PermissionAdministrator != 0
}

// respondWithError sends an error response to the user
func (bot *EnhancedDiscordBot) respondWithError(s *discordgo.Session, i *discordgo.InteractionCreate, message string) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("❌ %s", message),
			Flags:   discordgo.MessageFlagsEphemeral,
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
	}
}

// respondWithSuccess sends a success response to the user
func (bot *EnhancedDiscordBot) respondWithSuccess(s *discordgo.Session, i *discordgo.InteractionCreate, message string) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("✅ %s", message),
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
	}
}

// respondWithEmbed sends an embed response to the user
func (bot *EnhancedDiscordBot) respondWithEmbed(s *discordgo.Session, i *discordgo.InteractionCreate, embed *discordgo.MessageEmbed) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
	}
}

// respondWithUserFriendlyError handles UserFriendlyError types with enhanced messaging
func (bot *EnhancedDiscordBot) respondWithUserFriendlyError(s *discordgo.Session, i *discordgo.InteractionCreate, err error) {
	var userMessage string
	color := 0xff0000 // Red for errors

	// Check if it's a UserFriendlyError
	if ufe, ok := err.(*UserFriendlyError); ok {
		userMessage = ufe.GetUserMessage()
		bot.logger.LogError("respondWithUserFriendlyError", ufe.TechnicalError, map[string]interface{}{
			"user_id":      getInteractionUserID(i),
			"command":      getCommandName(i),
			"user_message": ufe.UserMessage,
		})
	} else {
		userMessage = "An unexpected error occurred. Please try again later."
		bot.logger.LogError("respondWithUserFriendlyError", err, map[string]interface{}{
			"user_id": getInteractionUserID(i),
			"command": getCommandName(i),
		})
	}

	embed := &discordgo.MessageEmbed{
		Title:       "❌ Error",
		Description: userMessage,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "If this problem persists, please contact an administrator",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	bot.respondWithEmbed(s, i, embed)
}

// executeWithRateLimit executes a Discord API operation with rate limiting
func (bot *EnhancedDiscordBot) executeWithRateLimit(operation func() error) error {
	// Apply rate limiting
	bot.rateLimiter.Wait()

	// Execute with circuit breaker protection
	return bot.circuitBreaker.Execute(operation)
}

// validateCommandPermissions checks permissions for a command with enhanced security
func (bot *EnhancedDiscordBot) validateCommandPermissions(i *discordgo.InteractionCreate, command *Command) error {
	return bot.permissionChecker.ValidateCommandPermissions(i, command, bot.Config.AdminRoleID)
}

// Connect establishes connection to Discord and deploys slash commands
func (bot *EnhancedDiscordBot) Connect() error {
	log.Println("Connecting Discord bot...")

	err := bot.Session.Open()
	if err != nil {
		return fmt.Errorf("error opening Discord connection: %v", err)
	}

	log.Printf("Discord bot connected successfully as %s", bot.Session.State.User.Username)

	// Record bot start time
	bot.StartTime = time.Now()

	// Deploy slash commands
	err = bot.deploySlashCommands()
	if err != nil {
		log.Printf("Error sending message to Discord: %v", err)
		return err
	}

	return nil
}

// deploySlashCommands registers all slash commands with Discord
func (bot *EnhancedDiscordBot) deploySlashCommands() error {
	log.Println("Deploying slash commands...")

	var commands []*discordgo.ApplicationCommand

	bot.mu.RLock()
	for _, cmd := range bot.Commands {
		commands = append(commands, &discordgo.ApplicationCommand{
			Name:        cmd.Name,
			Description: cmd.Description,
			Options:     cmd.Options,
		})
	}
	bot.mu.RUnlock()

	// Register commands globally or for specific guild
	var err error
	if bot.Config.GuildID != "" {
		// Register for specific guild (faster for development)
		_, err = bot.Session.ApplicationCommandBulkOverwrite(bot.Session.State.User.ID, bot.Config.GuildID, commands)
	} else {
		// Register globally (takes up to 1 hour to propagate)
		_, err = bot.Session.ApplicationCommandBulkOverwrite(bot.Session.State.User.ID, "", commands)
	}

	if err != nil {
		return fmt.Errorf("error deploying slash commands: %v", err)
	}

	log.Printf("Successfully deployed %d slash commands", len(commands))
	return nil
}

// Disconnect closes the Discord connection
func (bot *EnhancedDiscordBot) Disconnect() error {
	log.Println("Disconnecting Discord bot...")
	return bot.Session.Close()
}

// ConfigData represents the persistent configuration data
// ChannelAlerts maps specific alert types to a Discord channel.
// Types is a list of keywords (e.g. wickets, milestones, toss, start, all).
type ChannelAlerts struct {
	ChannelID string   `json:"channel_id"`
	Types     []string `json:"types"`
}

type ConfigData struct {
	MonitoredTeams    []string `json:"monitored_teams"`
	AlertOnToss       bool     `json:"alert_on_toss"`
	AlertOnStart      bool     `json:"alert_on_start"`
	AlertOnWicket     bool     `json:"alert_on_wicket"`
	AlertOnScoreEvery int      `json:"alert_on_score_every"`
	CurrentMatchURL   string   `json:"current_match_url,omitempty"`

	// Discord-specific settings (optional)
	GuildID     string `json:"guild_id,omitempty"`
	ChannelID   string `json:"channel_id,omitempty"`
	AdminRoleID string `json:"admin_role_id,omitempty"`

	// Per-channel alert routing
	ChannelConfigs []ChannelAlerts `json:"channel_configs,omitempty"`
}

// loadConfig loads the current configuration from file and environment variables
func (bot *EnhancedDiscordBot) loadConfig() (*ConfigData, error) {
	config := &ConfigData{
		MonitoredTeams:    []string{"IND"}, // Default team
		AlertOnToss:       true,
		AlertOnStart:      true,
		AlertOnWicket:     true,
		AlertOnScoreEvery: 5,
		GuildID:           bot.Config.GuildID,
		ChannelID:         bot.Config.ChannelID,
		AdminRoleID:       bot.Config.AdminRoleID,
	}

	// Try to load from file first
	configPath := "bot_config.json"
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, config); err != nil {
			log.Printf("Error unmarshaling config file: %v", err)
		} else {
			log.Printf("Loaded configuration from %s", configPath)
		}
	}

	// Override with environment variables if present
	if envGuild := os.Getenv("DISCORD_GUILD_ID"); envGuild != "" {
		config.GuildID = envGuild
	}
	if envChannel := os.Getenv("DISCORD_CHANNEL_ID"); envChannel != "" {
		config.ChannelID = envChannel
	}
	if envAdminRole := os.Getenv("DISCORD_ADMIN_ROLE_ID"); envAdminRole != "" {
		config.AdminRoleID = envAdminRole
	}

	if teamsEnv := os.Getenv("MONITORED_TEAMS"); teamsEnv != "" {
		var teams []string
		for _, team := range strings.Split(teamsEnv, ",") {
			team = strings.TrimSpace(team)
			if team != "" {
				teams = append(teams, strings.ToUpper(team))
			}
		}
		if len(teams) > 0 {
			config.MonitoredTeams = teams
		}
	}

	// Ensure at least one team is monitored
	if len(config.MonitoredTeams) == 0 {
		config.MonitoredTeams = []string{"IND"}
	}

	// Ensure Guild/Channel IDs fallback to bot config if still empty
	if config.GuildID == "" {
		config.GuildID = bot.Config.GuildID
	}
	if config.ChannelID == "" {
		config.ChannelID = bot.Config.ChannelID
	}
	if config.AdminRoleID == "" {
		config.AdminRoleID = bot.Config.AdminRoleID
	}

	return config, nil
}

// saveConfig saves the configuration to file
func (bot *EnhancedDiscordBot) saveConfig(config *ConfigData) error {
	configPath := "bot_config.json"

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %v", err)
	}

	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return fmt.Errorf("error writing config file: %v", err)
	}

	log.Printf("Saved configuration to %s", configPath)
	return nil
}

// handleScoreCommand handles the /score command with optional team filtering
func (bot *EnhancedDiscordBot) handleScoreCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var teamFilter string

	// Check if team filter is provided
	if len(options) > 0 && options[0].Name == "team" {
		teamFilter = strings.ToUpper(strings.TrimSpace(options[0].StringValue()))
	}

	mu.RLock()
	defer mu.RUnlock()

	if len(matchStates) == 0 {
		bot.respondWithError(s, i, "No live matches currently being monitored")
		return
	}

	var matchesToShow []*MatchState
	for _, state := range matchStates {
		// If team filter is provided, check if either team matches
		if teamFilter != "" {
			team1Upper := strings.ToUpper(state.Team1)
			team2Upper := strings.ToUpper(state.Team2)
			if !strings.Contains(team1Upper, teamFilter) && !strings.Contains(team2Upper, teamFilter) {
				continue
			}
		}
		matchesToShow = append(matchesToShow, state)
	}

	if len(matchesToShow) == 0 {
		if teamFilter != "" {
			bot.respondWithError(s, i, fmt.Sprintf("No live matches found for team: %s", teamFilter))
		} else {
			bot.respondWithError(s, i, "No live matches currently being monitored")
		}
		return
	}

	// Create embed response with same styling as /match command
	embed := &discordgo.MessageEmbed{
		Title: "🏏 Live Cricket Scores",
		Color: 0xff9900, // Same color as /match command
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if teamFilter != "" {
		embed.Title = fmt.Sprintf("🏏 Live Cricket Scores - %s", teamFilter)
	}

	for i, state := range matchesToShow {
		// Add separator between matches if there are multiple
		if i > 0 {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
				Value:  "\u200b", // invisible space
				Inline: false,
			})
		}

		// Match title exactly like /match command
		matchTitle := fmt.Sprintf("🏏 %s vs %s", state.Team1, state.Team2)

		// Add match details as description field (exactly like /match command)
		var description strings.Builder
		if state.Status != "" {
			description.WriteString(fmt.Sprintf("**Status:** %s\n", state.Status))
		}
		if state.Series != "" {
			description.WriteString(fmt.Sprintf("**Series:** %s\n", state.Series))
		}
		if state.Format != "" {
			description.WriteString(fmt.Sprintf("**Format:** %s\n", state.Format))
		}
		if state.Venue != "" {
			description.WriteString(fmt.Sprintf("**Venue:** %s\n", state.Venue))
		}

		if description.Len() > 0 {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   matchTitle,
				Value:  description.String(),
				Inline: false,
			})
		} else {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   matchTitle,
				Value:  "\u200b", // invisible space
				Inline: false,
			})
		}

		// Score and overs (exactly like /match command)
		if state.Score != "" {
			scoreValue := state.Score
			if state.Overs != "" {
				scoreValue += fmt.Sprintf(" (%s overs)", state.Overs)
			}
			if state.RunRate != "" {
				scoreValue += fmt.Sprintf(" | CRR: %s", state.RunRate)
			}
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🏏 Current Score",
				Value:  scoreValue,
				Inline: false,
			})
		}

		// Current batsmen (exactly like /match command)
		if len(state.CurrentPlayers) > 0 {
			var batsmenValue strings.Builder
			for _, player := range state.CurrentPlayers {
				batsmenValue.WriteString(fmt.Sprintf("**%s:** %d (%d balls)\n", player.Name, player.Runs, player.Balls))
				batsmenValue.WriteString(fmt.Sprintf("4s: %d, 6s: %d\n\n", player.Fours, player.Sixes))
			}
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🏏 Current Batsmen",
				Value:  batsmenValue.String(),
				Inline: true,
			})
		}

		// Current bowler (exactly like /match command)
		if state.CurrentBowler.Name != "" {
			bowlerValue := fmt.Sprintf("**%s**\n", state.CurrentBowler.Name)
			bowlerValue += fmt.Sprintf("Overs: %s\n", state.CurrentBowler.Overs)
			bowlerValue += fmt.Sprintf("Wickets: %d\n", state.CurrentBowler.Wickets)
			bowlerValue += fmt.Sprintf("Runs: %d\n", state.CurrentBowler.Runs)
			bowlerValue += fmt.Sprintf("Maidens: %d", state.CurrentBowler.Maidens)

			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "⚾ Current Bowler",
				Value:  bowlerValue,
				Inline: true,
			})
		}

		// Partnership details (exactly like /match command)
		if state.Partnership != "" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🤝 Partnership",
				Value:  state.Partnership,
				Inline: false,
			})
		}

		// Recent overs (exactly like /match command)
		if state.RecentOvers != "" && strings.TrimSpace(state.RecentOvers) != "Recent:" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "📊 Recent Overs",
				Value:  state.RecentOvers,
				Inline: false,
			})
		}

		// Last wicket (exactly like /match command)
		if state.LastWicket != "" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🎯 Last Wicket",
				Value:  state.LastWicket,
				Inline: false,
			})
		}

		// Yet to bat (exactly like /match command)
		if state.YetToBat != "" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "⏳ Yet to Bat",
				Value:  state.YetToBat,
				Inline: false,
			})
		}

		// Toss information (exactly like /match command)
		if state.Toss != "" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🪙 Toss",
				Value:  state.Toss,
				Inline: false,
			})
		}

		// Target information (exactly like /match command)
		if state.TargetRuns > 0 && state.TargetBalls > 0 {
			rrr := float64(state.TargetRuns) / (float64(state.TargetBalls) / 6.0)
			targetValue := fmt.Sprintf("Need %d runs in %d balls\nRequired Run Rate: %.2f",
				state.TargetRuns, state.TargetBalls, rrr)
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "🎯 Target",
				Value:  targetValue,
				Inline: false,
			})
		}
	}

	bot.respondWithEmbed(s, i, embed)
}

// handleMatchesCommand handles the /matches command to list all tracked matches with IDs
func (bot *EnhancedDiscordBot) handleMatchesCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	log.Printf("🔍 MATCHES COMMAND START: User %s requested /matches", i.Member.User.ID)

	// Log timing information
	log.Printf("🕐 MATCHES COMMAND: Current time: %s", time.Now().Format("15:04:05.000"))

	// Try to acquire lock with logging
	log.Printf("🔒 MATCHES COMMAND: Attempting to acquire read lock...")
	mu.RLock()
	log.Printf("✅ MATCHES COMMAND: Read lock acquired successfully")
	defer func() {
		mu.RUnlock()
		log.Printf("🔓 MATCHES COMMAND: Read lock released")
	}()

	matchCount := len(matchStates)
	log.Printf("📊 MATCHES COMMAND: matchStates length: %d", matchCount)

	// Debug: Log memory address and detailed state info
	log.Printf("🧠 MATCHES COMMAND: matchStates map address: %p", &matchStates)

	// Log detailed information about each match
	if matchCount > 0 {
		log.Printf("📋 MATCHES COMMAND: Detailed match information:")
		for id, state := range matchStates {
			if state == nil {
				log.Printf("  ⚠️  Match %s: state is nil!", id)
				continue
			}
			log.Printf("  ✅ Match %s:", id)
			log.Printf("    - Teams: '%s' vs '%s'", state.Team1, state.Team2)
			log.Printf("    - Status: '%s'", state.Status)
			log.Printf("    - Score: '%s'", state.Score)
			log.Printf("    - Overs: '%s'", state.Overs)
			log.Printf("    - Format: '%s'", state.Format)
		}
	} else {
		log.Printf("❌ MATCHES COMMAND: matchStates is empty!")

		// Additional debugging for empty state
		log.Printf("🔍 MATCHES COMMAND: Checking if matchStates map is nil: %v", matchStates == nil)
		if matchStates != nil {
			log.Printf("🔍 MATCHES COMMAND: matchStates map capacity: %d", len(matchStates))
		}
	}

	if len(matchStates) == 0 {
		log.Printf("❌ MATCHES COMMAND: No matches found, responding with error message")
		bot.respondWithError(s, i, "No live matches currently being monitored")
		return
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📋 Tracked Live Matches",
		Description: "Use `/match <matchid>` to get detailed information about a specific match",
		Color:       0x00ff00,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	var fieldValue strings.Builder
	for matchID, state := range matchStates {
		log.Printf("✍️  MATCHES COMMAND: Building response for matchID=%s Team1=%s Team2=%s", matchID, state.Team1, state.Team2)
		fieldValue.WriteString(fmt.Sprintf("**ID:** `%s`\n", matchID))
		fieldValue.WriteString(fmt.Sprintf("**Teams:** %s vs %s\n", state.Team1, state.Team2))
		if state.Format != "" {
			fieldValue.WriteString(fmt.Sprintf("**Format:** %s\n", state.Format))
		}
		if state.Status != "" {
			fieldValue.WriteString(fmt.Sprintf("**Status:** %s\n", state.Status))
		}
		if state.Score != "" {
			fieldValue.WriteString(fmt.Sprintf("**Score:** %s", state.Score))
			if state.Overs != "" {
				fieldValue.WriteString(fmt.Sprintf(" (%s)", state.Overs))
			}
			fieldValue.WriteString("\n")
		}
		fieldValue.WriteString("\n")
	}

	embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
		Name:   "Live Matches",
		Value:  fieldValue.String(),
		Inline: false,
	})

	log.Printf("📤 MATCHES COMMAND: Sending embed response with %d matches", len(matchStates))
	bot.respondWithEmbed(s, i, embed)
	log.Printf("✅ MATCHES COMMAND: Response sent successfully")
}

// handleMatchCommand handles the /match command to get detailed match information by ID
func (bot *EnhancedDiscordBot) handleMatchCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 || options[0].Name != "matchid" {
		bot.respondWithError(s, i, "Match ID is required")
		return
	}

	// Validate match ID input
	matchID, err := bot.securityValidator.ValidateMatchID(options[0].StringValue())
	if err != nil {
		bot.respondWithUserFriendlyError(s, i, err)
		return
	}

	mu.RLock()
	state, exists := matchStates[matchID]
	mu.RUnlock()

	if !exists {
		bot.respondWithError(s, i, "Match not found. Use `/matches` to see available match IDs")
		return
	}

	// Save current match URL for scoreboard command using stored OriginalURL
	var currentMatchURL string
	if state.OriginalURL != "" {
		currentMatchURL = state.OriginalURL
		log.Printf("🔗 MATCH: Using stored original URL: %s", currentMatchURL)
	} else {
		// Fallback to constructed URL if OriginalURL not available
		currentMatchURL = fmt.Sprintf("https://www.cricbuzz.com/live-cricket-scores/%s", matchID)
		log.Printf("🔗 MATCH: Using fallback URL (no OriginalURL stored): %s", currentMatchURL)
	}
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
	} else {
		config.CurrentMatchURL = currentMatchURL
		if err := bot.saveConfig(config); err != nil {
			log.Printf("Error saving config: %v", err)
		}
	}

	// Create detailed embed response
	embed := &discordgo.MessageEmbed{
		Title: fmt.Sprintf("🏏 %s vs %s", state.Team1, state.Team2),
		Color: 0xff9900,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add match details as description
	var description strings.Builder
	if state.Status != "" {
		description.WriteString(fmt.Sprintf("**Status:** %s\n", state.Status))
	}
	if state.Series != "" {
		description.WriteString(fmt.Sprintf("**Series:** %s\n", state.Series))
	}
	if state.Format != "" {
		description.WriteString(fmt.Sprintf("**Format:** %s\n", state.Format))
	}
	if state.Venue != "" {
		description.WriteString(fmt.Sprintf("**Venue:** %s\n", state.Venue))
	}
	embed.Description = description.String()

	// Score and overs
	if state.Score != "" {
		scoreValue := state.Score
		if state.Overs != "" {
			scoreValue += fmt.Sprintf(" (%s overs)", state.Overs)
		}
		if state.RunRate != "" {
			scoreValue += fmt.Sprintf(" | CRR: %s", state.RunRate)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🏏 Current Score",
			Value:  scoreValue,
			Inline: false,
		})
	}

	// Current batsmen
	if len(state.CurrentPlayers) > 0 {
		var batsmenValue strings.Builder
		for _, player := range state.CurrentPlayers {
			batsmenValue.WriteString(fmt.Sprintf("**%s:** %d (%d balls)\n", player.Name, player.Runs, player.Balls))
			batsmenValue.WriteString(fmt.Sprintf("4s: %d, 6s: %d\n\n", player.Fours, player.Sixes))
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🏏 Current Batsmen",
			Value:  batsmenValue.String(),
			Inline: true,
		})
	}

	// Current bowler
	if state.CurrentBowler.Name != "" {
		bowlerValue := fmt.Sprintf("**%s**\n", state.CurrentBowler.Name)
		bowlerValue += fmt.Sprintf("Overs: %s\n", state.CurrentBowler.Overs)
		bowlerValue += fmt.Sprintf("Wickets: %d\n", state.CurrentBowler.Wickets)
		bowlerValue += fmt.Sprintf("Runs: %d\n", state.CurrentBowler.Runs)
		bowlerValue += fmt.Sprintf("Maidens: %d", state.CurrentBowler.Maidens)

		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⚾ Current Bowler",
			Value:  bowlerValue,
			Inline: true,
		})
	}

	// Partnership details
	if state.Partnership != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🤝 Partnership",
			Value:  state.Partnership,
			Inline: false,
		})
	}

	// Recent overs
	if state.RecentOvers != "" && strings.TrimSpace(state.RecentOvers) != "Recent:" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "📊 Recent Overs",
			Value:  state.RecentOvers,
			Inline: false,
		})
	}

	// Last wicket
	if state.LastWicket != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🎯 Last Wicket",
			Value:  state.LastWicket,
			Inline: false,
		})
	}

	// Yet to bat
	if state.YetToBat != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⏳ Yet to Bat",
			Value:  state.YetToBat,
			Inline: false,
		})
	}

	// Toss information
	if state.Toss != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🪙 Toss",
			Value:  state.Toss,
			Inline: false,
		})
	}

	// Target information (if chasing)
	if state.TargetRuns > 0 && state.TargetBalls > 0 {
		rrr := float64(state.TargetRuns) / (float64(state.TargetBalls) / 6.0)
		targetValue := fmt.Sprintf("Need %d runs in %d balls\nRequired Run Rate: %.2f",
			state.TargetRuns, state.TargetBalls, rrr)
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🎯 Target",
			Value:  targetValue,
			Inline: false,
		})
	}

	bot.respondWithEmbed(s, i, embed)
}

func (bot *EnhancedDiscordBot) handleScoreboardCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Load config to get current match URL
	config, err := bot.loadConfig()
	if err != nil {
		bot.respondWithError(s, i, "Error loading configuration")
		return
	}
	if config.CurrentMatchURL == "" {
		bot.respondWithError(s, i, "Brotherman, I don't have a current match set! Please use `/match` first to set a match.")
		return
	}

	// Debug: Log the current match URL
	log.Printf("🔍 SCOREBOARD: Current match URL: %s", config.CurrentMatchURL)

	// Transform live-cricket-scores URL to live-cricket-scorecard URL
	scoreboardURL := strings.Replace(config.CurrentMatchURL, "/live-cricket-scores/", "/live-cricket-scorecard/", 1)

	// Debug: Log the transformed URL
	log.Printf("🔄 SCOREBOARD: Transformed URL: %s", scoreboardURL)

	// Validate that the transformation worked
	if scoreboardURL == config.CurrentMatchURL {
		log.Printf("⚠️  SCOREBOARD: URL transformation failed - URLs are identical")
		// Try alternative URL patterns
		if strings.Contains(config.CurrentMatchURL, "/cricket-scores/") {
			scoreboardURL = strings.Replace(config.CurrentMatchURL, "/cricket-scores/", "/live-cricket-scorecard/", 1)
			log.Printf("🔄 SCOREBOARD: Trying alternative transformation: %s", scoreboardURL)
		} else {
			// If simple URL, try to enhance it with /scorecard suffix
			scoreboardURL = strings.Replace(config.CurrentMatchURL, "/live-cricket-scores/", "/live-cricket-scorecard/", 1)
		}
	}

	// Try multiple URL patterns if the first one fails
	urlsToTry := []string{scoreboardURL}

	// If the URL doesn't have match details, try adding some common patterns
	if !strings.Contains(scoreboardURL, "-vs-") {
		// Extract match ID from URL
		matchIDPattern := regexp.MustCompile(`/(\d+)(?:/|$)`)
		if matches := matchIDPattern.FindStringSubmatch(scoreboardURL); len(matches) > 1 {
			matchID := matches[1]
			// Try simple pattern first
			urlsToTry = append(urlsToTry, fmt.Sprintf("https://www.cricbuzz.com/live-cricket-scorecard/%s", matchID))
		}
	}

	// Try fetching from multiple URL patterns
	var resp *http.Response
	var finalURL string
	var lastError error

	for i, url := range urlsToTry {
		log.Printf("🌍 SCOREBOARD: Attempt %d - Fetching URL: %s", i+1, url)
		if !strings.HasPrefix(url, "https://www.cricbuzz.com/") {
			log.Printf("❌ SCOREBOARD: URL not allowed: %s", url)
			lastError = fmt.Errorf("disallowed domain")
			continue
		}
		// Domain is validated above
		resp, err = http.Get(url) // #nosec G107
		if err != nil {
			log.Printf("❌ SCOREBOARD: Network error for URL %s: %v", url, err)
			lastError = err
			continue
		}

		if resp.StatusCode == 200 {
			finalURL = url
			log.Printf("✅ SCOREBOARD: Success with URL: %s", url)
			break
		} else {
			log.Printf("📟 SCOREBOARD: HTTP %d for URL: %s", resp.StatusCode, url)
			if errClose := resp.Body.Close(); errClose != nil {
				log.Printf("Error closing response body: %v", errClose)
			}
			lastError = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}

	if resp == nil || resp.StatusCode != 200 {
		if lastError != nil {
			log.Printf("❌ SCOREBOARD: All URLs failed, last error: %v", lastError)
			bot.respondWithError(s, i, fmt.Sprintf("😔 Couldn't fetch the detailed scorecard, brotherman! \n\n**What happened:** The scorecard page isn't available (might be too early in the match or the match format doesn't support detailed scorecards).\n\n**What you can do:**\n• Use `/match` to get the live score instead\n• Try again later when more match data is available\n• The match might be too new or already finished\n\n**Technical details:** %v", lastError))
		} else {
			bot.respondWithError(s, i, "😔 Couldn't fetch the detailed scorecard, brotherman! \n\n**What happened:** The scorecard page isn't available right now.\n\n**What you can do:**\n• Use `/match` to get the live score instead\n• Try again later when the match has more data\n• Check if the match is still active")
		}
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	log.Printf("🎉 SCOREBOARD: Successfully fetched scorecard from: %s", finalURL)

	// Parse the HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		bot.respondWithError(s, i, "Failed to parse scorecard: "+err.Error())
		return
	}

	// Parse the scorecard data using scorecard page parser
	state := parseScoreboardPage(doc)

	// Create detailed embed response identical to /match command
	embed := &discordgo.MessageEmbed{
		Title: fmt.Sprintf("🏏 %s vs %s", state.Team1, state.Team2),
		Color: 0xff9900,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add match details as description (exactly like /match command)
	var description strings.Builder
	if state.Status != "" {
		description.WriteString(fmt.Sprintf("**Status:** %s\n", state.Status))
	}
	if state.Series != "" {
		description.WriteString(fmt.Sprintf("**Series:** %s\n", state.Series))
	}
	if state.Format != "" {
		description.WriteString(fmt.Sprintf("**Format:** %s\n", state.Format))
	}
	if state.Venue != "" {
		description.WriteString(fmt.Sprintf("**Venue:** %s\n", state.Venue))
	}
	embed.Description = description.String()

	// Score and overs (exactly like /match command)
	if state.Score != "" {
		scoreValue := state.Score
		if state.Overs != "" {
			scoreValue += fmt.Sprintf(" (%s overs)", state.Overs)
		}
		if state.RunRate != "" {
			scoreValue += fmt.Sprintf(" | CRR: %s", state.RunRate)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🏏 Current Score",
			Value:  scoreValue,
			Inline: false,
		})
	}

	// Current batsmen (exactly like /match command)
	if len(state.CurrentPlayers) > 0 {
		var batsmenValue strings.Builder
		for _, player := range state.CurrentPlayers {
			batsmenValue.WriteString(fmt.Sprintf("**%s:** %d (%d balls)\n", player.Name, player.Runs, player.Balls))
			batsmenValue.WriteString(fmt.Sprintf("4s: %d, 6s: %d\n\n", player.Fours, player.Sixes))
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🏏 Current Batsmen",
			Value:  batsmenValue.String(),
			Inline: true,
		})
	}

	// Current bowler (exactly like /match command)
	if state.CurrentBowler.Name != "" {
		bowlerValue := fmt.Sprintf("**%s**\n", state.CurrentBowler.Name)
		bowlerValue += fmt.Sprintf("Overs: %s\n", state.CurrentBowler.Overs)
		bowlerValue += fmt.Sprintf("Wickets: %d\n", state.CurrentBowler.Wickets)
		bowlerValue += fmt.Sprintf("Runs: %d\n", state.CurrentBowler.Runs)
		bowlerValue += fmt.Sprintf("Maidens: %d", state.CurrentBowler.Maidens)

		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⚾ Current Bowler",
			Value:  bowlerValue,
			Inline: true,
		})
	}

	// Partnership details (exactly like /match command)
	if state.Partnership != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🤝 Partnership",
			Value:  state.Partnership,
			Inline: false,
		})
	}

	// Recent overs (exactly like /match command)
	if state.RecentOvers != "" && strings.TrimSpace(state.RecentOvers) != "Recent:" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "📊 Recent Overs",
			Value:  state.RecentOvers,
			Inline: false,
		})
	}

	// Last wicket (exactly like /match command)
	if state.LastWicket != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🎯 Last Wicket",
			Value:  state.LastWicket,
			Inline: false,
		})
	}

	// Yet to bat (exactly like /match command)
	if state.YetToBat != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⏳ Yet to Bat",
			Value:  state.YetToBat,
			Inline: false,
		})
	}

	// Toss information (exactly like /match command)
	if state.Toss != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🪙 Toss",
			Value:  state.Toss,
			Inline: false,
		})
	}

	// Target information (exactly like /match command)
	if state.TargetRuns > 0 && state.TargetBalls > 0 {
		rrr := float64(state.TargetRuns) / (float64(state.TargetBalls) / 6.0)
		targetValue := fmt.Sprintf("Need %d runs in %d balls\nRequired Run Rate: %.2f",
			state.TargetRuns, state.TargetBalls, rrr)
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🎯 Target",
			Value:  targetValue,
			Inline: false,
		})
	}

	bot.respondWithEmbed(s, i, embed)
}

// handleMonitorCommand handles the /monitor command for managing monitored teams
func (bot *EnhancedDiscordBot) handleMonitorCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 {
		bot.respondWithError(s, i, "Action is required. Use add, remove, or list")
		return
	}

	action := strings.ToLower(strings.TrimSpace(options[0].StringValue()))

	switch action {
	case "add":
		bot.handleMonitorAdd(s, i, options)
	case "remove":
		bot.handleMonitorRemove(s, i, options)
	case "list":
		bot.handleMonitorList(s, i)
	default:
		bot.respondWithError(s, i, "Invalid action. Use add, remove, or list")
	}
}

// handleMonitorAdd adds a team to the monitoring list
func (bot *EnhancedDiscordBot) handleMonitorAdd(s *discordgo.Session, i *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	// Find team parameter
	var teamName string
	for _, option := range options {
		if option.Name == "team" {
			teamName = strings.TrimSpace(option.StringValue())
			break
		}
	}

	if teamName == "" {
		bot.respondWithError(s, i, "Team name is required for add action")
		return
	}

	// Normalize team name to uppercase for consistency
	// Validate team code
	var errVal error
	teamName, errVal = ValidateTeamCode(teamName)
	if errVal != nil {
		bot.respondWithError(s, i, errVal.Error())
		return
	}

	// Load current configuration
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondWithError(s, i, "Failed to load configuration")
		return
	}

	// Check if team is already monitored
	for _, existingTeam := range config.MonitoredTeams {
		if strings.ToUpper(existingTeam) == teamName {
			bot.respondWithError(s, i, fmt.Sprintf("Team %s is already being monitored", teamName))
			return
		}
	}

	// Add team to monitored list
	config.MonitoredTeams = append(config.MonitoredTeams, teamName)

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondWithError(s, i, "Failed to save configuration")
		return
	}

	bot.respondWithSuccess(s, i, fmt.Sprintf("Successfully added %s to monitored teams", teamName))
	log.Printf("Added team %s to monitoring list", teamName)
}

// handleMonitorRemove removes a team from the monitoring list
func (bot *EnhancedDiscordBot) handleMonitorRemove(s *discordgo.Session, i *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	// Find team parameter
	var teamName string
	for _, option := range options {
		if option.Name == "team" {
			teamName = strings.TrimSpace(option.StringValue())
			break
		}
	}

	if teamName == "" {
		bot.respondWithError(s, i, "Team name is required for remove action")
		return
	}

	// Normalize team name to uppercase for consistency
	// Validate team code
	var errVal error
	teamName, errVal = ValidateTeamCode(teamName)
	if errVal != nil {
		bot.respondWithError(s, i, errVal.Error())
		return
	}

	// Load current configuration
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondWithError(s, i, "Failed to load configuration")
		return
	}

	// Find and remove team from monitored list
	found := false
	newTeams := make([]string, 0, len(config.MonitoredTeams))
	for _, existingTeam := range config.MonitoredTeams {
		if strings.ToUpper(existingTeam) != teamName {
			newTeams = append(newTeams, existingTeam)
		} else {
			found = true
		}
	}

	if !found {
		bot.respondWithError(s, i, fmt.Sprintf("Team %s is not currently being monitored", teamName))
		return
	}

	// Prevent removing all teams (keep at least one)
	if len(newTeams) == 0 {
		bot.respondWithError(s, i, "Cannot remove all monitored teams. At least one team must be monitored")
		return
	}

	config.MonitoredTeams = newTeams

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondWithError(s, i, "Failed to save configuration")
		return
	}

	bot.respondWithSuccess(s, i, fmt.Sprintf("Successfully removed %s from monitored teams", teamName))
	log.Printf("Removed team %s from monitoring list", teamName)
}

// handleMonitorList displays all currently monitored teams
func (bot *EnhancedDiscordBot) handleMonitorList(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Load current configuration
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondWithError(s, i, "Failed to load configuration")
		return
	}

	if len(config.MonitoredTeams) == 0 {
		bot.respondWithError(s, i, "No teams are currently being monitored")
		return
	}

	// Create embed response
	embed := &discordgo.MessageEmbed{
		Title:       "📋 Monitored Teams",
		Description: "Teams currently being monitored for cricket alerts",
		Color:       0x00ff00,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	var teamsValue strings.Builder
	for i, team := range config.MonitoredTeams {
		teamsValue.WriteString(fmt.Sprintf("%d. **%s**\n", i+1, team))
	}

	embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
		Name:   fmt.Sprintf("Teams (%d)", len(config.MonitoredTeams)),
		Value:  teamsValue.String(),
		Inline: false,
	})

	bot.respondWithEmbed(s, i, embed)
}

// handleAlertsCommand handles the /alerts command for configuring alert preferences
func (bot *EnhancedDiscordBot) handleAlertsCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 {
		bot.respondWithError(s, i, "Action is required. Use 'config' to configure alert settings")
		return
	}

	action := strings.ToLower(strings.TrimSpace(options[0].StringValue()))

	switch action {
	case "config":
		bot.handleAlertsConfig(s, i)
	default:
		bot.respondWithError(s, i, "Invalid action. Use 'config' to configure alert settings")
	}
}

// handleAlertsConfig shows the current alert configuration with interactive toggles
func (bot *EnhancedDiscordBot) handleAlertsConfig(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Load current configuration
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondWithError(s, i, "Failed to load current configuration")
		return
	}

	// Create embed with current settings
	embed := &discordgo.MessageEmbed{
		Title:       "⚙️ Alert Configuration",
		Description: "Current alert preferences for this server. Use the buttons below to toggle settings.",
		Color:       0x9932cc,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Admin only • Changes are saved automatically",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add current settings as fields
	embed.Fields = []*discordgo.MessageEmbedField{
		{
			Name:   "🪙 Toss Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnToss),
			Inline: true,
		},
		{
			Name:   "🏏 Match Start Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnStart),
			Inline: true,
		},
		{
			Name:   "🎯 Wicket Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnWicket),
			Inline: true,
		},
		{
			Name:   "📊 Score Alert Frequency",
			Value:  fmt.Sprintf("Every %d runs", config.AlertOnScoreEvery),
			Inline: true,
		},
	}

	// Create action buttons
	components := []discordgo.MessageComponent{
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.Button{
					CustomID: "toggle_toss",
					Label:    bot.getToggleButtonLabel("Toss", config.AlertOnToss),
					Style:    bot.getToggleButtonStyle(config.AlertOnToss),
					Emoji:    &discordgo.ComponentEmoji{Name: "🪙"},
				},
				discordgo.Button{
					CustomID: "toggle_start",
					Label:    bot.getToggleButtonLabel("Start", config.AlertOnStart),
					Style:    bot.getToggleButtonStyle(config.AlertOnStart),
					Emoji:    &discordgo.ComponentEmoji{Name: "🏏"},
				},
				discordgo.Button{
					CustomID: "toggle_wicket",
					Label:    bot.getToggleButtonLabel("Wickets", config.AlertOnWicket),
					Style:    bot.getToggleButtonStyle(config.AlertOnWicket),
					Emoji:    &discordgo.ComponentEmoji{Name: "🎯"},
				},
			},
		},
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.Button{
					CustomID: "score_freq_decrease",
					Label:    "- Frequency",
					Style:    discordgo.SecondaryButton,
					Emoji:    &discordgo.ComponentEmoji{Name: "➖"},
				},
				discordgo.Button{
					CustomID: "score_freq_current",
					Label:    fmt.Sprintf("Every %d runs", config.AlertOnScoreEvery),
					Style:    discordgo.SecondaryButton,
					Disabled: true,
				},
				discordgo.Button{
					CustomID: "score_freq_increase",
					Label:    "+ Frequency",
					Style:    discordgo.SecondaryButton,
					Emoji:    &discordgo.ComponentEmoji{Name: "➕"},
				},
			},
		},
	}

	// Send response with embed and components
	err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds:     []*discordgo.MessageEmbed{embed},
			Components: components,
		},
	})
	if err != nil {
		log.Printf("Error responding to alerts config interaction: %v", err)
	}
}

// getBooleanStatusText returns a formatted status text for boolean settings
func (bot *EnhancedDiscordBot) getBooleanStatusText(enabled bool) string {
	if enabled {
		return "✅ **Enabled**"
	}
	return "❌ **Disabled**"
}

// getToggleButtonLabel returns the appropriate label for toggle buttons
func (bot *EnhancedDiscordBot) getToggleButtonLabel(name string, enabled bool) string {
	if enabled {
		return fmt.Sprintf("Disable %s", name)
	}
	return fmt.Sprintf("Enable %s", name)
}

// getToggleButtonStyle returns the appropriate style for toggle buttons
func (bot *EnhancedDiscordBot) getToggleButtonStyle(enabled bool) discordgo.ButtonStyle {
	if enabled {
		return discordgo.DangerButton
	}
	return discordgo.SuccessButton
}

// SendAlertWithMentions sends an alert to Discord with user mentions for subscribed users
// sendMessageWithRetry sends a message and retries on Discord rate-limit errors with exponential backoff.
func (bot *EnhancedDiscordBot) sendMessageWithRetry(msg *discordgo.MessageSend) error {
	const maxAttempts = 3
	delay := time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		_, err := bot.Session.ChannelMessageSendComplex(bot.Config.ChannelID, msg)
		if err == nil {
			return nil
		}

		// Check for RESTError to detect rate limiting
		if restErr, ok := err.(*discordgo.RESTError); ok {
			// Discordgo fills RetryAfter for rate limit responses (status 429)
			if restErr.Response != nil && restErr.Response.StatusCode == 429 {
				// Respect Retry-After header if provided
				if ra := restErr.Response.Header.Get("Retry-After"); ra != "" {
					if secs, errConv := strconv.ParseFloat(ra, 64); errConv == nil {
						// Add small buffer of 0.5s
						time.Sleep(time.Duration((secs + 0.5) * float64(time.Second)))
					} else {
						time.Sleep(delay)
						delay *= 2
					}
				} else {
					// Fallback exponential backoff
					time.Sleep(delay)
					delay *= 2
				}
				continue
			}
		}
		// Non rate-limit error, return
		return err
	}
	return fmt.Errorf("failed to send message after retries due to rate limit")
}

func (bot *EnhancedDiscordBot) SendAlertWithMentions(title string, color int, state *MatchState, alertType SubscriptionType) error {
	if bot.Session == nil || bot.Config.ChannelID == "" {
		return fmt.Errorf("bot not properly initialized or channel ID not set")
	}

	// Get subscribed users for this alert type
	subscribedUsers := bot.Subscribers.GetSubscribedUsers(alertType)

	// Create embed similar to webhook alerts
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: fmt.Sprintf("%s v %s\n%s", state.Team1, state.Team2, state.Status),
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add fields similar to webhook alerts
	if state.Score != "" {
		scoreValue := fmt.Sprintf("%s (%s)", state.Score, state.Overs)
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🏏 Score",
			Value:  scoreValue,
			Inline: false,
		})
	}

	if state.RunRate != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Run Rate",
			Value:  state.RunRate,
			Inline: false,
		})
	}

	// Current batsmen
	if len(state.CurrentPlayers) > 0 {
		var batsmenValue strings.Builder
		for _, p := range state.CurrentPlayers {
			batsmenValue.WriteString(fmt.Sprintf("**%s**: %d (%d) - 4s: %d, 6s: %d\n", p.Name, p.Runs, p.Balls, p.Fours, p.Sixes))
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Batsmen",
			Value:  batsmenValue.String(),
			Inline: false,
		})
	}

	// Current bowler
	if state.CurrentBowler.Name != "" {
		bowlerValue := fmt.Sprintf("**%s**: %d-%d (%s)", state.CurrentBowler.Name, state.CurrentBowler.Wickets, state.CurrentBowler.Runs, state.CurrentBowler.Overs)
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Bowler",
			Value:  bowlerValue,
			Inline: false,
		})
	}

	// Partnership
	if state.Partnership != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Partnership",
			Value:  state.Partnership,
			Inline: false,
		})
	}

	// Last wicket
	if state.LastWicket != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Last Wicket",
			Value:  state.LastWicket,
			Inline: false,
		})
	}

	// Recent overs
	if state.RecentOvers != "" && strings.TrimSpace(state.RecentOvers) != "Recent:" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Recent Overs",
			Value:  state.RecentOvers,
			Inline: false,
		})
	}

	// Toss
	if state.Toss != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Toss",
			Value:  state.Toss,
			Inline: false,
		})
	}

	// Venue and other details
	if state.Venue != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Venue",
			Value:  state.Venue,
			Inline: false,
		})
	}

	if state.Series != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Series",
			Value:  state.Series,
			Inline: false,
		})
	}

	if state.Format != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Format",
			Value:  state.Format,
			Inline: true,
		})
	}

	// Chase requirements
	if state.TargetRuns > 0 && state.TargetBalls > 0 {
		rrr := float64(state.TargetRuns) / (float64(state.TargetBalls) / 6.0)
		chase := fmt.Sprintf("%d off %d  |  RRR %.2f", state.TargetRuns, state.TargetBalls, rrr)
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Target",
			Value:  chase,
			Inline: false,
		})
	}

	// Fall of wickets for wicket alerts
	if strings.Contains(strings.ToLower(title), "wicket") && state.LastFoW != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Fall of Wickets",
			Value:  state.LastFoW,
			Inline: false,
		})
	}

	// Create content with user mentions
	var content string
	if len(subscribedUsers) > 0 {
		var mentions []string
		for _, userID := range subscribedUsers {
			mentions = append(mentions, fmt.Sprintf("<@%s>", userID))
		}
		content = strings.Join(mentions, " ")
	}

	// Send the message
	err := bot.sendMessageWithRetry(&discordgo.MessageSend{
		Content: content,
		Embeds:  []*discordgo.MessageEmbed{embed},
	})

	if err != nil {
		return fmt.Errorf("failed to send Discord message: %v", err)
	}

	log.Printf("Sent bot alert: %s (mentioned %d users)", title, len(subscribedUsers))
	return nil
}

func (bot *EnhancedDiscordBot) handleSubscribeCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 || options[0].Name != "type" {
		bot.respondWithError(s, i, "Subscription type is required")
		return
	}

	// Validate subscription type with enhanced security
	subscriptionType, err := bot.securityValidator.ValidateSubscriptionType(options[0].StringValue())
	if err != nil {
		bot.respondWithUserFriendlyError(s, i, err)
		return
	}

	userID := i.Member.User.ID

	// Check if user is already subscribed
	if bot.Subscribers.IsUserSubscribed(userID, subscriptionType) {
		bot.respondWithError(s, i, fmt.Sprintf("You are already subscribed to %s alerts", subscriptionType))
		return
	}

	// Subscribe the user
	err = bot.Subscribers.Subscribe(userID, subscriptionType)
	if err != nil {
		bot.logger.LogError("handleSubscribeCommand", err, map[string]interface{}{
			"user_id": userID,
			"type":    subscriptionType,
		})
		bot.respondWithUserFriendlyError(s, i, NewUserFriendlyError(
			err,
			"Failed to process your subscription. Please try again.",
			"Try the command again in a few moments",
			"Contact an administrator if the problem persists",
		))
		return
	}

	// Log successful subscription
	bot.logger.LogInfo("handleSubscribeCommand", "User subscribed successfully", map[string]interface{}{
		"user_id": userID,
		"type":    subscriptionType,
	})
	// Create success response with subscription details
	embed := &discordgo.MessageEmbed{
		Title:       "✅ Subscription Added",
		Description: fmt.Sprintf("You have successfully subscribed to **%s** alerts!", subscriptionType),
		Color:       0x00ff00,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "You will now be mentioned when these alerts are sent",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add information about what this subscription includes
	var alertInfo string
	switch subscriptionType {
	case SubMilestones:
		alertInfo = "You'll be notified when players reach significant milestones (50s, 100s, etc.)"
	case SubWickets:
		alertInfo = "You'll be notified when wickets fall during matches"
	case SubToss:
		alertInfo = "You'll be notified when the toss results are announced"
	case SubStart:
		alertInfo = "You'll be notified when matches start"
	}

	embed.Fields = []*discordgo.MessageEmbedField{
		{
			Name:   fmt.Sprintf("📢 %s Alerts", toTitle(string(subscriptionType))),
			Value:  alertInfo,
			Inline: false,
		},
	}

	bot.respondWithEmbed(s, i, embed)
	log.Printf("User %s subscribed to %s alerts", userID, subscriptionType)
}

func (bot *EnhancedDiscordBot) handleUnsubscribeCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 || options[0].Name != "type" {
		bot.respondWithError(s, i, "Subscription type is required")
		return
	}

	// Validate subscription type with enhanced security
	subscriptionType, err := bot.securityValidator.ValidateSubscriptionType(options[0].StringValue())
	if err != nil {
		bot.respondWithUserFriendlyError(s, i, err)
		return
	}

	userID := i.Member.User.ID

	// Check if user is subscribed to this type
	if !bot.Subscribers.IsUserSubscribed(userID, subscriptionType) {
		bot.respondWithError(s, i, fmt.Sprintf("You are not subscribed to %s alerts", subscriptionType))
		return
	}

	// Unsubscribe the user
	err = bot.Subscribers.Unsubscribe(userID, subscriptionType)
	if err != nil {
		bot.logger.LogError("handleUnsubscribeCommand", err, map[string]interface{}{
			"user_id": userID,
			"type":    subscriptionType,
		})
		bot.respondWithUserFriendlyError(s, i, NewUserFriendlyError(
			err,
			"Failed to process your unsubscription. Please try again.",
			"Try the command again in a few moments",
			"Contact an administrator if the problem persists",
		))
		return
	}

	// Log successful unsubscription
	bot.logger.LogInfo("handleUnsubscribeCommand", "User unsubscribed successfully", map[string]interface{}{
		"user_id": userID,
		"type":    subscriptionType,
	})
	// Create success response
	embed := &discordgo.MessageEmbed{
		Title:       "✅ Subscription Removed",
		Description: fmt.Sprintf("You have been unsubscribed from **%s** alerts.", subscriptionType),
		Color:       0xff9900,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "You will no longer be mentioned for these alerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	embed.Fields = []*discordgo.MessageEmbedField{
		{
			Name:   "📭 Unsubscribed",
			Value:  fmt.Sprintf("You will no longer receive %s alerts", subscriptionType),
			Inline: false,
		},
	}

	bot.respondWithEmbed(s, i, embed)
	log.Printf("User %s unsubscribed from %s alerts", userID, subscriptionType)
}

func (bot *EnhancedDiscordBot) handleSubscriptionsCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	userID := i.Member.User.ID
	userSubs := bot.Subscribers.GetUserSubscriptions(userID)

	embed := &discordgo.MessageEmbed{
		Title: "📋 Your Subscription Status",
		Color: 0x0099ff,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Use /subscribe or /unsubscribe to manage your alerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if len(userSubs) == 0 {
		embed.Description = "You are not currently subscribed to any cricket alerts."
		embed.Fields = []*discordgo.MessageEmbedField{
			{
				Name:   "💡 Available Subscriptions",
				Value:  "• **milestones** - Player milestone alerts (50s, 100s, etc.)\n• **wickets** - Wicket fall alerts\n• **toss** - Toss result alerts\n• **start** - Match start alerts",
				Inline: false,
			},
			{
				Name:   "🔔 Get Started",
				Value:  "Use `/subscribe <type>` to start receiving alerts!\nExample: `/subscribe wickets`",
				Inline: false,
			},
		}
	} else {
		embed.Description = fmt.Sprintf("You are subscribed to **%d** alert type(s). You will be mentioned when these alerts are sent.", len(userSubs))

		// Create active subscriptions field
		var activeSubsValue strings.Builder
		for _, sub := range userSubs {
			var description string
			switch sub {
			case SubMilestones:
				description = "Player milestone alerts (50s, 100s, etc.)"
			case SubWickets:
				description = "Wicket fall alerts"
			case SubToss:
				description = "Toss result alerts"
			case SubStart:
				description = "Match start alerts"
			}
			activeSubsValue.WriteString(fmt.Sprintf("✅ **%s** - %s\n", sub, description))
		}

		embed.Fields = []*discordgo.MessageEmbedField{
			{
				Name:   "🔔 Active Subscriptions",
				Value:  activeSubsValue.String(),
				Inline: false,
			},
		}

		// Add available subscriptions if user isn't subscribed to all types
		allTypes := []SubscriptionType{SubMilestones, SubWickets, SubToss, SubStart}
		var availableTypes []SubscriptionType
		for _, availableType := range allTypes {
			subscribed := false
			for _, userSub := range userSubs {
				if userSub == availableType {
					subscribed = true
					break
				}
			}
			if !subscribed {
				availableTypes = append(availableTypes, availableType)
			}
		}

		if len(availableTypes) > 0 {
			var availableValue strings.Builder
			for _, availableType := range availableTypes {
				var description string
				switch availableType {
				case SubMilestones:
					description = "Player milestone alerts (50s, 100s, etc.)"
				case SubWickets:
					description = "Wicket fall alerts"
				case SubToss:
					description = "Toss result alerts"
				case SubStart:
					description = "Match start alerts"
				}
				availableValue.WriteString(fmt.Sprintf("⭕ **%s** - %s\n", availableType, description))
			}

			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "📢 Available Subscriptions",
				Value:  availableValue.String(),
				Inline: false,
			})
		}
	}

	bot.respondWithEmbed(s, i, embed)
}

// MonitoringService represents the cricket monitoring service control
type MonitoringService struct {
	isRunning   bool
	startTime   time.Time
	stopChannel chan bool
	mu          sync.RWMutex
}

var (
	monitoringService = &MonitoringService{
		isRunning:   true, // Initially running
		startTime:   time.Now(),
		stopChannel: make(chan bool, 1),
	}
)

// handleBotCommand handles the /bot command for controlling monitoring service
func (bot *EnhancedDiscordBot) handleBotCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	if len(options) == 0 || options[0].Name != "action" {
		bot.respondWithError(s, i, "Action is required. Use start, stop, status, or restart")
		return
	}

	action := strings.TrimSpace(options[0].StringValue())

	switch action {
	case "start":
		bot.handleBotStart(s, i)
	case "stop":
		bot.handleBotStop(s, i)
	case "status":
		bot.handleBotStatus(s, i)
	case "restart":
		bot.handleBotRestart(s, i)
	default:
		bot.respondWithError(s, i, "Invalid action. Use start, stop, status, or restart")
	}
}

// handleBotStart starts the cricket monitoring service
func (bot *EnhancedDiscordBot) handleBotStart(s *discordgo.Session, i *discordgo.InteractionCreate) {
	monitoringService.mu.Lock()
	defer monitoringService.mu.Unlock()

	if monitoringService.isRunning {
		bot.respondWithError(s, i, "Cricket monitoring is already running")
		return
	}

	// Start monitoring service
	monitoringService.isRunning = true
	monitoringService.startTime = time.Now()
	monitoringService.stopChannel = make(chan bool, 1)

	// Create success embed
	embed := &discordgo.MessageEmbed{
		Title:       "✅ Monitoring Started",
		Description: "Cricket score monitoring has been started successfully",
		Color:       0x00ff00,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "🟢 Status",
				Value:  "Running",
				Inline: true,
			},
			{
				Name:   "⏰ Started At",
				Value:  monitoringService.startTime.Format("15:04:05 MST"),
				Inline: true,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Monitoring service is now active",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	bot.respondWithEmbed(s, i, embed)
	log.Printf("Cricket monitoring started by admin user %s", i.Member.User.ID)
}

// handleBotStop stops the cricket monitoring service
func (bot *EnhancedDiscordBot) handleBotStop(s *discordgo.Session, i *discordgo.InteractionCreate) {
	monitoringService.mu.Lock()
	defer monitoringService.mu.Unlock()

	if !monitoringService.isRunning {
		bot.respondWithError(s, i, "Cricket monitoring is already stopped")
		return
	}

	// Stop monitoring service
	monitoringService.isRunning = false
	uptime := time.Since(monitoringService.startTime)

	// Send stop signal (non-blocking)
	select {
	case monitoringService.stopChannel <- true:
	default:
	}

	// Create success embed
	embed := &discordgo.MessageEmbed{
		Title:       "⏹️ Monitoring Stopped",
		Description: "Cricket score monitoring has been stopped",
		Color:       0xff9900,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "🔴 Status",
				Value:  "Stopped",
				Inline: true,
			},
			{
				Name:   "⏱️ Uptime",
				Value:  formatDuration(uptime),
				Inline: true,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Monitoring service has been paused",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	bot.respondWithEmbed(s, i, embed)
	log.Printf("Cricket monitoring stopped by admin user %s", i.Member.User.ID)
}

// handleBotStatus reports the current monitoring status and uptime
func (bot *EnhancedDiscordBot) handleBotStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	monitoringService.mu.RLock()
	defer monitoringService.mu.RUnlock()

	var statusText, statusEmoji string
	var statusColor int
	var uptime time.Duration

	if monitoringService.isRunning {
		statusText = "Running"
		statusEmoji = "🟢"
		statusColor = 0x00ff00
		uptime = time.Since(monitoringService.startTime)
	} else {
		statusText = "Stopped"
		statusEmoji = "🔴"
		statusColor = 0xff0000
		uptime = 0
	}

	// Get current match count
	mu.RLock()
	matchCount := len(matchStates)
	mu.RUnlock()

	// Load current configuration to show monitored teams
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config for status: %v", err)
		config = &ConfigData{MonitoredTeams: []string{"IND"}}
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📊 Bot Monitoring Status",
		Description: "Current status of the cricket monitoring service",
		Color:       statusColor,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   fmt.Sprintf("%s Status", statusEmoji),
				Value:  statusText,
				Inline: true,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Cricket monitoring service",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add uptime if running
	if monitoringService.isRunning {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⏱️ Uptime",
			Value:  formatDuration(uptime),
			Inline: true,
		})
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⏰ Started At",
			Value:  monitoringService.startTime.Format("15:04:05 MST"),
			Inline: true,
		})
	}

	// Add monitored teams
	teamsText := strings.Join(config.MonitoredTeams, ", ")
	if teamsText == "" {
		teamsText = "None configured"
	}
	embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
		Name:   "🏏 Monitored Teams",
		Value:  teamsText,
		Inline: false,
	})

	// Add current matches
	embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
		Name:   "📋 Active Matches",
		Value:  fmt.Sprintf("%d live matches being tracked", matchCount),
		Inline: true,
	})

	// Add bot uptime (different from monitoring service uptime)
	var botUptime time.Duration
	if !bot.StartTime.IsZero() {
		botUptime = time.Since(bot.StartTime)
	}
	embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
		Name:   "🤖 Bot Uptime",
		Value:  formatDuration(botUptime),
		Inline: true,
	})

	bot.respondWithEmbed(s, i, embed)
}

// handleBotRestart restarts the cricket monitoring service
func (bot *EnhancedDiscordBot) handleBotRestart(s *discordgo.Session, i *discordgo.InteractionCreate) {
	monitoringService.mu.Lock()
	defer monitoringService.mu.Unlock()

	wasRunning := monitoringService.isRunning
	oldUptime := time.Duration(0)
	if wasRunning {
		oldUptime = time.Since(monitoringService.startTime)
	}

	// Stop if running
	if monitoringService.isRunning {
		monitoringService.isRunning = false
		select {
		case monitoringService.stopChannel <- true:
		default:
		}
	}

	// Brief pause for graceful shutdown
	time.Sleep(2 * time.Second)

	// Restart
	monitoringService.isRunning = true
	monitoringService.startTime = time.Now()
	monitoringService.stopChannel = make(chan bool, 1)

	// Create success embed
	embed := &discordgo.MessageEmbed{
		Title:       "🔄 Monitoring Restarted",
		Description: "Cricket score monitoring has been restarted successfully",
		Color:       0x0099ff,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "🟢 Status",
				Value:  "Running",
				Inline: true,
			},
			{
				Name:   "⏰ Restarted At",
				Value:  monitoringService.startTime.Format("15:04:05 MST"),
				Inline: true,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Monitoring service has been restarted",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add previous uptime if it was running
	if wasRunning {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "⏱️ Previous Uptime",
			Value:  formatDuration(oldUptime),
			Inline: true,
		})
	}

	bot.respondWithEmbed(s, i, embed)
	log.Printf("Cricket monitoring restarted by admin user %s", i.Member.User.ID)
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}

	return strings.Join(parts, " ")
}

// IsMonitoringRunning returns whether the monitoring service is currently running
func IsMonitoringRunning() bool {
	monitoringService.mu.RLock()
	defer monitoringService.mu.RUnlock()
	return monitoringService.isRunning
}

// GetMonitoringStopChannel returns the stop channel for the monitoring service
func GetMonitoringStopChannel() <-chan bool {
	monitoringService.mu.RLock()
	defer monitoringService.mu.RUnlock()
	return monitoringService.stopChannel
}

// handleScrapeCommand triggers an immediate scrape of live scores
func (bot *EnhancedDiscordBot) handleScrapeCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Quick ACK so Discord doesn't time-out (3-second rule)
	_ = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "⏳ Scraping live scores…",
		},
	})

	go func() {
		// Run the scrape with retries
		var resultMsg string
		if globalConfig == nil {
			resultMsg = "❌ Bot configuration not initialized"
		} else {
			err := RetryWithBackoff(retryConfig, func() error {
				return scrapeAndAlert(*globalConfig)
			})
			if err != nil {
				resultMsg = fmt.Sprintf("❌ Scrape failed: %v", err)
			} else {
				resultMsg = "✅ Scrape completed. Run /matches to view tracked games."
			}
		}

		// Edit the original deferred message with the result
		_, _ = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Content: &resultMsg,
		})
	}()
}

func (bot *EnhancedDiscordBot) handleHelpCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Determine if the user asked for help on a specific command
	var specificCmd string
	if opts := i.ApplicationCommandData().Options; len(opts) > 0 && opts[0].Name == "command" {
		specificCmd = strings.ToLower(strings.TrimSpace(opts[0].StringValue()))
	}

	// Helper to check admin access
	isAdmin := func() bool {
		if i.Member == nil {
			return false
		}
		return bot.isAdmin(i.Member)
	}()

	if specificCmd != "" {
		// --- Per-command help ---
		bot.mu.RLock()
		cmd, ok := bot.Commands[specificCmd]
		bot.mu.RUnlock()
		if !ok {
			bot.respondWithError(s, i, fmt.Sprintf("Unknown command: %s", specificCmd))
			return
		}
		// Hide admin-only commands from non-admins
		if cmd.AdminOnly && !isAdmin {
			bot.respondWithError(s, i, "You do not have permission to view this command")
			return
		}

		embed := &discordgo.MessageEmbed{
			Title:       fmt.Sprintf("/%s", cmd.Name),
			Description: cmd.Description,
			Color:       0x33ffcc,
			Footer: &discordgo.MessageEmbedFooter{
				Text: "Use /help to list all commands",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		if len(cmd.Options) > 0 {
			var optsBuilder strings.Builder
			for _, opt := range cmd.Options {
				req := ""
				if opt.Required {
					req = " (required)"
				}
				optsBuilder.WriteString(fmt.Sprintf("`%s`%s – %s\n", opt.Name, req, opt.Description))
			}
			embed.Fields = []*discordgo.MessageEmbedField{{
				Name:   "Options",
				Value:  optsBuilder.String(),
				Inline: false,
			}}
		}

		bot.respondWithEmbed(s, i, embed)
		return
	}

	// --- General help list ---
	var listBuilder strings.Builder
	bot.mu.RLock()
	for _, cmd := range bot.Commands {
		if cmd.AdminOnly && !isAdmin {
			// Skip admin commands for non-admins
			continue
		}
		listBuilder.WriteString(fmt.Sprintf("/%s – %s\n", cmd.Name, cmd.Description))
	}
	bot.mu.RUnlock()

	embed := &discordgo.MessageEmbed{
		Title:       "Available Commands",
		Description: listBuilder.String(),
		Color:       0x33ffcc,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Use /help <command> to get details about a command",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	bot.respondWithEmbed(s, i, embed)
}

// handleToggleToss toggles the toss alert setting
func (bot *EnhancedDiscordBot) handleToggleToss(s *discordgo.Session, i *discordgo.InteractionCreate) {
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to load configuration")
		return
	}

	// Toggle the setting
	config.AlertOnToss = !config.AlertOnToss

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to save configuration")
		return
	}

	// Update the message with new configuration
	bot.updateAlertsConfigMessage(s, i, config, fmt.Sprintf("Toss alerts %s", bot.getEnabledDisabledText(config.AlertOnToss)))
}

// handleToggleStart toggles the match start alert setting
func (bot *EnhancedDiscordBot) handleToggleStart(s *discordgo.Session, i *discordgo.InteractionCreate) {
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to load configuration")
		return
	}

	// Toggle the setting
	config.AlertOnStart = !config.AlertOnStart

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to save configuration")
		return
	}

	// Update the message with new configuration
	bot.updateAlertsConfigMessage(s, i, config, fmt.Sprintf("Match start alerts %s", bot.getEnabledDisabledText(config.AlertOnStart)))
}

// handleToggleWicket toggles the wicket alert setting
func (bot *EnhancedDiscordBot) handleToggleWicket(s *discordgo.Session, i *discordgo.InteractionCreate) {
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to load configuration")
		return
	}

	// Toggle the setting
	config.AlertOnWicket = !config.AlertOnWicket

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to save configuration")
		return
	}

	// Update the message with new configuration
	bot.updateAlertsConfigMessage(s, i, config, fmt.Sprintf("Wicket alerts %s", bot.getEnabledDisabledText(config.AlertOnWicket)))
}

// handleScoreFreqDecrease decreases the score alert frequency
func (bot *EnhancedDiscordBot) handleScoreFreqDecrease(s *discordgo.Session, i *discordgo.InteractionCreate) {
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to load configuration")
		return
	}

	// Decrease frequency (minimum 1)
	if config.AlertOnScoreEvery > 1 {
		config.AlertOnScoreEvery--
	} else {
		bot.respondToButtonWithError(s, i, "Score alert frequency is already at minimum (1 run)")
		return
	}

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to save configuration")
		return
	}

	// Update the message with new configuration
	bot.updateAlertsConfigMessage(s, i, config, fmt.Sprintf("Score alert frequency set to every %d runs", config.AlertOnScoreEvery))
}

// handleScoreFreqIncrease increases the score alert frequency
func (bot *EnhancedDiscordBot) handleScoreFreqIncrease(s *discordgo.Session, i *discordgo.InteractionCreate) {
	config, err := bot.loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to load configuration")
		return
	}

	// Increase frequency (maximum 50)
	if config.AlertOnScoreEvery < 50 {
		config.AlertOnScoreEvery++
	} else {
		bot.respondToButtonWithError(s, i, "Score alert frequency is already at maximum (50 runs)")
		return
	}

	// Save configuration
	err = bot.saveConfig(config)
	if err != nil {
		log.Printf("Error saving config: %v", err)
		bot.respondToButtonWithError(s, i, "Failed to save configuration")
		return
	}

	// Update the message with new configuration
	bot.updateAlertsConfigMessage(s, i, config, fmt.Sprintf("Score alert frequency set to every %d runs", config.AlertOnScoreEvery))
}

// updateAlertsConfigMessage updates the alert configuration message with new settings
func (bot *EnhancedDiscordBot) updateAlertsConfigMessage(s *discordgo.Session, i *discordgo.InteractionCreate, config *ConfigData, successMessage string) {
	// Create updated embed with current settings
	embed := &discordgo.MessageEmbed{
		Title:       "⚙️ Alert Configuration",
		Description: "Current alert preferences for this server. Use the buttons below to toggle settings.",
		Color:       0x9932cc,
		Footer: &discordgo.MessageEmbedFooter{
			Text: fmt.Sprintf("Admin only • Changes are saved automatically • %s", successMessage),
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Add current settings as fields
	embed.Fields = []*discordgo.MessageEmbedField{
		{
			Name:   "🪙 Toss Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnToss),
			Inline: true,
		},
		{
			Name:   "🏏 Match Start Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnStart),
			Inline: true,
		},
		{
			Name:   "🎯 Wicket Alerts",
			Value:  bot.getBooleanStatusText(config.AlertOnWicket),
			Inline: true,
		},
		{
			Name:   "📊 Score Alert Frequency",
			Value:  fmt.Sprintf("Every %d runs", config.AlertOnScoreEvery),
			Inline: true,
		},
	}

	// Create updated action buttons
	components := []discordgo.MessageComponent{
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.Button{
					CustomID: "toggle_toss",
					Label:    bot.getToggleButtonLabel("Toss", config.AlertOnToss),
					Style:    bot.getToggleButtonStyle(config.AlertOnToss),
					Emoji:    &discordgo.ComponentEmoji{Name: "🪙"},
				},
				discordgo.Button{
					CustomID: "toggle_start",
					Label:    bot.getToggleButtonLabel("Start", config.AlertOnStart),
					Style:    bot.getToggleButtonStyle(config.AlertOnStart),
					Emoji:    &discordgo.ComponentEmoji{Name: "🏏"},
				},
				discordgo.Button{
					CustomID: "toggle_wicket",
					Label:    bot.getToggleButtonLabel("Wickets", config.AlertOnWicket),
					Style:    bot.getToggleButtonStyle(config.AlertOnWicket),
					Emoji:    &discordgo.ComponentEmoji{Name: "🎯"},
				},
			},
		},
		discordgo.ActionsRow{
			Components: []discordgo.MessageComponent{
				discordgo.Button{
					CustomID: "score_freq_decrease",
					Label:    "- Frequency",
					Style:    discordgo.SecondaryButton,
					Emoji:    &discordgo.ComponentEmoji{Name: "➖"},
					Disabled: config.AlertOnScoreEvery <= 1,
				},
				discordgo.Button{
					CustomID: "score_freq_current",
					Label:    fmt.Sprintf("Every %d runs", config.AlertOnScoreEvery),
					Style:    discordgo.SecondaryButton,
					Disabled: true,
				},
				discordgo.Button{
					CustomID: "score_freq_increase",
					Label:    "+ Frequency",
					Style:    discordgo.SecondaryButton,
					Emoji:    &discordgo.ComponentEmoji{Name: "➕"},
					Disabled: config.AlertOnScoreEvery >= 50,
				},
			},
		},
	}

	// Update the message
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseUpdateMessage,
		Data: &discordgo.InteractionResponseData{
			Embeds:     []*discordgo.MessageEmbed{embed},
			Components: components,
		},
	})
	if err != nil {
		log.Printf("Error updating alerts config message: %v", err)
	}

	log.Printf("Alert configuration updated: %s", successMessage)
}

// respondToButtonWithError sends an error response to a button interaction
func (bot *EnhancedDiscordBot) respondToButtonWithError(s *discordgo.Session, i *discordgo.InteractionCreate, message string) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("❌ %s", message),
			Flags:   discordgo.MessageFlagsEphemeral,
		},
	})
	if err != nil {
		log.Printf("Error responding to button interaction: %v", err)
	}
}

// getEnabledDisabledText returns "enabled" or "disabled" text for settings
func (bot *EnhancedDiscordBot) getEnabledDisabledText(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

// Helper functions for enhanced error handling
func getCommandName(i *discordgo.InteractionCreate) string {
	if i.Type == discordgo.InteractionApplicationCommand {
		return i.ApplicationCommandData().Name
	}
	return "unknown"
}
