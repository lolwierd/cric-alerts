package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bwmarrin/discordgo"
)

// SecurityValidator handles input validation and security checks
type SecurityValidator struct {
	logger *EnhancedLogger
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		logger: NewEnhancedLogger("SECURITY"),
	}
}

// Input validation constants
const (
	MaxTeamCodeLength      = 4
	MinTeamCodeLength      = 2
	MaxMatchIDLength       = 20
	MaxUserInputLength     = 500
	MaxCommandOptionLength = 100
)

// Validation patterns
var (
	teamCodePattern     = regexp.MustCompile(`^[A-Z]{2,4}$`)
	matchIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,20}$`)
	alphanumericPattern = regexp.MustCompile(`^[a-zA-Z0-9\s\-_\.]{1,100}$`)
	discordIDPattern    = regexp.MustCompile(`^[0-9]{17,19}$`)
)

// Dangerous patterns that could indicate injection attempts
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(javascript|script|eval|function|document|window)\b`),
	regexp.MustCompile(`(?i)\balert\s*\(`), // Match alert() function calls specifically
	regexp.MustCompile(`(?i)(select|union|insert|update|delete|drop|create|alter)`),
	regexp.MustCompile(`(?i)(<script|<iframe|<object|<embed|<link|<meta)`),
	regexp.MustCompile(`(?i)(onload|onclick|onerror|onmouseover|onfocus)`),
	regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`), // Control characters
}

// ValidateTeamCode validates and normalizes team codes
func (sv *SecurityValidator) ValidateTeamCode(input string) (string, error) {
	if input == "" {
		return "", NewInvalidInputError(fmt.Errorf("empty team code"), "team code")
	}

	// Sanitize input
	sanitized := sv.SanitizeInput(input)
	normalized := strings.ToUpper(strings.TrimSpace(sanitized))

	// Length check
	if len(normalized) < MinTeamCodeLength || len(normalized) > MaxTeamCodeLength {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid team code length: %d", len(normalized)),
			"team code",
		)
	}

	// Pattern check
	if !teamCodePattern.MatchString(normalized) {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid team code format: %s", normalized),
			"team code",
		)
	}

	sv.logger.LogInfo("ValidateTeamCode", "Team code validated successfully", map[string]interface{}{
		"input":      input,
		"normalized": normalized,
	})

	return normalized, nil
}

// ValidateMatchID validates match IDs
func (sv *SecurityValidator) ValidateMatchID(input string) (string, error) {
	if input == "" {
		return "", NewInvalidInputError(fmt.Errorf("empty match ID"), "match ID")
	}

	// Sanitize input
	sanitized := sv.SanitizeInput(input)
	trimmed := strings.TrimSpace(sanitized)

	// Length check
	if len(trimmed) > MaxMatchIDLength {
		return "", NewInvalidInputError(
			fmt.Errorf("match ID too long: %d characters", len(trimmed)),
			"match ID",
		)
	}

	// Pattern check
	if !matchIDPattern.MatchString(trimmed) {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid match ID format: %s", trimmed),
			"match ID",
		)
	}

	sv.logger.LogInfo("ValidateMatchID", "Match ID validated successfully", map[string]interface{}{
		"input":     input,
		"validated": trimmed,
	})

	return trimmed, nil
}

// ValidateSubscriptionType validates subscription types
func (sv *SecurityValidator) ValidateSubscriptionType(input string) (SubscriptionType, error) {
	if input == "" {
		return "", NewInvalidInputError(fmt.Errorf("empty subscription type"), "subscription type")
	}

	sanitized := sv.SanitizeInput(input)
	normalized := strings.ToLower(strings.TrimSpace(sanitized))

	subscriptionType, valid := ValidateSubscriptionType(normalized)
	if !valid {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid subscription type: %s", normalized),
			"subscription type",
		)
	}

	sv.logger.LogInfo("ValidateSubscriptionType", "Subscription type validated successfully", map[string]interface{}{
		"input":      input,
		"normalized": normalized,
		"type":       subscriptionType,
	})

	return subscriptionType, nil
}

// ValidateDiscordID validates Discord user/role/guild IDs
func (sv *SecurityValidator) ValidateDiscordID(input string, idType string) (string, error) {
	if input == "" {
		return "", NewInvalidInputError(fmt.Errorf("empty %s ID", idType), fmt.Sprintf("%s ID", idType))
	}

	sanitized := sv.SanitizeInput(input)
	trimmed := strings.TrimSpace(sanitized)

	if !discordIDPattern.MatchString(trimmed) {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid %s ID format: %s", idType, trimmed),
			fmt.Sprintf("%s ID", idType),
		)
	}

	return trimmed, nil
}

// ValidateCommandOption validates general command options
func (sv *SecurityValidator) ValidateCommandOption(input string, optionName string) (string, error) {
	if input == "" {
		return "", NewInvalidInputError(fmt.Errorf("empty %s", optionName), optionName)
	}

	// Length check
	if len(input) > MaxCommandOptionLength {
		return "", NewInvalidInputError(
			fmt.Errorf("%s too long: %d characters", optionName, len(input)),
			optionName,
		)
	}

	// Sanitize input
	sanitized := sv.SanitizeInput(input)
	trimmed := strings.TrimSpace(sanitized)

	// Basic alphanumeric check
	if !alphanumericPattern.MatchString(trimmed) {
		return "", NewInvalidInputError(
			fmt.Errorf("invalid %s format: contains invalid characters", optionName),
			optionName,
		)
	}

	return trimmed, nil
}

// SanitizeInput removes potentially dangerous characters and patterns
func (sv *SecurityValidator) SanitizeInput(input string) string {
	if input == "" {
		return input
	}

	// Normalize UTF-8
	if !utf8.ValidString(input) {
		sv.logger.LogWarning("SanitizeInput", "Invalid UTF-8 string detected", map[string]interface{}{
			"length": len(input),
		})
		input = strings.ToValidUTF8(input, "")
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(input) {
			sv.logger.LogWarning("SanitizeInput", "Dangerous pattern detected in input", map[string]interface{}{
				"pattern": pattern.String(),
				"input":   input[:min(len(input), 50)], // Log only first 50 chars for safety
			})
			// Remove the dangerous content
			input = pattern.ReplaceAllString(input, "")
		}
	}

	// Remove excessive whitespace
	input = regexp.MustCompile(`\s+`).ReplaceAllString(input, " ")

	// Limit overall length
	if len(input) > MaxUserInputLength {
		sv.logger.LogWarning("SanitizeInput", "Input truncated due to length", map[string]interface{}{
			"original_length": len(input),
			"max_length":      MaxUserInputLength,
		})
		input = input[:MaxUserInputLength]
	}

	return input
}

// PermissionChecker handles permission verification
type PermissionChecker struct {
	logger *EnhancedLogger
}

// NewPermissionChecker creates a new permission checker
func NewPermissionChecker() *PermissionChecker {
	return &PermissionChecker{
		logger: NewEnhancedLogger("PERMISSIONS"),
	}
}

// IsAdmin checks if a user has admin permissions
func (pc *PermissionChecker) IsAdmin(interaction *discordgo.InteractionCreate, adminRoleID string) bool {
	if interaction.Member == nil {
		pc.logger.LogWarning("IsAdmin", "No member data in interaction", map[string]interface{}{
			"user_id": getInteractionUserID(interaction),
		})
		return false
	}

	// Check if user has the admin role
	for _, roleID := range interaction.Member.Roles {
		if roleID == adminRoleID {
			pc.logger.LogInfo("IsAdmin", "Admin access granted", map[string]interface{}{
				"user_id": interaction.Member.User.ID,
				"role_id": roleID,
			})
			return true
		}
	}

	// Check if user has administrator permissions
	permissions := interaction.Member.Permissions
	if permissions&discordgo.PermissionAdministrator != 0 {
		pc.logger.LogInfo("IsAdmin", "Admin access granted via permissions", map[string]interface{}{
			"user_id":     interaction.Member.User.ID,
			"permissions": permissions,
		})
		return true
	}

	pc.logger.LogWarning("IsAdmin", "Admin access denied", map[string]interface{}{
		"user_id": interaction.Member.User.ID,
		"roles":   interaction.Member.Roles,
	})

	return false
}

// ValidateCommandPermissions checks if a user can execute a command
func (pc *PermissionChecker) ValidateCommandPermissions(interaction *discordgo.InteractionCreate, command *Command, adminRoleID string) error {
	if !command.AdminOnly {
		return nil // Command is available to all users
	}

	if !pc.IsAdmin(interaction, adminRoleID) {
		return NewPermissionError()
	}

	return nil
}

// SecureTokenHandler handles secure token operations
type SecureTokenHandler struct {
	logger *EnhancedLogger
}

// NewSecureTokenHandler creates a new secure token handler
func NewSecureTokenHandler() *SecureTokenHandler {
	return &SecureTokenHandler{
		logger: NewEnhancedLogger("TOKEN"),
	}
}

// ValidateToken validates a Discord bot token format
func (sth *SecureTokenHandler) ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("bot token is required")
	}

	if len(token) < 50 {
		return fmt.Errorf("bot token appears to be too short")
	}

	// Basic format check for Discord bot tokens
	// Discord bot tokens typically start with a bot ID followed by a dot and then the token
	tokenPattern := regexp.MustCompile(`^[A-Za-z0-9\._-]{50,}$`)
	if !tokenPattern.MatchString(token) {
		return fmt.Errorf("bot token has invalid format")
	}

	sth.logger.LogInfo("ValidateToken", "Bot token validated successfully", map[string]interface{}{
		"token_length": len(token),
		"token_prefix": token[:min(len(token), 10)] + "...", // Log only first 10 chars
	})

	return nil
}

// RedactSensitiveInfo redacts sensitive information from logs
func (sth *SecureTokenHandler) RedactSensitiveInfo(input string) string {
	// Redact potential tokens
	tokenPattern := regexp.MustCompile(`([A-Za-z0-9\._-]{50,})`)
	redacted := tokenPattern.ReplaceAllString(input, "[REDACTED_TOKEN]")

	// Redact Discord IDs in sensitive contexts
	idPattern := regexp.MustCompile(`([0-9]{17,19})`)
	redacted = idPattern.ReplaceAllString(redacted, "[REDACTED_ID]")

	return redacted
}

// Helper functions
func getInteractionUserID(interaction *discordgo.InteractionCreate) string {
	if interaction.User != nil {
		return interaction.User.ID
	}
	if interaction.Member != nil && interaction.Member.User != nil {
		return interaction.Member.User.ID
	}
	return "unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	MaxRequestsPerMinute int
	CircuitBreakerConfig struct {
		MaxFailures  int
		ResetTimeout int // in seconds
	}
	InputValidation struct {
		MaxInputLength    int
		AllowSpecialChars bool
		StrictModeEnabled bool
	}
	Logging struct {
		LogSensitiveData bool
		LogLevel         string
	}
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxRequestsPerMinute: 30,
		CircuitBreakerConfig: struct {
			MaxFailures  int
			ResetTimeout int
		}{
			MaxFailures:  5,
			ResetTimeout: 60,
		},
		InputValidation: struct {
			MaxInputLength    int
			AllowSpecialChars bool
			StrictModeEnabled bool
		}{
			MaxInputLength:    500,
			AllowSpecialChars: false,
			StrictModeEnabled: true,
		},
		Logging: struct {
			LogSensitiveData bool
			LogLevel         string
		}{
			LogSensitiveData: false,
			LogLevel:         "INFO",
		},
	}
}
