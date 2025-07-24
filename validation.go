package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateTeamCode validates a cricket team short code (e.g., IND, AUS).
// It trims whitespace, converts to upper-case and ensures it matches 2-4 alpha chars.
// Returns the normalised code or an error.
func ValidateTeamCode(input string) (string, error) {
	code := strings.ToUpper(strings.TrimSpace(input))
	if code == "" {
		return "", fmt.Errorf("team code cannot be empty")
	}
	// allow A-Z, 2-4 chars
	validRe := regexp.MustCompile(`^[A-Z]{2,4}$`)
	if !validRe.MatchString(code) {
		return "", fmt.Errorf("invalid team code '%s' – use 2-4 letters", input)
	}
	return code, nil
}
