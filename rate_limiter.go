package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// RateLimiter manages rate limiting for Discord API calls
type RateLimiter struct {
	requests    []time.Time
	maxRequests int
	window      time.Duration
	mu          sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:    make([]time.Time, 0),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Wait blocks until it's safe to make another request
func (rl *RateLimiter) Wait() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Remove old requests outside the window
	cutoff := now.Add(-rl.window)
	validRequests := make([]time.Time, 0)
	for _, reqTime := range rl.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	rl.requests = validRequests

	// If we're at the limit, wait until we can make another request
	if len(rl.requests) >= rl.maxRequests {
		oldestRequest := rl.requests[0]
		waitTime := rl.window - now.Sub(oldestRequest)
		if waitTime > 0 {
			log.Printf("Rate limit reached, waiting %v", waitTime)
			time.Sleep(waitTime)
		}
	}

	// Add current request
	rl.requests = append(rl.requests, now)
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for external API calls
type CircuitBreaker struct {
	name          string
	maxFailures   int
	resetTimeout  time.Duration
	state         CircuitBreakerState
	failures      int
	lastFailTime  time.Time
	nextRetryTime time.Time
	mu            sync.RWMutex
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Execute runs a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	// Check if we should transition from Open to Half-Open
	if cb.state == CircuitOpen && now.After(cb.nextRetryTime) {
		cb.state = CircuitHalfOpen
		log.Printf("Circuit breaker %s transitioning to Half-Open", cb.name)
	}

	// If circuit is open, fail fast
	if cb.state == CircuitOpen {
		return fmt.Errorf("circuit breaker %s is open, failing fast", cb.name)
	}

	// Execute the function
	err := fn()

	if err != nil {
		cb.recordFailure()
		return fmt.Errorf("circuit breaker %s: %w", cb.name, err)
	}

	cb.recordSuccess()
	return nil
}

func (cb *CircuitBreaker) recordFailure() {
	cb.failures++
	cb.lastFailTime = time.Now()

	if cb.failures >= cb.maxFailures {
		cb.state = CircuitOpen
		cb.nextRetryTime = time.Now().Add(cb.resetTimeout)
		log.Printf("Circuit breaker %s opened due to %d failures", cb.name, cb.failures)
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
		log.Printf("Circuit breaker %s closed after successful call", cb.name)
	}
	cb.failures = 0
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxAttempts   int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}
}

// RetryWithBackoff executes a function with exponential backoff retry logic
func RetryWithBackoff(config RetryConfig, operation func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			if attempt > 1 {
				log.Printf("Operation succeeded on attempt %d", attempt)
			}
			return nil
		}

		lastErr = err

		if attempt == config.MaxAttempts {
			log.Printf("Operation failed after %d attempts: %v", config.MaxAttempts, err)
			break
		}

		log.Printf("Operation failed on attempt %d: %v, retrying in %v", attempt, err, delay)
		time.Sleep(delay)

		// Calculate next delay with exponential backoff
		delay = time.Duration(float64(delay) * config.BackoffFactor)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// EnhancedLogger provides structured logging with different levels
type EnhancedLogger struct {
	prefix string
}

// NewEnhancedLogger creates a new enhanced logger
func NewEnhancedLogger(prefix string) *EnhancedLogger {
	return &EnhancedLogger{prefix: prefix}
}

// LogError logs an error with context
func (el *EnhancedLogger) LogError(operation string, err error, context map[string]interface{}) {
	contextStr := ""
	if context != nil {
		for key, value := range context {
			contextStr += fmt.Sprintf("%s=%v ", key, value)
		}
	}
	log.Printf("ERROR [%s] %s failed: %v | Context: %s", el.prefix, operation, err, contextStr)
}

// LogWarning logs a warning with context
func (el *EnhancedLogger) LogWarning(operation string, message string, context map[string]interface{}) {
	contextStr := ""
	if context != nil {
		for key, value := range context {
			contextStr += fmt.Sprintf("%s=%v ", key, value)
		}
	}
	log.Printf("WARN [%s] %s: %s | Context: %s", el.prefix, operation, message, contextStr)
}

// LogInfo logs informational messages
func (el *EnhancedLogger) LogInfo(operation string, message string, context map[string]interface{}) {
	contextStr := ""
	if context != nil {
		for key, value := range context {
			contextStr += fmt.Sprintf("%s=%v ", key, value)
		}
	}
	log.Printf("INFO [%s] %s: %s | Context: %s", el.prefix, operation, message, contextStr)
}

// UserFriendlyError creates user-friendly error messages
type UserFriendlyError struct {
	TechnicalError error
	UserMessage    string
	Suggestions    []string
}

// Error implements the error interface
func (ufe *UserFriendlyError) Error() string {
	return ufe.TechnicalError.Error()
}

// GetUserMessage returns a user-friendly error message
func (ufe *UserFriendlyError) GetUserMessage() string {
	message := ufe.UserMessage
	if len(ufe.Suggestions) > 0 {
		message += "\n\n**Suggestions:**"
		for i, suggestion := range ufe.Suggestions {
			message += fmt.Sprintf("\n%d. %s", i+1, suggestion)
		}
	}
	return message
}

// NewUserFriendlyError creates a new user-friendly error
func NewUserFriendlyError(technicalError error, userMessage string, suggestions ...string) *UserFriendlyError {
	return &UserFriendlyError{
		TechnicalError: technicalError,
		UserMessage:    userMessage,
		Suggestions:    suggestions,
	}
}

// Common user-friendly error creators
func NewAPIConnectionError(err error) *UserFriendlyError {
	return NewUserFriendlyError(
		err,
		"Unable to connect to the cricket data service. Please try again in a few moments.",
		"Try again in a few minutes",
		"Check if there are any ongoing issues with the cricket data provider",
		"Contact an administrator if the problem persists",
	)
}

func NewInvalidInputError(err error, fieldName string) *UserFriendlyError {
	return NewUserFriendlyError(
		err,
		fmt.Sprintf("Invalid input provided for %s.", fieldName),
		"Check that your input meets the required format",
		"Use the `/help` command to see usage examples",
		"Contact an administrator if you need assistance",
	)
}

func NewPermissionError() *UserFriendlyError {
	return NewUserFriendlyError(
		fmt.Errorf("insufficient permissions"),
		"You don't have permission to use this command.",
		"This command requires administrator privileges",
		"Contact a server administrator to request access",
	)
}

func NewRateLimitError() *UserFriendlyError {
	return NewUserFriendlyError(
		fmt.Errorf("rate limit exceeded"),
		"Rate limit exceeded. Too many requests. Please wait a moment before trying again.",
		"Wait a few seconds before using the command again",
		"Rate limiting helps ensure fair usage for all users",
	)
}
