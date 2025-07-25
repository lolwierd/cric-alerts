package main

import (
	"bytes"
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

// Config holds the configuration for the alerting service.
type Config struct {
	DiscordWebhookURLs []string
	TargetTeam         string
	PollInterval       time.Duration
	AlertOnToss        bool
	AlertOnStart       bool
	AlertOnWicket      bool
	AlertOnScoreEvery  int // in overs
	PlayerMilestones   []int

	// Discord Bot configuration
	DiscordBot     BotConfig
	MonitoredTeams []string
	EnableBot      bool
}

// BotConfig holds Discord bot specific configuration
type BotConfig struct {
	Token       string
	GuildID     string
	ChannelID   string
	AdminRoleID string
}

// CommandHandler represents a function that handles Discord slash commands
type CommandHandler func(s *discordgo.Session, i *discordgo.InteractionCreate)

// MatchState holds the current state of a match.
type MatchState struct {
	MatchID           string
	Team1             string
	Team2             string
	Score             string
	Overs             string
	RunRate           string
	Status            string
	LastWicket        string
	Partnership       string
	RecentOvers       string
	CurrentPlayers    []Player
	CurrentBowler     Player
	LastAlertedOver   int
	NotifiedMilestone map[string]int
	Toss              string
	Series            string // Series/tournament name
	Format            string // New field for match format (Test/ODI/T20)
	Venue             string // Venue of the match
	YetToBat          string
	TargetRuns        int
	TargetBalls       int
	LastFoW           string
	OriginalURL       string // Full URL path from Cricbuzz for scoreboard access
}

// Player represents a player's score.
type Player struct {
	Name       string
	Runs       int
	Balls      int
	Fours      int
	Sixes      int
	IsOnStrike bool
	// For bowlers
	Overs   string
	Maidens int
	Wickets int
}

// DiscordEmbedFooter represents the footer of a Discord embed.
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// DiscordEmbedField represents a field in a Discord embed.
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// DiscordEmbed represents a Discord embed message.
type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []DiscordEmbedField `json:"fields"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp"`
}

// DiscordMessage represents a message to be sent to Discord.
type DiscordMessage struct {
	Username  string         `json:"username"`
	AvatarURL string         `json:"avatar_url"`
	Embeds    []DiscordEmbed `json:"embeds"`
}

var (
	matchStates    = make(map[string]*MatchState)
	mu             sync.RWMutex
	globalBot      *EnhancedDiscordBot // Global reference to bot for configuration access
	globalConfig   *Config             // Global reference to app configuration
	logger         *EnhancedLogger
	circuitBreaker *CircuitBreaker
	retryConfig    RetryConfig
)

func main() {
	urlsEnv := os.Getenv("DISCORD_WEBHOOK_URLS")
	var urls []string
	for _, u := range strings.Split(urlsEnv, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}

	// Load Discord bot configuration from environment variables
	botConfig := BotConfig{
		Token:       os.Getenv("DISCORD_BOT_TOKEN"),
		GuildID:     os.Getenv("DISCORD_GUILD_ID"),
		ChannelID:   os.Getenv("DISCORD_CHANNEL_ID"),
		AdminRoleID: os.Getenv("DISCORD_ADMIN_ROLE_ID"),
	}

	// Parse monitored teams from environment variable
	var monitoredTeams []string
	teamsEnv := os.Getenv("MONITORED_TEAMS")
	if teamsEnv != "" {
		for _, team := range strings.Split(teamsEnv, ",") {
			team = strings.TrimSpace(team)
			if team != "" {
				monitoredTeams = append(monitoredTeams, team)
			}
		}
	}
	// Default to IND if no teams specified
	if len(monitoredTeams) == 0 {
		monitoredTeams = []string{"IND"}
	}

	// Check if bot should be enabled
	enableBot := os.Getenv("ENABLE_DISCORD_BOT") == "true"

	config := Config{
		DiscordWebhookURLs: urls, // Get your webhook URL from Discord
		TargetTeam:         "IND",
		PollInterval:       30 * time.Second,
		AlertOnToss:        true,
		AlertOnStart:       true,
		AlertOnWicket:      true,
		AlertOnScoreEvery:  5, // Alert every 5 overs
		PlayerMilestones:   []int{50, 100, 150, 200, 250, 300},
		DiscordBot:         botConfig,
		MonitoredTeams:     monitoredTeams,
		EnableBot:          enableBot,
	}

	// Save global configuration reference for use in bot handlers
	globalConfig = &config

	if len(config.DiscordWebhookURLs) == 0 && !config.EnableBot {
		log.Fatal("Either DISCORD_WEBHOOK_URLS or ENABLE_DISCORD_BOT=true must be set.")
	}

	// Initialize enhanced logging and reliability components
	logger = NewEnhancedLogger("CRICKET_ALERTS")
	circuitBreaker = NewCircuitBreaker("cricbuzz_api", 5, 60*time.Second)
	retryConfig = DefaultRetryConfig()

	logger.LogInfo("main", "Starting cricket alerter", map[string]interface{}{
		"target_team":     config.TargetTeam,
		"monitored_teams": config.MonitoredTeams,
		"bot_enabled":     config.EnableBot,
	})

	// Initialize Discord bot if enabled
	var bot *EnhancedDiscordBot
	if config.EnableBot {
		var err error
		bot, err = NewDiscordBot(&config.DiscordBot)
		if err != nil {
			logger.LogError("main", err, map[string]interface{}{
				"component": "discord_bot_init",
			})
		} else {
			err = bot.Connect()
			if err != nil {
				logger.LogError("main", err, map[string]interface{}{
					"component": "discord_bot_connect",
				})
				bot = nil
			} else {
				// Set global bot reference for configuration access
				globalBot = bot
				logger.LogInfo("main", "Discord bot connected successfully", map[string]interface{}{
					"bot_user": bot.Session.State.User.Username,
				})
				// Ensure bot disconnects gracefully on shutdown
				defer func() {
					if bot != nil {
						logger.LogInfo("main", "Disconnecting Discord bot", nil)
						if err := bot.Disconnect(); err != nil {
							log.Printf("error disconnecting bot: %v", err)
						}
					}
				}()
			}
		}
	}

	go func() {
		log.Printf("🚀 MONITORING: Starting monitoring goroutine")
		for {
			// Check if monitoring should continue
			isRunning := IsMonitoringRunning()
			log.Printf("🔍 MONITORING: IsMonitoringRunning() = %v", isRunning)
			if isRunning {
				log.Printf("✅ MONITORING: About to run scrapeAndAlert...")
				err := RetryWithBackoff(retryConfig, func() error {
					return scrapeAndAlert(config)
				})
				if err != nil {
					log.Printf("❌ MONITORING: scrapeAndAlert failed: %v", err)
					logger.LogError("main", err, map[string]interface{}{
						"component": "monitoring_loop",
					})
				} else {
					log.Printf("✅ MONITORING: scrapeAndAlert completed successfully")
				}

				// Periodic logging of matchStates for debugging
				mu.RLock()
				currentCount := len(matchStates)
				var matchIDs []string
				for id, state := range matchStates {
					matchIDs = append(matchIDs, fmt.Sprintf("%s(%s vs %s)", id, state.Team1, state.Team2))
				}
				mu.RUnlock()
				log.Printf("PERIODIC CHECK: matchStates contains %d matches: %v", currentCount, matchIDs)
			} else {
				log.Printf("⏸️  MONITORING: Monitoring is paused/stopped")
			}

			// Use select to allow for interruption during sleep
			select {
			case <-GetMonitoringStopChannel():
				logger.LogInfo("main", "Monitoring service received stop signal", nil)
				// Continue the loop but monitoring will be paused
			case <-time.After(config.PollInterval):
				// Normal polling interval
			}
		}
	}()

	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		for _, state := range matchStates {
			sendDiscordAlert(config, "Manual Alert", 0x0000ff, state)
		}
		if _, err := w.Write([]byte("alert sent")); err != nil {
			log.Printf("error writing response: %v", err)
		}
	})

	http.HandleFunc("/score", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(matchStates); err != nil {
			log.Printf("error encoding score response: %v", err)
		}
	})

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func scrapeAndAlert(config Config) error {
	scrapeStartTime := time.Now()
	log.Printf("🚀 SCRAPING: Starting scrape cycle at %s", scrapeStartTime.Format("15:04:05.000"))

	return circuitBreaker.Execute(func() error {
		res, err := http.Get("https://www.cricbuzz.com/cricket-match/live-scores")
		if err != nil {
			logger.LogError("scrapeAndAlert", err, map[string]interface{}{
				"url": "https://www.cricbuzz.com/cricket-match/live-scores",
			})
			return err
		}
		defer func() {
			if err := res.Body.Close(); err != nil {
				log.Printf("error closing response body: %v", err)
			}
		}()

		if res.StatusCode != 200 {
			err := fmt.Errorf("HTTP status code error: %d %s", res.StatusCode, res.Status)
			logger.LogError("scrapeAndAlert", err, map[string]interface{}{
				"status_code": res.StatusCode,
				"status":      res.Status,
			})
			return err
		}

		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			logger.LogError("scrapeAndAlert", err, map[string]interface{}{
				"component": "html_parsing",
			})
			return err
		}

		totalMatches := doc.Find("a.text-hvr-underline").Length()
		log.Printf("🔢 SCRAPING: Found %d total matches at %s", totalMatches, time.Now().Format("15:04:05.000"))
		logger.LogInfo("scrapeAndAlert", "Found live matches", map[string]interface{}{
			"match_count": totalMatches,
		})

		// Get teams to monitor - use bot's dynamic configuration if available
		teamsToMonitor := config.MonitoredTeams
		if globalBot != nil {
			// Try to get updated configuration from bot
			if botConfig, err := globalBot.loadConfig(); err == nil && len(botConfig.MonitoredTeams) > 0 {
				teamsToMonitor = botConfig.MonitoredTeams
			}
		}

		// Fall back to TargetTeam if no teams configured
		if len(teamsToMonitor) == 0 {
			teamsToMonitor = []string{config.TargetTeam}
		}

		targetCount := 0
		log.Printf("🎯 SCRAPING: Starting to process match containers at %s", time.Now().Format("15:04:05.000"))

		// Find all match containers, including live, stumps, lunch, etc.
		doc.Find("div.cb-mtch-lst.cb-col-100.cb-col").Each(func(i int, s *goquery.Selection) {
			// Look for a live-score link within the container
			link := s.Find("a.cb-lv-scrs-well.cb-lv-scrs-well-live, a.cb-lv-scrs-well.cb-stmp, a.cb-lv-scrs-well.cb-lunch, a.cb-lv-scrs-well.cb-rain").First()
			if link.Length() == 0 {
				return // Skip if no valid live/paused link
			}
			isTargetMatch := false

			// Team names can appear under multiple selectors; check both at once
			var foundTeams []string
			s.Find(".cb-hmscg-tm-nm, .cb-col-50.cb-ovr-flo .text-normal").Each(func(_ int, team *goquery.Selection) {
				teamText := strings.TrimSpace(team.Text())
				if teamText != "" {
					foundTeams = append(foundTeams, teamText)
				}
				for _, monitoredTeam := range teamsToMonitor {
					if strings.Contains(teamText, monitoredTeam) {
						log.Printf("Team match found: '%s' contains monitored team '%s'", teamText, monitoredTeam)
						isTargetMatch = true
						return
					}
				}
			})
			if len(foundTeams) > 0 {
				log.Printf("Found teams in match %d: %v, monitored teams: %v, isTargetMatch: %v", i, foundTeams, teamsToMonitor, isTargetMatch)
			}

			if isTargetMatch {
				targetCount++
				href, _ := link.Attr("href")
				log.Printf("⚡ SCRAPING: Processing target match at %s: %s", time.Now().Format("15:04:05.000"), href)
				processMatch(href, config)
			}
		})

		processingEndTime := time.Now()
		processingDuration := processingEndTime.Sub(scrapeStartTime)
		log.Printf("✅ SCRAPING: Completed scrape cycle at %s (took %v)", processingEndTime.Format("15:04:05.000"), processingDuration)
		log.Printf("📊 SCRAPING: Processed %d target matches for teams: %v", targetCount, teamsToMonitor)

		// Log current matchStates count after scraping
		mu.RLock()
		currentMatchCount := len(matchStates)
		mu.RUnlock()
		log.Printf("🏁 SCRAPING: matchStates now contains %d matches after scrape cycle", currentMatchCount)

		return nil
	})
}

func processMatch(href string, config Config) {
	if href == "" {
		log.Printf("Skipping match without href")
		return
	}

	re := regexp.MustCompile(`/cricket-scores/(\d+)(?:/|$)|/live-cricket-scores/(\d+)(?:/|$)`)
	matches := re.FindStringSubmatch(href)
	var matchID string
	switch {
	case len(matches) >= 2 && matches[1] != "":
		matchID = matches[1]
	case len(matches) >= 3 && matches[2] != "":
		matchID = matches[2]
	default:
		log.Printf("Could not extract match ID from href: %s", href)
		return
	}

	log.Printf("🔍 LOOKUP: Checking for existing match %s at %s", matchID, time.Now().Format("15:04:05.000"))
	mu.RLock()
	log.Printf("🧠 LOOKUP: Reading from matchStates map at address: %p", &matchStates)
	prevState := matchStates[matchID]
	lookupExists := prevState != nil
	mu.RUnlock()
	log.Printf("📖 LOOKUP: Match %s exists: %v at %s", matchID, lookupExists, time.Now().Format("15:04:05.000"))

	resp, err := http.Get(fmt.Sprintf("https://www.cricbuzz.com/live-cricket-scores/%s", matchID))
	if err != nil {
		log.Printf("Error fetching match details for %s: %v", matchID, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		log.Printf("Error fetching match details for %s: Status code %d", matchID, resp.StatusCode)
		return
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("Error parsing match details for %s: %v", matchID, err)
		return
	}

	newState := parseScorecard(doc)
	// Preserve previously parsed team names if current scrape failed to detect them
	if newState.Team1 == "" {
		newState.Team1 = prevState.Team1
	}
	if newState.Team2 == "" {
		newState.Team2 = prevState.Team2
	}
	// Re-use historical data that is still relevant
	newState.MatchID = matchID
	if prevState != nil {
		newState.LastAlertedOver = prevState.LastAlertedOver
		newState.NotifiedMilestone = prevState.NotifiedMilestone
	} else {
		newState.LastAlertedOver = -1
		newState.NotifiedMilestone = make(map[string]int)
	}

	// decide alert cadence & milestones by match format
	var scoreAlertEvery int
	var milestones []int
	switch strings.ToUpper(newState.Format) {
	case "T20", "T20I":
		scoreAlertEvery = 2
		milestones = []int{30, 50, 75, 100}
	case "ODI":
		scoreAlertEvery = 5
		milestones = []int{50, 100, 150}
	case "TEST":
		scoreAlertEvery = 10
		milestones = []int{50, 100, 150, 200, 250, 300}
	default:
		scoreAlertEvery = config.AlertOnScoreEvery
		milestones = config.PlayerMilestones
	}

	// Ensure prevState is non-nil for alert logic below
	if prevState == nil {
		prevState = &MatchState{}
	}

	log.Printf("Current state for match %s: %s vs %s, %s, %s %s, CRR: %s", matchID, newState.Team1, newState.Team2, newState.Status, newState.Score, newState.Overs, newState.RunRate)
	log.Printf("Batsmen: %+v, Bowler: %+v", newState.CurrentPlayers, newState.CurrentBowler)
	log.Printf("Partnership: %s, Last Wicket: %s, Recent: %s, Toss: %s", newState.Partnership, newState.LastWicket, newState.RecentOvers, newState.Toss)

	log.Printf("🚦 ALERTING: Starting alert logic for match %s", matchID)

	// Alerting logic
	log.Printf("🚦 ALERTING: Checking toss alert - AlertOnToss: %v, tossAlerted: %v, hasToss: %v",
		config.AlertOnToss, prevState.tossAlerted(), strings.Contains(newState.Toss, "won"))
	if config.AlertOnToss && !prevState.tossAlerted() && strings.Contains(newState.Toss, "won") {
		log.Printf("🚦 ALERTING: Sending toss alert...")
		go sendDiscordAlertWithSubscriptions(config, fmt.Sprintf("Toss: %s", newState.Toss), 0x00ff00, &newState, SubToss)
		log.Printf("🚦 ALERTING: Toss alert sent successfully")
	}

	log.Printf("🚦 ALERTING: Checking start alert - AlertOnStart: %v, gameStarted: %v, hasScore: %v",
		config.AlertOnStart, prevState.gameStarted(), strings.Contains(newState.Score, "/"))
	if config.AlertOnStart && !prevState.gameStarted() && strings.Contains(newState.Score, "/") {
		log.Printf("🚦 ALERTING: Sending start alert...")
		go sendDiscordAlertWithSubscriptions(config, "Match Started", 0x00ff00, &newState, SubStart)
		log.Printf("🚦 ALERTING: Start alert sent successfully")
		prevState.Score = "started"
	}

	log.Printf("🚦 ALERTING: Checking score changes - newScore: '%s', prevScore: '%s'", newState.Score, prevState.Score)
	if newState.Score != "" && prevState.Score != "started" && prevState.Score != newState.Score {
		log.Printf("🚦 ALERTING: Score changed, checking wicket alert...")
		if config.AlertOnWicket && isWicketFall(prevState.Score, newState.Score) &&
			newState.LastWicket != "" && newState.LastWicket != prevState.LastWicket {
			log.Printf("🚦 ALERTING: Sending wicket alert...")
			title := "Wicket"
			if newState.LastWicket != "" {
				title = fmt.Sprintf("Wicket: %s", newState.LastWicket)
			}
			go sendDiscordAlertWithSubscriptions(config, title, 0xff0000, &newState, SubWickets)
			log.Printf("🚦 ALERTING: Wicket alert sent successfully")
		}

		log.Printf("🚦 ALERTING: Checking score alert...")
		currentOver, _ := strconv.Atoi(strings.Split(newState.Overs, ".")[0])
		if scoreAlertEvery > 0 && currentOver > prevState.LastAlertedOver && currentOver%scoreAlertEvery == 0 {
			log.Printf("🚦 ALERTING: Sending score alert...")
			go sendDiscordAlert(config, "Score Update", 0x0000ff, &newState)
			log.Printf("🚦 ALERTING: Score alert sent successfully")
			newState.LastAlertedOver = currentOver
		}
	}

	log.Printf("🚦 ALERTING: Checking player milestones...")
	go checkPlayerMilestones(config, prevState, &newState, milestones)
	log.Printf("🚦 ALERTING: Player milestones check completed")

	log.Printf("🚦 ALERTING: All alerting logic completed for match %s", matchID)

	// Persist the freshly parsed state. We overwrite the existing pointer (if
	// any) with a pointer to the newState to ensure readers always see a fully
	// populated object.
	log.Printf("🔒 STORAGE: Attempting to acquire write lock for match %s at %s", matchID, time.Now().Format("15:04:05.000"))
	mu.Lock()
	log.Printf("✅ STORAGE: Write lock acquired for match %s at %s", matchID, time.Now().Format("15:04:05.000"))

	// Store original URL for scorecard access
	if strings.HasPrefix(href, "http") {
		newState.OriginalURL = href
	} else {
		newState.OriginalURL = "https://www.cricbuzz.com" + href
	}
	log.Printf("🔗 STORAGE: Storing original URL for match %s: %s", matchID, newState.OriginalURL)

	// Log memory address for debugging
	log.Printf("🧠 STORAGE: Writing to matchStates map at address: %p", &matchStates)

	matchStates[matchID] = &newState
	currentMapSize := len(matchStates)
	log.Printf("💾 STORAGE: Match %s successfully stored at %s", matchID, time.Now().Format("15:04:05.000"))

	mu.Unlock()
	log.Printf("🔓 STORAGE: Write lock released for match %s at %s", matchID, time.Now().Format("15:04:05.000"))
	log.Printf("📊 STORED MATCH: %s (%s vs %s) - total tracked: %d", matchID, newState.Team1, newState.Team2, currentMapSize)

	// Debug: List all current match IDs with details
	log.Printf("🔍 DEBUG: Acquiring read lock to verify storage at %s", time.Now().Format("15:04:05.000"))
	mu.RLock()
	var matchDetails []string
	for id, state := range matchStates {
		matchDetails = append(matchDetails, fmt.Sprintf("%s(%s vs %s, %s)", id, state.Team1, state.Team2, state.Status))
	}
	verifyMapSize := len(matchStates)
	mu.RUnlock()
	log.Printf("✅ DEBUG: Read lock released, verified %d matches at %s", verifyMapSize, time.Now().Format("15:04:05.000"))
	log.Printf("📋 ALL STORED MATCHES: %v", matchDetails)

}

// parseScorecard parses the Cricbuzz scorecard page and returns a fully populated MatchState
func parseScorecard(doc *goquery.Document) MatchState {
	var state MatchState

	// Try to capture the two teams. Works for "A vs B, ..." or "A v B, ..."
	fullTitle := doc.Find("title").Text()
	titleParts := strings.Split(fullTitle, " | ")[0]
	teamRegex := regexp.MustCompile(`(?i)([^,]+?)\s+v(?:s)?\.?\s+([^,]+?)(?:,|$)`)
	var teamMatches []string

	// first attempt: from the <title>
	teamMatches = teamRegex.FindStringSubmatch(titleParts)
	// second attempt: from the nav sub‑header text (often more reliable)
	if len(teamMatches) <= 2 {
		navText := strings.TrimSpace(doc.Find(".cb-nav-subhdr").Text())
		teamMatches = teamRegex.FindStringSubmatch(navText)
	}

	if len(teamMatches) > 2 {
		state.Team1 = strings.TrimSpace(teamMatches[1])
		state.Team2 = strings.TrimSpace(teamMatches[2])
	} else {
		// last‑ditch fallback: infer from the first scoreline
		scoreLine := strings.TrimSpace(doc.Find(".cb-min-pad-lft .cb-font-20.text-bold").First().Text())
		if scoreLine == "" {
			scoreLine = strings.TrimSpace(doc.Find(".cb-lv-main .cb-font-20").First().Text())
		}
		parts := strings.Fields(scoreLine)
		if len(parts) > 0 {
			state.Team2 = parts[0] // batting team in the live score
		}
		// leave Team1 blank if we truly can’t find it – better than garbage like "CRR:"
	}
	log.Printf("Parsed Team1: %s, Team2: %s", state.Team1, state.Team2)

	// Series name from nav sub‑header (first <a> inside)
	seriesName := strings.TrimSpace(doc.Find(".cb-nav-subhdr a").First().Text())
	if seriesName != "" {
		state.Series = seriesName
	}

	// Extract Match Format
	formatRegex := regexp.MustCompile(`(?i)(\d+(?:st|nd|rd|th)?\s+(TEST|ODI|T20I|T20))`)
	formatMatches := formatRegex.FindStringSubmatch(fullTitle)
	if len(formatMatches) > 2 {
		state.Format = strings.ToUpper(formatMatches[2])
	} else {
		upperTitle := strings.ToUpper(fullTitle)

		// priority: T20I > T20 > ODI > TEST
		switch {
		case strings.Contains(upperTitle, "T20I") || strings.Contains(upperTitle, "YOUTH T20I"):
			state.Format = "T20I"
		case strings.Contains(upperTitle, "T20") || strings.Contains(upperTitle, "YOUTH T20"):
			state.Format = "T20"
		case strings.Contains(upperTitle, "ODI") || strings.Contains(upperTitle, "YOUTH ODI"):
			state.Format = "ODI"
		case strings.Contains(upperTitle, "TEST"):
			state.Format = "TEST"
		default:
			state.Format = ""
		}
	}
	log.Printf("Parsed Format: %s", state.Format)

	// Status
	state.Status = strings.TrimSpace(doc.Find(".cb-text-inprogress, .cb-text-complete, .cb-text-preview, .cb-text-stumps, .cb-text-lunch, .cb-text-tea").First().Text())
	log.Printf("Status: %s", state.Status)

	// Score and Overs
	scoreAndOversText := doc.Find(".cb-min-bat-rw .cb-font-20.text-bold").Text()
	scoreRegex := regexp.MustCompile(`([A-Z]{3}\s+\d+/\d+)\s+\((\d+\.?\d*)\)`) // e.g., IND 101/2 (30.1)
	scoreMatches := scoreRegex.FindStringSubmatch(scoreAndOversText)
	if len(scoreMatches) > 2 {
		state.Score = strings.TrimSpace(scoreMatches[1])
		state.Overs = strings.TrimSpace(scoreMatches[2])
	} else {
		state.Score = strings.TrimSpace(scoreAndOversText)
		state.Overs = ""
	}
	log.Printf("Score: %s, Overs: %s", state.Score, state.Overs)

	// Run Rate
	runRateText := doc.Find("span:contains('CRR:')").Next().Text()
	state.RunRate = strings.TrimSpace(runRateText)
	log.Printf("RunRate: %s", state.RunRate)

	// Key Stats (Partnership, Last Wicket, Toss)
	doc.Find(".cb-key-st-lst .cb-min-itm-rw").Each(func(i int, s *goquery.Selection) {
		label := strings.TrimSpace(s.Find("span.text-bold").Text())
		value := strings.TrimSpace(s.Find("span").Last().Text())
		log.Printf("Key Stat Label: %s, Value: %s", label, value)
		switch label {
		case "Partnership:":
			state.Partnership = value
		case "Last Wkt:":
			state.LastWicket = value
		case "Toss:":
			state.Toss = value
		}
	})

	// Recent Overs
	recentOversText := doc.Find(".cb-min-rcnt").Text()
	state.RecentOvers = strings.TrimSpace(strings.TrimPrefix(recentOversText, "Recent:"))
	log.Printf("RecentOvers: %s", state.RecentOvers)

	// Yet to Bat
	doc.Find("tr").Each(func(i int, s *goquery.Selection) {
		firstCell := strings.TrimSpace(s.Find("td").First().Text())
		if strings.HasPrefix(firstCell, "Yet to Bat") {
			state.YetToBat = strings.TrimSpace(s.Find("td").Last().Text())
		}
	})

	// Fall of Wickets (grab entire string; show only on wicket alert)
	state.LastFoW = strings.TrimSpace(doc.Find(".cb-scrd-fll-wkt").First().Text())

	// Target + required RR if chasing
	needRegex := regexp.MustCompile(`Need (\d+) run(?:s)? in (\d+) ball`)
	if m := needRegex.FindStringSubmatch(state.Status); len(m) == 3 {
		state.TargetRuns, _ = strconv.Atoi(m[1])
		state.TargetBalls, _ = strconv.Atoi(m[2])
	}

	// Venue
	venueName := doc.Find(".cb-nav-subhdr").Find("a[itemprop='location'] span[itemprop='name']").First().Text()
	locality := doc.Find(".cb-nav-subhdr").Find("a[itemprop='location'] span[itemprop='addressLocality']").First().Text()

	venue := strings.TrimSpace(strings.ReplaceAll(venueName, "\u00a0", " "))
	if locality != "" {
		venue = fmt.Sprintf("%s %s", venue, strings.TrimSpace(locality))
	}
	state.Venue = venue
	log.Printf("Venue: %s", state.Venue)

	var players []Player
	var bowler Player

	// Batsmen and Bowler parsing (assuming these selectors are correct from previous successful runs)
	doc.Find(".cb-min-inf").Each(func(i int, s *goquery.Selection) {
		header := strings.TrimSpace(s.Find(".cb-min-hdr-rw").First().Text())
		if strings.Contains(header, "Batter") {
			s.Find(".cb-min-itm-rw").Each(func(i int, playerRow *goquery.Selection) {
				name := strings.TrimSpace(playerRow.Find("a").Text())
				if name != "" {
					runs, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(1).Text()))
					balls, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(2).Text()))
					fours, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(3).Text()))
					sixes, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(4).Text()))

					players = append(players, Player{
						Name:  name,
						Runs:  runs,
						Balls: balls,
						Fours: fours,
						Sixes: sixes,
					})
				}
			})
		} else if strings.Contains(header, "Bowler") {
			s.Find(".cb-min-itm-rw").First().Each(func(i int, playerRow *goquery.Selection) {
				name := strings.TrimSpace(playerRow.Find("a").Text())
				if name != "" {
					overs := strings.TrimSpace(playerRow.Find("div").Eq(1).Text())
					maidens, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(2).Text()))
					runs, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(3).Text()))
					wickets, _ := strconv.Atoi(strings.TrimSpace(playerRow.Find("div").Eq(4).Text()))

					bowler = Player{
						Name:    name,
						Runs:    runs,
						Overs:   overs,
						Maidens: maidens,
						Wickets: wickets,
					}
				}

			})
		}
	})

	state.CurrentPlayers = players
	state.CurrentBowler = bowler

	return state
}

func parseScoreboardPage(doc *goquery.Document) MatchState {
	var state MatchState

	// Extract teams from title
	fullTitle := doc.Find("title").Text()
	if strings.Contains(fullTitle, " vs ") {
		titleParts := strings.Split(fullTitle, " vs ")
		if len(titleParts) >= 2 {
			// Extract team1 from "Cricket scorecard - England"
			team1Part := titleParts[0]
			if idx := strings.LastIndex(team1Part, " - "); idx != -1 {
				state.Team1 = strings.TrimSpace(team1Part[idx+3:])
			}

			// Extract team2 from "India, 4th Test, ..."
			team2Part := titleParts[1]
			if idx := strings.Index(team2Part, ","); idx != -1 {
				state.Team2 = strings.TrimSpace(team2Part[:idx])
			}
		}
	}

	// Extract series
	seriesLink := doc.Find(".cb-nav-subhdr a").First()
	if seriesLink.Length() > 0 {
		state.Series = strings.TrimSpace(seriesLink.Text())
	}

	// Extract venue
	venueSpan := doc.Find(".cb-nav-subhdr span[itemprop='name']").First()
	localitySpan := doc.Find(".cb-nav-subhdr span[itemprop='addressLocality']").First()
	if venueSpan.Length() > 0 {
		venue := strings.TrimSpace(venueSpan.Text())
		if localitySpan.Length() > 0 {
			locality := strings.TrimSpace(localitySpan.Text())
			if locality != "" && !strings.HasSuffix(venue, locality) {
				if strings.HasSuffix(venue, ",") {
					venue += " " + locality
				} else {
					venue += ", " + locality
				}
			}
		}
		state.Venue = venue
	}

	// Extract format from title
	upperTitle := strings.ToUpper(fullTitle)
	switch {
	case strings.Contains(upperTitle, "T20I"):
		state.Format = "T20I"
	case strings.Contains(upperTitle, "T20"):
		state.Format = "T20"
	case strings.Contains(upperTitle, "ODI"):
		state.Format = "ODI"
	case strings.Contains(upperTitle, "TEST"):
		state.Format = "TEST"
	}

	// Extract status
	status := doc.Find(".cb-scrcrd-status").Text()
	state.Status = strings.TrimSpace(status)

	// Extract current innings score from the pull-right span
	scoreSpan := doc.Find(".cb-scrd-hdr-rw .pull-right").First()
	if scoreSpan.Length() > 0 {
		scoreText := strings.TrimSpace(scoreSpan.Text())
		// Parse format like "264-4 (83 Ov)"
		if strings.Contains(scoreText, "(") && strings.Contains(scoreText, "Ov") {
			parts := strings.Split(scoreText, "(")
			if len(parts) >= 2 {
				// Extract score part "264-4"
				scorePart := strings.TrimSpace(parts[0])
				if strings.Contains(scorePart, "-") {
					// Convert "264-4" to "264/4" format for consistency
					state.Score = strings.Replace(scorePart, "-", "/", 1)
				}

				// Extract overs from "(83 Ov)"
				oversPart := parts[1]
				if strings.Contains(oversPart, "Ov") {
					oversText := strings.Replace(oversPart, "Ov)", "", 1)
					oversText = strings.TrimSpace(oversText)
					state.Overs = oversText

					// Calculate run rate
					if state.Score != "" && strings.Contains(state.Score, "/") {
						scoreParts := strings.Split(state.Score, "/")
						if len(scoreParts) >= 1 {
							if runs, err := strconv.Atoi(scoreParts[0]); err == nil {
								if overs, err := strconv.ParseFloat(oversText, 64); err == nil && overs > 0 {
									runRate := float64(runs) / overs
									state.RunRate = fmt.Sprintf("%.2f", runRate)
								}
							}
						}
					}
				}
			}
		}
	}

	// Extract toss information
	doc.Find(".cb-mtch-info-itm").Each(func(i int, s *goquery.Selection) {
		label := strings.TrimSpace(s.Find(".cb-col-27").Text())
		value := strings.TrimSpace(s.Find(".cb-col-73").Text())
		if label == "Toss" {
			state.Toss = value
		}
	})

	// Extract current batsmen from scorecard
	var players []Player
	doc.Find(".cb-scrd-itms").Each(func(i int, s *goquery.Selection) {
		nameLink := s.Find("a.cb-text-link").First()
		if nameLink.Length() > 0 {
			name := strings.TrimSpace(nameLink.Text())
			// Check if this is a batting entry (has runs, balls, etc.)
			cols := s.Find("div[class*='cb-col']")
			if cols.Length() >= 7 {
				runsText := strings.TrimSpace(cols.Eq(2).Text())
				ballsText := strings.TrimSpace(cols.Eq(3).Text())
				foursText := strings.TrimSpace(cols.Eq(4).Text())
				sixesText := strings.TrimSpace(cols.Eq(5).Text())

				if runs, err := strconv.Atoi(runsText); err == nil {
					player := Player{Name: name, Runs: runs}
					if balls, err := strconv.Atoi(ballsText); err == nil {
						player.Balls = balls
					}
					if fours, err := strconv.Atoi(foursText); err == nil {
						player.Fours = fours
					}
					if sixes, err := strconv.Atoi(sixesText); err == nil {
						player.Sixes = sixes
					}

					// Check if currently batting (no dismissal text)
					dismissalText := strings.TrimSpace(s.Find(".cb-col-33").Text())
					if dismissalText == "batting" {
						players = append(players, player)
					}
				}
			}
		}
	})
	state.CurrentPlayers = players

	// Extract current bowler from bowling figures
	var bowler Player
	doc.Find(".cb-scrd-itms").Each(func(i int, s *goquery.Selection) {
		nameLink := s.Find("a.cb-text-link").First()
		if nameLink.Length() > 0 {
			name := strings.TrimSpace(nameLink.Text())
			cols := s.Find("div[class*='cb-col']")

			// Check if this looks like bowling figures (has overs, maidens, runs, wickets)
			if cols.Length() >= 7 {
				oversText := strings.TrimSpace(cols.Eq(1).Text())
				maidensText := strings.TrimSpace(cols.Eq(2).Text())
				runsText := strings.TrimSpace(cols.Eq(3).Text())
				wicketsText := strings.TrimSpace(cols.Eq(4).Text())

				// If we can parse these as bowling figures
				if maidens, err := strconv.Atoi(maidensText); err == nil {
					if runs, err := strconv.Atoi(runsText); err == nil {
						if wickets, err := strconv.Atoi(wicketsText); err == nil {
							bowler = Player{
								Name:    name,
								Overs:   oversText,
								Maidens: maidens,
								Runs:    runs,
								Wickets: wickets,
							}
							return // Take the first bowler found
						}
					}
				}
			}
		}
	})
	state.CurrentBowler = bowler

	// Extract fall of wickets for last wicket
	fowDiv := doc.Find(".cb-scrd-sub-hdr:contains('Fall of Wickets')").Next()
	if fowDiv.Length() > 0 {
		// Get all spans within the fall of wickets div
		spans := fowDiv.Find("span")
		if spans.Length() > 0 {
			// Get the last span which contains the most recent wicket
			lastSpan := spans.Last()
			lastWicketText := strings.TrimSpace(lastSpan.Text())
			// Remove trailing comma if present
			lastWicketText = strings.TrimSuffix(lastWicketText, ",")
			lastWicketText = strings.TrimSpace(lastWicketText)
			if lastWicketText != "" {
				state.LastWicket = lastWicketText
			}
		}
	}

	// Extract yet to bat
	doc.Find(".cb-scrd-itms").Each(func(i int, s *goquery.Selection) {
		firstCol := strings.TrimSpace(s.Find("div").First().Text())
		if strings.Contains(firstCol, "Yet to Bat") {
			yetToBat := strings.TrimSpace(s.Find("div").Last().Text())
			// Clean up the yet to bat list - remove extra spaces
			yetToBat = strings.ReplaceAll(yetToBat, " , ", ", ")
			yetToBat = strings.ReplaceAll(yetToBat, "  ", " ")
			state.YetToBat = yetToBat
		}
	})

	// Extract partnership information if available from match info
	doc.Find(".cb-key-st-lst .cb-min-itm-rw").Each(func(i int, s *goquery.Selection) {
		label := strings.TrimSpace(s.Find("span.text-bold").Text())
		value := strings.TrimSpace(s.Find("span").Last().Text())
		switch label {
		case "Partnership:":
			state.Partnership = value
		}
	})

	return state
}

func checkPlayerMilestones(config Config, prev, current *MatchState, milestones []int) {
	for _, p := range current.CurrentPlayers {
		lastMilestone := prev.NotifiedMilestone[p.Name]
		for _, milestone := range milestones {
			if p.Runs >= milestone && lastMilestone < milestone {
				title := fmt.Sprintf("Milestone: %s reached %d!", p.Name, milestone)
				sendDiscordAlertWithSubscriptions(config, title, 0xffd700, current, SubMilestones)
				current.NotifiedMilestone[p.Name] = milestone
			}
		}
	}
}

func (ms *MatchState) tossAlerted() bool {
	return ms.Toss != ""
}

func (ms *MatchState) gameStarted() bool {
	return ms.Score == "started" || strings.Contains(ms.Score, "/")
}

func isWicketFall(prevScore, newScore string) bool {
	prevWickets := getWickets(prevScore)
	newWickets := getWickets(newScore)
	return newWickets > prevWickets
}

func getWickets(score string) int {
	if !strings.Contains(score, "/") {
		return 0
	}
	parts := strings.Split(score, "/")
	if len(parts) > 1 {
		wickets, _ := strconv.Atoi(strings.Split(parts[1], " ")[0])
		return wickets
	}
	return 0
}

// sendDiscordAlertWithSubscriptions sends alerts via both webhook and bot (with user mentions)
func sendDiscordAlertWithSubscriptions(config Config, title string, color int, state *MatchState, alertType SubscriptionType) {
	// Send via webhook (existing functionality) - make it non-blocking
	go func() {
		sendDiscordAlert(config, title, color, state)
	}()

	// Send via bot with user mentions if bot is available (non-blocking)
	if globalBot != nil {
		go func() {
			err := globalBot.SendAlertWithMentions(title, color, state, alertType)
			if err != nil {
				log.Printf("Failed to send bot alert: %v", err)
			}
		}()
	}
}

func sendDiscordAlert(config Config, title string, color int, state *MatchState) {
	// Enhanced error handling wrapper
	err := circuitBreaker.Execute(func() error {
		return sendDiscordAlertInternal(config, title, color, state)
	})
	if err != nil {
		logger.LogError("sendDiscordAlert", err, map[string]interface{}{
			"title":    title,
			"match_id": state.MatchID,
		})
	}
}

func sendDiscordAlertInternal(config Config, title string, color int, state *MatchState) error {
	var fields []DiscordEmbedField

	// Main Score and Overs
	if state.Score != "" {
		scoreValue := fmt.Sprintf("%s (%s)", state.Score, state.Overs)
		fields = append(fields, DiscordEmbedField{Name: "🏏 Score", Value: scoreValue, Inline: false})
	}

	// Run Rate
	if state.RunRate != "" {
		fields = append(fields, DiscordEmbedField{Name: "Run Rate", Value: state.RunRate, Inline: false})
	}

	// Batsmen
	var batsmenValue string
	for _, p := range state.CurrentPlayers {
		batsmenValue += fmt.Sprintf("**%s**: %d (%d) - 4s: %d, 6s: %d\n", p.Name, p.Runs, p.Balls, p.Fours, p.Sixes)
	}
	if batsmenValue != "" {
		fields = append(fields, DiscordEmbedField{Name: "Batsmen", Value: batsmenValue, Inline: false})
	}

	// Bowler
	if state.CurrentBowler.Name != "" {
		bowlerValue := fmt.Sprintf("**%s**: %d-%d (%s)\n", state.CurrentBowler.Name, state.CurrentBowler.Wickets, state.CurrentBowler.Runs, state.CurrentBowler.Overs)
		fields = append(fields, DiscordEmbedField{Name: "Bowler", Value: bowlerValue, Inline: false})
	}

	// Partnership
	if state.Partnership != "" {
		fields = append(fields, DiscordEmbedField{Name: "Partnership", Value: state.Partnership, Inline: false})
	}

	// Yet to Bat
	if state.YetToBat != "" {
		fields = append(fields, DiscordEmbedField{Name: "Next to Bat", Value: state.YetToBat, Inline: false})
	}

	// Last Wicket
	if state.LastWicket != "" {
		fields = append(fields, DiscordEmbedField{Name: "Last Wicket", Value: state.LastWicket, Inline: false})
	}

	// Recent Overs
	// Only add if it's not empty and not just the prefix
	if state.RecentOvers != "" && strings.TrimSpace(state.RecentOvers) != "Recent:" {
		fields = append(fields, DiscordEmbedField{Name: "Recent Overs", Value: state.RecentOvers, Inline: false})
	}

	// Toss
	if state.Toss != "" {
		fields = append(fields, DiscordEmbedField{Name: "Toss", Value: state.Toss, Inline: false})
	}

	// Venue
	if state.Venue != "" {
		fields = append(fields, DiscordEmbedField{Name: "Venue", Value: state.Venue, Inline: false})
	}
	// Series
	if state.Series != "" {
		fields = append(fields, DiscordEmbedField{Name: "Series", Value: state.Series, Inline: false})
	}
	// Format
	if state.Format != "" {
		fields = append(fields, DiscordEmbedField{Name: "Format", Value: state.Format, Inline: true})
	}

	// Chase requirements
	if state.TargetRuns > 0 && state.TargetBalls > 0 {
		rrr := float64(state.TargetRuns) / (float64(state.TargetBalls) / 6.0)
		chase := fmt.Sprintf("%d off %d  |  RRR %.2f", state.TargetRuns, state.TargetBalls, rrr)
		fields = append(fields, DiscordEmbedField{Name: "Target", Value: chase, Inline: false})
	}

	// If this is a wicket alert, surface FoW list
	if strings.Contains(strings.ToLower(title), "wicket") && state.LastFoW != "" {
		fields = append(fields, DiscordEmbedField{Name: "Fall of Wickets", Value: state.LastFoW, Inline: false})
	}

	description := fmt.Sprintf("%s v %s\n%s", state.Team1, state.Team2, state.Status)
	discordEmbed := DiscordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Fields:      fields,
		Footer: &DiscordEmbedFooter{
			Text: "via CricAlerts",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	discordMessage := DiscordMessage{
		Username:  "Cric-Alerts",
		AvatarURL: "https://www.cricbuzz.com/images/cb_logo.png", // You can change this to a custom avatar URL
		Embeds:    []DiscordEmbed{discordEmbed},
	}

	payload, err := json.Marshal(discordMessage)
	if err != nil {
		log.Printf("Error marshalling Discord message: %v", err)
		return fmt.Errorf("error marshalling Discord message: %v", err)
	}

	for _, webhookURL := range config.DiscordWebhookURLs {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Error creating request: %v", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error sending Discord webhook: %v", err)
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("error closing webhook response: %v", err)
			}
		}()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("Discord webhook returned status: %d", resp.StatusCode)
		}
	}
	return nil
}
