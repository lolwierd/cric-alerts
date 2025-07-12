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
}

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
	YetToBat    string
	TargetRuns  int
	TargetBalls int
	LastFoW     string
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
	matchStates = make(map[string]*MatchState)
	mu          sync.RWMutex
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

	config := Config{
		DiscordWebhookURLs: urls, // Get your webhook URL from Discord
		TargetTeam:         "IND",
		PollInterval:       30 * time.Second,
		AlertOnToss:        true,
		AlertOnStart:       true,
		AlertOnWicket:      true,
		AlertOnScoreEvery:  5, // Alert every 5 overs
		PlayerMilestones:   []int{50, 100, 150, 200, 250, 300},
	}

	if len(config.DiscordWebhookURLs) == 0 {
		log.Fatal("DISCORD_WEBHOOK_URLS environment variable not set.")
	}

	log.Printf("Starting cricket alerter for %s matches.", config.TargetTeam)

	go func() {
		for {
			scrapeAndAlert(config)
			time.Sleep(config.PollInterval)
		}
	}()

	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		for _, state := range matchStates {
			sendDiscordAlert(config, "Manual Alert", 0x0000ff, state)
		}
		w.Write([]byte("alert sent"))
	})

	http.HandleFunc("/score", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(matchStates)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func scrapeAndAlert(config Config) {
	res, err := http.Get("https://www.cricbuzz.com/cricket-match/live-scores")
	if err != nil {
		log.Printf("Error fetching live scores: %v", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Printf("Status code error: %d %s", res.StatusCode, res.Status)
		return
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Printf("Error parsing HTML: %v", err)
		return
	}

	totalMatches := doc.Find("a.cb-lv-scrs-well.cb-lv-scrs-well-live").Length()
	log.Printf("Found %d live matches", totalMatches)

	targetCount := 0
	doc.Find("a.cb-lv-scrs-well.cb-lv-scrs-well-live").Each(func(i int, s *goquery.Selection) {
		isTargetMatch := false
		s.Find(".cb-hmscg-tm-nm").Each(func(_ int, team *goquery.Selection) {
			if strings.Contains(team.Text(), config.TargetTeam) {
				isTargetMatch = true
			}
		})

		if isTargetMatch {
			targetCount++
			href, _ := s.Attr("href")
			processMatch(href, config)
		}
	})
	log.Printf("Processed %d matches for %s", targetCount, config.TargetTeam)
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

	mu.Lock()
	prevState, ok := matchStates[matchID]
	if !ok {
		log.Printf("Started tracking new match: %s", matchID)
		prevState = &MatchState{
			MatchID:           matchID,
			LastAlertedOver:   -1,
			NotifiedMilestone: make(map[string]int),
		}
		matchStates[matchID] = prevState
	}
	mu.Unlock()

	resp, err := http.Get(fmt.Sprintf("https://www.cricbuzz.com/live-cricket-scores/%s", matchID))
	if err != nil {
		log.Printf("Error fetching match details for %s: %v", matchID, err)
		return
	}
	defer resp.Body.Close()

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
	newState.MatchID = matchID
	newState.LastAlertedOver = prevState.LastAlertedOver
	newState.NotifiedMilestone = prevState.NotifiedMilestone

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

	log.Printf("Current state for match %s: %s vs %s, %s, %s %s, CRR: %s", matchID, newState.Team1, newState.Team2, newState.Status, newState.Score, newState.Overs, newState.RunRate)
	log.Printf("Batsmen: %+v, Bowler: %+v", newState.CurrentPlayers, newState.CurrentBowler)
	log.Printf("Partnership: %s, Last Wicket: %s, Recent: %s, Toss: %s", newState.Partnership, newState.LastWicket, newState.RecentOvers, newState.Toss)

	// Alerting logic
	if config.AlertOnToss && !prevState.tossAlerted() && strings.Contains(newState.Toss, "won") {
		sendDiscordAlert(config, fmt.Sprintf("Toss: %s", newState.Toss), 0x00ff00, &newState)
	}

	if config.AlertOnStart && !prevState.gameStarted() && strings.Contains(newState.Score, "/") {
		sendDiscordAlert(config, "Match Started", 0x00ff00, &newState)
		prevState.Score = "started"
	}

	if newState.Score != "" && prevState.Score != "started" && prevState.Score != newState.Score {
		if config.AlertOnWicket && isWicketFall(prevState.Score, newState.Score) &&
			newState.LastWicket != "" && newState.LastWicket != prevState.LastWicket {
			title := "Wicket"
			if newState.LastWicket != "" {
				title = fmt.Sprintf("Wicket: %s", newState.LastWicket)
			}
			sendDiscordAlert(config, title, 0xff0000, &newState)
		}

		currentOver, _ := strconv.Atoi(strings.Split(newState.Overs, ".")[0])
		if scoreAlertEvery > 0 && currentOver > prevState.LastAlertedOver && currentOver%scoreAlertEvery == 0 {
			sendDiscordAlert(config, "Score Update", 0x0000ff, &newState)
			newState.LastAlertedOver = currentOver
		}
	}

	checkPlayerMilestones(config, prevState, &newState, milestones)

	mu.Lock()
	matchStates[matchID] = &newState
	mu.Unlock()
}

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

func checkPlayerMilestones(config Config, prev, current *MatchState, milestones []int) {
	for _, p := range current.CurrentPlayers {
		lastMilestone := prev.NotifiedMilestone[p.Name]
		for _, milestone := range milestones {
			if p.Runs >= milestone && lastMilestone < milestone {
				title := fmt.Sprintf("Milestone: %s reached %d!", p.Name, milestone)
				sendDiscordAlert(config, title, 0xffd700, current)
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

func sendDiscordAlert(config Config, title string, color int, state *MatchState) {
	var fields []DiscordEmbedField

	// Main Score and Overs
	if state.Score != "" {
		scoreValue := fmt.Sprintf("%s (%s)", state.Score, state.Overs)
		fields = append(fields, DiscordEmbedField{Name: "Score", Value: scoreValue, Inline: false})
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
		return
	}

	for _, webhookURL := range config.DiscordWebhookURLs {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Error creating Discord request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error sending Discord message: %v", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			log.Printf("Discord API returned non-2xx status: %d", resp.StatusCode)
		} else {
			log.Printf("Sent alert: %s", title)
		}
	}
}
