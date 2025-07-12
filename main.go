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
	"time"

	"github.com/PuerkitoBio/goquery"
)

// Config holds the configuration for the alerting service.
type Config struct {
	DiscordWebhookURL string
	TargetTeam        string
	PollInterval      time.Duration
	AlertOnToss       bool
	AlertOnStart      bool
	AlertOnWicket     bool
	AlertOnScoreEvery int // in overs
	PlayerMilestones  []int
}

// MatchState holds the current state of a match.
type MatchState struct {
	MatchID           string
	Team1             string
	Team2             string
	Score             string
	Overs             string
	OversLeft         string
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
	Event             string // New field for the event/series name
	Format            string // New field for match format (Test/ODI/T20)
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
}

// DiscordMessage represents a message to be sent to Discord.
type DiscordMessage struct {
	Username  string         `json:"username"`
	AvatarURL string         `json:"avatar_url"`
	Embeds    []DiscordEmbed `json:"embeds"`
}

func main() {
	config := Config{
		DiscordWebhookURL: os.Getenv("DISCORD_WEBHOOK_URL"), // Get your webhook URL from Discord
		TargetTeam:        "IND",
		PollInterval:      30 * time.Second,
		AlertOnToss:       true,
		AlertOnStart:      true,
		AlertOnWicket:     true,
		AlertOnScoreEvery: 5, // Alert every 5 overs
		PlayerMilestones:  []int{50, 100, 150, 200, 250, 300},
	}

	if config.DiscordWebhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable not set.")
	}

	log.Printf("Starting cricket alerter for %s matches.", config.TargetTeam)

	matchStates := make(map[string]*MatchState)

	for {
		scrapeAndAlert(config, matchStates)
		time.Sleep(config.PollInterval)
	}
}

func scrapeAndAlert(config Config, matchStates map[string]*MatchState) {
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
			processMatch(href, config, matchStates)
		}
	})
	log.Printf("Processed %d matches for %s", targetCount, config.TargetTeam)
}

func processMatch(href string, config Config, matchStates map[string]*MatchState) {
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
		if config.AlertOnWicket && isWicketFall(prevState.Score, newState.Score) {
			title := "Wicket"
			if newState.LastWicket != "" {
				title = fmt.Sprintf("Wicket: %s", newState.LastWicket)
			}
			sendDiscordAlert(config, title, 0xff0000, &newState)
		}

		currentOver, _ := strconv.Atoi(strings.Split(newState.Overs, ".")[0])
		if config.AlertOnScoreEvery > 0 && currentOver > prevState.LastAlertedOver && currentOver%config.AlertOnScoreEvery == 0 {
			sendDiscordAlert(config, fmt.Sprintf("Score Update: %s (%s)", newState.Score, newState.Overs), 0x0000ff, &newState)
			newState.LastAlertedOver = currentOver
		}
	}

	checkPlayerMilestones(config, prevState, &newState)

	matchStates[matchID] = &newState
}

func parseScorecard(doc *goquery.Document) MatchState {
	var state MatchState

	// Extract Team1 and Team2 from the title tag
	fullTitle := doc.Find("title").Text()
	titleParts := strings.Split(fullTitle, " | ")[0]
	// Regex to capture "Team1 v Team2" from "Team1 v Team2, 3rd Test..." or "Team1 v Team2, Some League"
	teamNamesRegex := regexp.MustCompile(`(.+?)\s+v\s+(.+?)(?:,\s+\d(?:st|nd|rd|th)?\s+Test|,.*|$)`)
	teamMatches := teamNamesRegex.FindStringSubmatch(titleParts)
	if len(teamMatches) > 2 {
		state.Team1 = strings.TrimSpace(teamMatches[1])
		state.Team2 = strings.TrimSpace(teamMatches[2])
	} else {
		// Fallback if the specific regex for Test matches or other formats fails
		// Try to get from the main score section if available
		state.Team1 = strings.TrimSpace(doc.Find(".cb-scrs-wrp .cb-text-gray").First().Text())
		state.Team2 = strings.TrimSpace(doc.Find(".cb-scrs-wrp .cb-font-20").First().Text())
	}
	log.Printf("Parsed Team1: %s, Team2: %s", state.Team1, state.Team2)

	// Extract Event/Series Name
	eventRegex := regexp.MustCompile(`(?:,\s+\d(?:st|nd|rd|th)?\s+Test|,\s+\d{1,2}\s+\w{3}\s+\d{4},?)\s*(.*?),\s*Live Cricket Score`)
	eventMatches := eventRegex.FindStringSubmatch(fullTitle)
	if len(eventMatches) > 1 {
		state.Event = strings.TrimSpace(eventMatches[1])
		// Clean up common prefixes/suffixes if necessary
		state.Event = strings.TrimPrefix(state.Event, ", ")
		state.Event = strings.TrimSuffix(state.Event, ", Live Cricket Score")
	} else {
		// Fallback: try to extract from the title parts if the specific regex fails
		parts := strings.Split(titleParts, ",")
		if len(parts) > 2 {
			state.Event = strings.TrimSpace(parts[2])
		}
	}
	log.Printf("Parsed Event: %s", state.Event)

	// Extract Match Format
	formatRegex := regexp.MustCompile(`(\d+(?:st|nd|rd|th)?\s+(Test|ODI|T20I|T20))`)
	formatMatches := formatRegex.FindStringSubmatch(fullTitle)
	if len(formatMatches) > 1 {
		state.Format = formatMatches[2]
	} else {
		// Fallback for other formats
		if strings.Contains(fullTitle, "Test") {
			state.Format = "Test"
		} else if strings.Contains(fullTitle, "ODI") {
			state.Format = "ODI"
		} else if strings.Contains(fullTitle, "T20") {
			state.Format = "T20"
		}
	}
	log.Printf("Parsed Format: %s", state.Format)

	// Status
	state.Status = strings.TrimSpace(doc.Find(".cb-text-inprogress, .cb-text-complete, .cb-text-preview").First().Text())
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

	if state.Format == "Test" && state.Overs != "" {
		if ov, err := strconv.ParseFloat(state.Overs, 64); err == nil {
			left := 90.0 - ov
			if left < 0 {
				left = 0
			}
			state.OversLeft = fmt.Sprintf("%.1f overs left today", left)
		}
	}

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

func checkPlayerMilestones(config Config, prev, current *MatchState) {
	for _, p := range current.CurrentPlayers {
		lastMilestone := prev.NotifiedMilestone[p.Name]
		for _, milestone := range config.PlayerMilestones {
			if p.Runs >= milestone && lastMilestone < milestone {
				title := fmt.Sprintf("Milestone: %s reached %d", p.Name, milestone)
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
		fields = append(fields, DiscordEmbedField{Name: "Score", Value: scoreValue, Inline: true})
	}

	// Run Rate
	if state.RunRate != "" {
		fields = append(fields, DiscordEmbedField{Name: "Run Rate", Value: state.RunRate, Inline: true})
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
		fields = append(fields, DiscordEmbedField{Name: "Partnership", Value: state.Partnership, Inline: true})
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

	// Overs left in day for Tests
	if state.OversLeft != "" {
		fields = append(fields, DiscordEmbedField{Name: "Overs Left", Value: state.OversLeft, Inline: true})
	}

	description := fmt.Sprintf("%s v %s - %s %s\n%s", state.Team1, state.Team2, state.Event, state.Format, state.Status)
	discordEmbed := DiscordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Fields:      fields,
		Footer: &DiscordEmbedFooter{
			Text: time.Now().Format("Jan 2, 2006 at 3:04 PM MST"),
		},
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

	req, err := http.NewRequest("POST", config.DiscordWebhookURL, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("Error creating Discord request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending Discord message: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("Discord API returned non-2xx status: %d", resp.StatusCode)
	} else {
		log.Printf("Sent alert: %s", title)
	}
}
