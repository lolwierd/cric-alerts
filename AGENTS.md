# AGENT INSTRUCTIONS

This repository contains a Go application for cricket alerts. Future changes should keep all code in Go and remain within this repository.

## Development guidelines

- Format all Go files with `gofmt -w` before committing.
- Run `go vet ./...` and `go build ./...` after changes to ensure the code compiles.
- If new dependencies are added, run `go mod tidy`.
- Keep functionality in the root module; do not create submodules.

## Desired bot features

The long term goal is to build a complete cricket bot, similar to the information available on Cricbuzz. The bot should eventually support:

- Listing live matches and live series
- Querying match information, match statistics, and match scoreboards
- Fetching live scores and commentary for ongoing games
- Providing endpoints or commands to access the above data

Implementation can be done gradually, extending the current scraping logic.

