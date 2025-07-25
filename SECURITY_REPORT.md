# Security and Bug Report

The code was scanned using `gosec` and `golangci-lint`. The following notable issues were detected:

## gosec findings

- **Use of http.ListenAndServe without timeouts** – `main.go` starts the HTTP server without configuring timeouts, which may lead to resource exhaustion attacks. See line 290.
- **HTTP requests with variable URLs** – `discord_bot.go` performs `http.Get` on user controlled URLs, increasing the risk of SSRF. See lines 1438–1456.
- **File writes with permissive permissions** – configuration and subscription files are written using mode `0644`. See lines 246–258 and 904–914 in `discord_bot.go`.
- **Unhandled errors** – several calls ignore returned errors (e.g. saving config, closing responses). See lines 50–55, 1254, and 1456 of `discord_bot.go` and lines 223, 280, 287 of `main.go`.

## golangci-lint findings

- Multiple error return values are unchecked, matching the gosec report.
- Deprecated function usage `strings.Title` at line 2223 of `discord_bot.go`.
- Inefficient or unnecessary code patterns flagged by `staticcheck` (e.g. redundant type declarations at lines 700 and 1954 in `discord_bot.go`).

These issues should be reviewed and addressed to improve reliability and security.
