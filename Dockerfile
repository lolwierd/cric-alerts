# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build application
RUN CGO_ENABLED=0 GOOS=linux go build -o cric-alerts

# Runtime stage
FROM alpine:latest

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /app

# Copy built binary
COPY --from=builder /app/cric-alerts .

# Copy .env file if exists
COPY .env ./

# Expose port if needed
# EXPOSE 8080

# Run the application
CMD ["./cric-alerts"]
