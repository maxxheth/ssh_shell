# Simple Makefile for a Go project

# Build the application
all: build test

build:
	@echo "Building the application..."
	@mkdir -p dist
	@echo "Compiling the binary..."
	@go build -o dist/ssh-shell cmd/cli/main.go
	@echo "Binary created at dist/ssh-shell"
	@echo "Build complete."

# Run the application
run:
	@echo "Running the application..."
	@go run cmd/cli/main.go

# Test the application
test:
	@echo "Testing..."
	@go test ./... -v

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f dist/ssh-shell
	@echo "Deleted the binary."

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

.PHONY: all build run test clean watch
