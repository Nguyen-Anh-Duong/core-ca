.PHONY: help build run clean test-api swagger docs

# Default target
help:
	@echo "Core CA API - Available commands:"
	@echo ""
	@echo "  build      - Build the application"
	@echo "  run        - Run the application"
	@echo "  clean      - Clean build artifacts"
	@echo "  swagger    - Generate Swagger documentation"
	@echo "  test-api   - Test API endpoints (requires running server)"
	@echo "  docs       - Open API documentation"
	@echo "  install    - Install dependencies"
	@echo ""

# Build the application
build:
	@echo "Building Core CA application..."
	go build -o core-ca main.go
	@echo "✓ Build complete! Binary: ./core-ca"

# Run the application
run:
	@echo "Starting Core CA server on port 8080..."
	@echo "Swagger UI will be available at: http://localhost:8080/swagger/index.html"
	go run main.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f core-ca
	@echo "✓ Clean complete!"

# Generate Swagger documentation
swagger:
	@echo "Generating Swagger documentation..."
	swag init -g main.go --parseDependency --parseInternal
	@echo "✓ Swagger docs generated in ./docs/"
	@echo "✓ Access at: http://localhost:8080/swagger/index.html (when server is running)"

# Test API endpoints
test-api:
	@echo "Testing API endpoints..."
	./test_api.sh

# Open API documentation in browser (if server is running)
docs:
	@echo "Opening Swagger UI in browser..."
	@which xdg-open > /dev/null && xdg-open http://localhost:8080/swagger/index.html || \
	 which open > /dev/null && open http://localhost:8080/swagger/index.html || \
	 echo "Please open http://localhost:8080/swagger/index.html in your browser"

# Install dependencies
install:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download
	@echo "✓ Dependencies installed!"

# Install Swagger CLI if not present
install-swagger:
	@echo "Installing Swagger CLI..."
	go install github.com/swaggo/swag/cmd/swag@latest
	@echo "✓ Swagger CLI installed!"

# Development server with hot reload (requires air)
dev:
	@echo "Starting development server with hot reload..."
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

# Show project structure
tree:
	@echo "Project structure:"
	@tree -I '.git|tmp|*.log' || ls -la 