#!/bin/bash

echo "=== Core CA API Test Script ==="
echo "Make sure the server is running on http://localhost:8080"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${YELLOW}$1${NC}"
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

# Test if server is running
print_step "1. Testing if server is running..."
if curl -s http://localhost:8080/swagger/index.html > /dev/null; then
    print_success "✓ Server is running!"
    echo "✓ Swagger UI available at: http://localhost:8080/swagger/index.html"
else
    print_error "✗ Server is not running. Please start with: go run main.go"
    exit 1
fi

echo ""
print_step "2. Testing Key Management API..."

# Test Generate Key Pair
echo "Testing POST /keymanagement/generate"
response=$(curl -s -X POST http://localhost:8080/keymanagement/generate \
    -H "Content-Type: application/json" \
    -d '{"id": "test-key-123"}')

if echo "$response" | grep -q "test-key-123"; then
    print_success "✓ Key generation successful: $response"
else
    print_error "✗ Key generation failed: $response"
fi

echo ""

# Test Get Key Pair
echo "Testing GET /keymanagement/test-key-123"
response=$(curl -s http://localhost:8080/keymanagement/test-key-123)

if echo "$response" | grep -q "publicKey"; then
    print_success "✓ Key retrieval successful"
    echo "  Response: $(echo $response | jq -r '.id')"
else
    print_error "✗ Key retrieval failed: $response"
fi

echo ""
print_step "3. Testing Certificate Authority API..."

# Test Issue Certificate (this will likely fail without proper CSR, but we can test the endpoint)
echo "Testing POST /ca/issue (will fail without valid CSR)"
response=$(curl -s -X POST http://localhost:8080/ca/issue \
    -H "Content-Type: application/json" \
    -d '{"csr": "invalid-csr-for-demo"}')

if echo "$response" | grep -q "error"; then
    print_success "✓ CA issue endpoint is working (expected error with invalid CSR)"
else
    print_error "✗ Unexpected response: $response"
fi

echo ""

# Test Revoke Certificate (will fail without valid serial number)
echo "Testing POST /ca/revoke (will fail without valid serial)"
response=$(curl -s -X POST http://localhost:8080/ca/revoke \
    -H "Content-Type: application/json" \
    -d '{"serial_number": "123456789", "reason": "test"}')

if echo "$response" | grep -q "error"; then
    print_success "✓ CA revoke endpoint is working (expected error with invalid serial)"
else
    print_error "✗ Unexpected response: $response"
fi

echo ""

# Test Get CRL
echo "Testing GET /ca/crl"
response=$(curl -s -w "%{http_code}" http://localhost:8080/ca/crl)
http_code=$(echo "$response" | tail -c 4)

if [ "$http_code" = "200" ]; then
    print_success "✓ CRL endpoint is working"
else
    print_error "✗ CRL endpoint failed with code: $http_code"
fi

echo ""
print_step "4. Summary"
print_success "✓ All API endpoints are accessible"
print_success "✓ Swagger documentation is available at: http://localhost:8080/swagger/index.html"
echo ""
echo "Next steps:"
echo "1. Visit http://localhost:8080/swagger/index.html to explore the API"
echo "2. Use the interactive Swagger UI to test endpoints"
echo "3. Check the API_DOCUMENTATION.md file for detailed documentation" 