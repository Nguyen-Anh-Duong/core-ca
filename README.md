# Core CA - Certificate Authority Service

A Go-based Certificate Authority service using PKCS#11 (SoftHSM) for secure key management with support for certificate issuance, revocation, and CRL generation.

## Features

- 🔐 **Secure Key Management**: Uses PKCS#11 HSM (SoftHSM) for private key storage
- 📜 **Certificate Issuance**: Issues X.509 certificates from CSRs
- 🏛️ **CA Hierarchy**: Support for Root CA and Subordinate CA creation
- 🚫 **Certificate Revocation**: Revoke certificates with reason codes
- 📋 **Certificate Revocation List (CRL)**: Generate CA-specific CRLs
- 🔍 **OCSP Support**: Online Certificate Status Protocol for real-time status checking
- 🗄️ **Database Storage**: PostgreSQL for certificate and CA metadata storage
- 🔒 **Crypto Standards**: PKCS#1 v1.5 signatures with proper DigestInfo handling
- 📖 **API Documentation**: Swagger/OpenAPI documentation

## Prerequisites

- Go 1.21+
- PostgreSQL
- SoftHSM2
- PKCS#11 library

## Installation

### 1. Install SoftHSM2

**Ubuntu/Debian:**

```bash
sudo apt-get install softhsm2
```

**macOS:**

```bash
brew install softhsm
```

### 2. Initialize SoftHSM Token

```bash
# Initialize token
softhsm2-util --init-token --slot 0 --label "CA-Token" --pin 1234 --so-pin 5678

# List slots to get slot ID
softhsm2-util --show-slots
```

### 3. Setup Database

```sql
CREATE DATABASE core_ca;
-- Connection details will be in config.yaml
```

### 4. Configure Application

```bash
# Copy config template
cp config.yaml.example config.yaml

# Edit with your settings
vim config.yaml
```

## Configuration

Edit `config.yaml` with your specific settings:

```yaml
keymanagement:
  softhsm:
    module: /usr/lib/softhsm/libsofthsm2.so # Path to PKCS#11 library
    slot: "YOUR_SLOT_ID" # From softhsm2-util --show-slots
    pin: "1234" # Your token PIN

ca:
  issuer: "CN=My CA,O=My Organization,C=VN"
  validity_days: 2920 # 8 years for Root CA
  database:
    dsn: "postgres://user:pass@localhost:5432/core_ca?sslmode=disable"
```

## Usage

### 1. Build and Run

```bash
go mod tidy
go build -o core-ca
./core-ca
```

The server will start on `http://localhost:8080`

### 2. API Documentation

Access Swagger documentation at: `http://localhost:8080/swagger/index.html`

## API Endpoints

### Key Management

#### Generate Key Pair

```bash
curl -X POST http://localhost:8080/keymanagement/generate \
  -H "Content-Type: application/json" \
  -d '{"id": "test1"}'
```

#### Get Public Key

```bash
curl http://localhost:8080/keymanagement/test1
```

### Certificate Authority Management

#### Create Root CA

```bash
curl -X POST http://localhost:8080/ca/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyRootCA",
    "type": "root"
  }'
```

#### Create Subordinate CA

```bash
curl -X POST http://localhost:8080/ca/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MySubCA",
    "type": "sub",
    "parent_ca_id": 1
  }'
```

### Certificate Operations

#### Issue Certificate

```bash
# First, create a CSR (Certificate Signing Request)
openssl req -new -key private.key -out request.csr

# Convert CSR to single line for JSON
CSR_CONTENT=$(cat request.csr | tr -d '\n')

# Then submit to CA
curl -X POST http://localhost:8080/ca/issue \
  -H "Content-Type: application/json" \
  -d "{
    \"csr\": \"$CSR_CONTENT\",
    \"ca_id\": 1
  }"
```

#### Revoke Certificate

```bash
curl -X POST http://localhost:8080/ca/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "123456789",
    "reason": "keyCompromise"
  }'
```

**Available revocation reasons:**

- `unspecified`
- `keyCompromise`
- `caCompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold`

#### Get Certificate Revocation List (CRL)

```bash
# Get CRL for specific CA (JSON format)
curl "http://localhost:8080/ca/crl?ca_id=1" \
  -H "Accept: application/x-pem-file" \
  --output ca1.crl

# Get CRL as downloadable file (standard format)
curl "http://localhost:8080/crl.pem?ca_id=1" \
  --output ca1.crl

# Or use in browser/Postman
# GET http://localhost:8080/crl.pem?ca_id=1
```

#### Check Certificate Status via OCSP

```bash
# Create OCSP request using OpenSSL
SERIAL_NUMBER="123456789"  # Serial number to check
openssl ocsp -issuer ca.crt -serial $SERIAL_NUMBER -reqout ocsp_request.der

# Send OCSP request to server
curl -X POST "http://localhost:8080/ocsp?ca_id=1" \
  -H "Content-Type: application/ocsp-request" \
  --data-binary @ocsp_request.der \
  --output ocsp_response.der

# Verify OCSP response
openssl ocsp -respin ocsp_response.der -text -CAfile ca.crt
```

## Complete API Reference

| Method | Endpoint                  | Description           | Parameters                                                     |
| ------ | ------------------------- | --------------------- | -------------------------------------------------------------- |
| `POST` | `/keymanagement/generate` | Generate new key pair | `{"id": "string"}`                                             |
| `GET`  | `/keymanagement/{id}`     | Get public key        | Path: `id`                                                     |
| `POST` | `/ca/create`              | Create new CA         | `{"name": "string", "type": "root\|sub", "parent_ca_id": int}` |
| `POST` | `/ca/issue`               | Issue certificate     | `{"csr": "string", "ca_id": int}`                              |
| `POST` | `/ca/revoke`              | Revoke certificate    | `{"serial_number": "string", "reason": "string"}`              |
| `GET`  | `/ca/crl`                 | Get CRL (JSON)        | Query: `ca_id`                                                 |
| `GET`  | `/crl.pem`                | Get CRL (file)        | Query: `ca_id`                                                 |
| `POST` | `/ocsp`                   | OCSP status check     | Query: `ca_id`, Body: OCSP request (DER)                       |
| `GET`  | `/swagger/*`              | API documentation     | -                                                              |

## Database Schema

The application automatically creates the following tables:

### certificate_authorities

- `id` (SERIAL PRIMARY KEY)
- `name` (VARCHAR NOT NULL UNIQUE)
- `type` (VARCHAR NOT NULL) - 'root' or 'sub'
- `parent_ca_id` (INTEGER) - Foreign key to parent CA
- `cert_pem` (TEXT NOT NULL)
- `status` (VARCHAR DEFAULT 'active')
- `created_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)

### certificates

- `serial_number` (VARCHAR PRIMARY KEY)
- `subject` (VARCHAR NOT NULL)
- `not_before` (TIMESTAMP NOT NULL)
- `not_after` (TIMESTAMP NOT NULL)
- `cert_pem` (TEXT NOT NULL)
- `ca_id` (INTEGER) - Foreign key to issuing CA
- `status` (VARCHAR DEFAULT 'valid')
- `created_at` (TIMESTAMP DEFAULT CURRENT_TIMESTAMP)

### revoked_certificates

- `serial_number` (VARCHAR PRIMARY KEY)
- `revocation_date` (TIMESTAMP NOT NULL)
- `reason` (VARCHAR)
- `is_ca` (BOOLEAN DEFAULT FALSE)

## Security Considerations

⚠️ **IMPORTANT**: This is a demo implementation. For production use:

- Use Hardware Security Modules (HSM) instead of SoftHSM
- Implement proper access controls and authentication
- Add RBAC (Role-Based Access Control)
- Secure database connections with TLS
- Add audit logging for all operations
- Implement certificate chain validation
- Use proper secret management for HSM PINs
- Add rate limiting and DDoS protection
- Implement OCSP (Online Certificate Status Protocol)

## Development

### Project Structure

```
├── ca/                    # Certificate Authority logic
│   ├── event/            # Certificate events
│   ├── model/            # CA data models
│   ├── repository/       # Certificate storage
│   └── service/          # CA business logic
├── keymanagement/        # Key management with PKCS#11
│   ├── config/           # Key management configuration
│   ├── model/            # Key pair models
│   ├── repository/       # HSM integration
│   └── service/          # Key management services
├── config/               # Application configuration
├── docs/                 # Swagger documentation
└── main.go              # Application entry point
```

### Running Tests

```bash
go test ./...
```

### Building for Production

```bash
CGO_ENABLED=1 go build -ldflags="-s -w" -o core-ca
```

### Regenerate Swagger Documentation

```bash
# Install swag
go install github.com/swaggo/swag/cmd/swag@latest

# Generate docs
swag init
```

## Examples

### Complete Workflow Example

```bash
# 1. Generate CA key pair
curl -X POST http://localhost:8080/keymanagement/generate \
  -H "Content-Type: application/json" \
  -d '{"id": "RootCA-Key"}'

# 2. Create Root CA
curl -X POST http://localhost:8080/ca/create \
  -H "Content-Type: application/json" \
  -d '{"name": "RootCA", "type": "root"}'

# 3. Generate end-entity key pair
openssl genrsa -out client.key 2048

# 4. Create CSR
openssl req -new -key client.key -out client.csr \
  -subj "/C=VN/O=MyOrg/CN=client.example.com"

# 5. Issue certificate
CSR_CONTENT=$(cat client.csr | tr -d '\n')
curl -X POST http://localhost:8080/ca/issue \
  -H "Content-Type: application/json" \
  -d "{\"csr\": \"$CSR_CONTENT\", \"ca_id\": 1}" \
  --output client.crt

# 6. Verify certificate
openssl x509 -in client.crt -text -noout

# 7. Revoke certificate (if needed)
SERIAL=$(openssl x509 -in client.crt -serial -noout | cut -d= -f2)
curl -X POST http://localhost:8080/ca/revoke \
  -H "Content-Type: application/json" \
  -d "{\"serial_number\": \"$SERIAL\", \"reason\": \"keyCompromise\"}"

# 8. Get CRL
curl "http://localhost:8080/crl.pem?ca_id=1" --output ca.crl

# 9. Verify CRL
openssl crl -in ca.crl -text -noout

# 10. Check certificate status via OCSP
SERIAL=$(openssl x509 -in client.crt -serial -noout | cut -d= -f2)
openssl ocsp -issuer ca.crt -serial $SERIAL -reqout ocsp_request.der
curl -X POST "http://localhost:8080/ocsp?ca_id=1" \
  -H "Content-Type: application/ocsp-request" \
  --data-binary @ocsp_request.der \
  --output ocsp_response.der
openssl ocsp -respin ocsp_response.der -text -CAfile ca.crt
```

## Troubleshooting

### PKCS#11 Errors

- **CKR_ATTRIBUTE_TYPE_INVALID**: Check SoftHSM token initialization and key attributes
- **Slot not found**: Verify slot ID from `softhsm2-util --show-slots`
- **Login failed**: Check PIN configuration

### Certificate Issues

- **Signature verification failed**: Ensure DigestInfo is properly formatted
- **Private key mismatch**: Verify key pair was generated correctly
- **CA not found**: Ensure CA exists before issuing certificates

### Database Issues

- **Connection failed**: Check PostgreSQL connection string
- **Table creation failed**: Ensure database user has CREATE permissions
- **Foreign key constraint**: Ensure parent CA exists when creating subordinate CA

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request
