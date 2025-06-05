# Core CA - Certificate Authority Service

A Go-based Certificate Authority service using PKCS#11 (SoftHSM) for secure key management.

## Features

- 🔐 **Secure Key Management**: Uses PKCS#11 HSM (SoftHSM) for private key storage
- 📜 **Certificate Issuance**: Issues X.509 certificates from CSRs
- 🗄️ **Database Storage**: PostgreSQL for certificate metadata storage
- 🔒 **Crypto Standards**: PKCS#1 v1.5 signatures with proper DigestInfo handling

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
  validity_days: 365
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

### 2. Generate Key Pair

```bash
curl -X POST http://localhost:8080/keymanagement/generate \
  -H "Content-Type: application/json" \
  -d '{"id": "test1"}'
```

### 3. Get Public Key

```bash
curl http://localhost:8080/keymanagement/test1
```

### 4. Issue Certificate

```bash
# First, create a CSR (Certificate Signing Request)
openssl req -new -key private.key -out request.csr

# Then submit to CA
curl -X POST http://localhost:8080/ca/issue \
  -H "Content-Type: application/json" \
  -d '{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"}'
```

## API Endpoints

### Key Management

- `POST /keymanagement/generate` - Generate new key pair
- `GET /keymanagement/{id}` - Get public key

### Certificate Authority

- `POST /ca/issue` - Issue certificate from CSR

## Security Considerations

⚠️ **IMPORTANT**: This is a demo implementation. For production use:

- Use Hardware Security Modules (HSM) instead of SoftHSM
- Implement proper access controls and authentication
- Add certificate revocation (CRL/OCSP)
- Secure database connections
- Add audit logging
- Implement certificate chain validation

## Development

### Project Structure

```
├── ca/                    # Certificate Authority logic
│   ├── config/           # CA configuration
│   ├── model/            # CA data models
│   ├── repository/       # Certificate storage
│   └── service/          # CA business logic
├── keymanagement/        # Key management with PKCS#11
│   ├── config/           # Key management configuration
│   ├── model/            # Key pair models
│   ├── repository/       # HSM integration
│   └── service/          # Key management services
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

## Troubleshooting

### PKCS#11 Errors

- **CKR_ATTRIBUTE_TYPE_INVALID**: Check SoftHSM token initialization and key attributes
- **Slot not found**: Verify slot ID from `softhsm2-util --show-slots`
- **Login failed**: Check PIN configuration

### Certificate Issues

- **Signature verification failed**: Ensure DigestInfo is properly formatted
- **Private key mismatch**: Verify key pair was generated correctly

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request
