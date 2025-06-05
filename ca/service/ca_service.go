package service

import (
	"context"
	"core-ca/ca/config"
	"core-ca/ca/model"
	"core-ca/ca/repository"
	"core-ca/keymanagement/service"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	// "encoding/asn1"
	"encoding/pem"
	"errors"

	"fmt"
	"math/big"
	"time"
)

type CaService interface {
	IssueCertificate(csrPEM string) (model.Certificate, error)
}

type caService struct {
	repo       repository.CertificateRepository
	keyService service.KeyManagementService
	cfg        *config.Config
}

func NewCaService(repo repository.CertificateRepository, keyService service.KeyManagementService, cfg *config.Config) CaService {
	return &caService{
		repo:       repo,
		keyService: keyService,
		cfg:        cfg,
	}
}

func (s *caService) IssueCertificate(csrPEM string) (model.Certificate, error) {
	ctx := context.Background()

	// Parse CSR
	csrBlock, _ := pem.Decode([]byte(csrPEM))

	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return model.Certificate{}, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return model.Certificate{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return model.Certificate{}, errors.New("invalid CSR signature")
	}

	// Get signer
	signer, err := s.keyService.GetSigner("test1")
	if err != nil {
		return model.Certificate{}, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return model.Certificate{}, err
	}

	// Create certificate template for the subject (end entity)
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(s.cfg.ValidityDays) * 24 * time.Hour)
	subjectTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		Issuer: pkix.Name{
			CommonName:   s.cfg.Issuer,
			Organization: []string{"Example Org"},
			Country:      []string{"VN"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          []byte{1, 2, 3, 4}, // Simplified
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Create issuer (CA) template with CA's public key
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   s.cfg.Issuer,
			Organization: []string{"Example Org"},
			Country:      []string{"VN"},
		},
		Issuer: pkix.Name{
			CommonName:   s.cfg.Issuer,
			Organization: []string{"Example Org"},
			Country:      []string{"VN"},
		},
		NotBefore:             notBefore.Add(-24 * time.Hour), // CA valid from yesterday
		NotAfter:              notAfter.Add(365 * 24 * time.Hour), // CA valid longer
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, csr.PublicKey, signer)
	if err != nil {
		return model.Certificate{}, fmt.Errorf("x509.CreateCertificate failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Save certificate metadata
	certData := model.CertificateData{
		SerialNumber: serialNumber.String(),
		Subject:      csr.Subject.CommonName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		CertPEM:      string(certPEM),
	}
	if err := s.repo.Save(ctx, certData); err != nil {
		return model.Certificate{}, err
	}

	return model.Certificate{
		SerialNumber: certData.SerialNumber,
		Subject:      certData.Subject,
		NotBefore:    string(certData.NotBefore.Format(time.RFC3339)),
		NotAfter:     string(certData.NotAfter.Format(time.RFC3339)),
		Raw:          certDER,
	}, nil
}
