package service

import (
	"bytes"
	"context"
	"core-ca/ca/config"
	"core-ca/ca/model"
	"core-ca/ca/repository"
	"core-ca/keymanagement/service"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"

	"encoding/asn1"
	"encoding/pem"
	"errors"

	"fmt"
	"math/big"
	"time"
)

type CaService interface {
	CreateCA(ctx context.Context, name string, caType string, parentCAID *int) (model.CA, error)
	GetCA(ctx context.Context, caID int) (model.CA, error)
	// GetCAChain (ctx context.Context, id int) ([]model.CA, error)
	RevokeCA(ctx context.Context, caID int, reason model.RevocationReason) error

	IssueCertificate(csrPEM string) ([]byte, error)
	RevokeCertificate(serialNumber, reason model.RevocationReason) error
	GetCRL() ([]byte, error)
	// GetCertificateStatus(serialNumber string) (model.CertificateStatus, error)
}

type caService struct {
	repo       repository.Repository
	keyService service.KeyManagementService
	cfg        *config.Config
}

func NewCaService(repo repository.Repository, keyService service.KeyManagementService, cfg *config.Config) CaService {
	return &caService{
		repo:       repo,
		keyService: keyService,
		cfg:        cfg,
	}
}

func (s *caService) IssueCertificate(csrPEM string) ([]byte, error) {
	ctx := context.Background()

	// Parse CSR
	csrBlock, _ := pem.Decode([]byte(csrPEM))

	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("invalid CSR signature")
	}

	// Get signer.
	signer, err := s.keyService.GetSigner("test1")
	if err != nil {
		return nil, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create certificate template for the subject (end entity).
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(s.cfg.ValidityDays) * 24 * time.Hour)
	subjectTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		Issuer: pkix.Name{
			CommonName: s.cfg.Issuer,
			// Organization: []string{"Example Org"},
			// Country:      []string{"VN"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          []byte{1, 2, 3, 4}, // Simplified.
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	// Create issuer (CA) template with CA's public key.
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		// Subject: pkix.Name{
		// 	CommonName:   s.cfg.Issuer,
		// 	Organization: []string{"Example Org"},
		// 	Country:      []string{"VN"},
		// },
		Issuer: pkix.Name{
			CommonName:   s.cfg.Issuer,
			Organization: []string{"Example Org"},
			Country:      []string{"VN"},
		},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notAfter.Add(365 * 24 * time.Hour), // CA valid longer.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		CRLDistributionPoints: []string{
			"https://my-ca.example.com/ca/crl",
		},
	}

	// Create certificate.
	certDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, csr.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Save certificate metadata.
	certData := model.CertificateData{
		SerialNumber: serialNumber.String(),
		Subject:      csr.Subject.CommonName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		CertPEM:      string(certPEM),
	}
	if err := s.repo.Save(ctx, certData); err != nil {
		return nil, err
	}

	return certPEM, nil
}

func (s *caService) RevokeCertificate(serialNumber, reason string) error {
	ctx := context.Background()
	// Validate certificate exists.
	_, err := s.repo.FindBySerialNumber(ctx, serialNumber)
	if err != nil {
		return errors.New("certificate not found")
	}
	// Revoke certificate.
	return s.repo.Revoke(ctx, serialNumber, reason, false)
}

func (s *caService) GetCRL() ([]byte, error) {
	ctx := context.Background()

	revokedCerts, err := s.repo.GetRevokedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	//Get key pair
	keypair, err := s.keyService.GetKeyPair("test1")
	if err != nil {
		return nil, err
	}

	// Get signer.
	signer, err := s.keyService.GetSigner("test1")
	if err != nil {
		return nil, err
	}

	var revokedList []x509.RevocationListEntry
	for _, cert := range revokedCerts {
		serialNumber, ok := new(big.Int).SetString(cert.SerialNumber, 10)
		if !ok {
			return nil, errors.New("invalid serial number")
		}
		var reasonCode = map[model.RevocationReason]int{
			model.ReasonUnspecified:          0,
			model.ReasonKeyCompromise:        1,
			model.ReasonCACompromise:         2,
			model.ReasonAffiliationChanged:   3,
			model.ReasonSuperseded:           4,
			model.ReasonCessationOfOperation: 5,
			model.ReasonCertificateHold:      6,
		}[model.RevocationReason(cert.Reason)]

		value, err := asn1.Marshal(reasonCode)
		if err != nil {
			return nil, err
		}

		revokedList = append(revokedList, x509.RevocationListEntry{
			SerialNumber:   serialNumber,
			RevocationTime: cert.RevocationDate,
			ReasonCode:     reasonCode,
			Extensions: []pkix.Extension{
				{
					Id:    []int{2, 5, 29, 21}, // CRLReason OID.
					Value: value,
				},
			},
		})
	}

	// Create CRL.
	crlTemplate := x509.RevocationList{
		Issuer: pkix.Name{
			CommonName:   s.cfg.Issuer,
			Organization: []string{"Example Org"},
			Country:      []string{"VN"},
		},
		SignatureAlgorithm:        x509.SHA256WithRSA,
		RevokedCertificateEntries: revokedList,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(7 * 24 * time.Hour),
		Number:                    big.NewInt(1),
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(s.cfg.ValidityDays) * 24 * time.Hour)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(keypair.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: s.cfg.Issuer,
			// Organization: []string{"Example Org"},
			// Country:      []string{"VN"},
		},
		Issuer: pkix.Name{
			CommonName: s.cfg.Issuer + "haha",
			// Organization: []string{"Example Org"},
			// Country:      []string{"VN"},
		},
		NotBefore:             notBefore.Add(-24 * time.Hour),
		NotAfter:              notAfter.Add(365 * 24 * time.Hour), // CA valid longer.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKey:             keypair.PublicKey,
		PublicKeyAlgorithm:    x509.RSA,
		CRLDistributionPoints: []string{
			"https://my-ca.example.com/ca/crl",
		},
		SubjectKeyId: func() []byte {
			sum := sha1.Sum(pubKeyBytes)
			return sum[:]
		}(),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, issuerTemplate, signer)
	if err != nil {
		return nil, err
	}

	var pemBuf bytes.Buffer
	err = pem.Encode(&pemBuf, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	if err != nil {
		return nil, err
	}

	return pemBuf.Bytes(), nil

}
