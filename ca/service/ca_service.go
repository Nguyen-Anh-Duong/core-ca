package service

import (
	"bytes"
	"context"
	"core-ca/ca/model"
	"core-ca/ca/repository"
	"core-ca/config"
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

	"golang.org/x/crypto/ocsp"
)

type CaService interface {
	CreateCA(ctx context.Context, name string, caType model.CAType, parentCAID *int) (model.CA, error)
	// GetCA(ctx context.Context, id int) (model.CA, error)
	// GetCAChain(ctx context.Context, caID int) ([]model.CA, error)
	// RevokeCA(ctx context.Context, caID int, reason model.RevocationReason) error

	IssueCertificate(ctx context.Context, csrPEM string, issuerID int) (model.Certificate, error)
	RevokeCertificate(ctx context.Context, serialNumber string, reason model.RevocationReason) error
	GetCRL(ctx context.Context, caID int) ([]byte, error)
	// GetCertificateStatus(ctx context.Context, serialNumber string) (model.CertificateStatus, error)
	HandleOCSPRequest(ctx context.Context, requestData []byte, caID int) ([]byte, error)
}

type caService struct {
	repo       repository.Repository
	keyService service.KeyManagementService
	cfg        *config.AppConfig
}

func NewCaService(repo repository.Repository, keyService service.KeyManagementService, cfg *config.AppConfig) CaService {
	return &caService{
		repo:       repo,
		keyService: keyService,
		cfg:        cfg,
	}
}

func (s *caService) IssueCertificate(ctx context.Context, csrPEM string, caID int) (model.Certificate, error) {

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

	ca, err := s.repo.FindCAByID(ctx, caID)
	if err != nil {
		return model.Certificate{}, fmt.Errorf("failed to find issuer CA: %w", err)
	}

	// Get signer.
	signer, err := s.keyService.GetSigner(ca.Name + "-Key")
	if err != nil {
		return model.Certificate{}, err
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return model.Certificate{}, err
	}

	block, _ := pem.Decode([]byte(ca.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return model.Certificate{}, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return model.Certificate{}, fmt.Errorf("failed to get issuer CA key: %v", err)
	}

	// set validity to half of issuer CA's lifetime
	certLifetime := caCert.NotAfter.Sub(caCert.NotBefore)
	halfLifetime := certLifetime / 2

	// Create certificate template for the subject (end entity).
	notBefore := time.Now()
	notAfter := notBefore.Add(halfLifetime)

	subjectTemplate := &x509.Certificate{
		Version:               csr.Version,
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId: func() []byte {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
			if err != nil {
				log.Fatal(err)
			}
			sum := sha1.Sum(pubKeyBytes)
			return sum[:]
		}(),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		ExtraExtensions:       csr.Extensions,
		AuthorityKeyId:        caCert.SubjectKeyId,
		CRLDistributionPoints: caCert.CRLDistributionPoints,
		OCSPServer:            caCert.OCSPServer,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
	}

	// Create certificate.
	cert, err := x509.CreateCertificate(rand.Reader, subjectTemplate, caCert, csr.PublicKey, signer)
	if err != nil {
		return model.Certificate{}, fmt.Errorf("x509.CreateCertificate failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	// Save certificate metadata.
	certData := model.Certificate{
		SerialNumber: serialNumber.String(),
		CAID:         ca.ID,
		Subject:      csr.Subject.CommonName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		CertPEM:      string(certPEM),
		Status:       model.StatusValid,
	}

	if err := s.repo.SaveCert(ctx, certData); err != nil {
		return model.Certificate{}, err
	}

	return certData, nil
}

func (s *caService) RevokeCertificate(ctx context.Context, serialNumber string, reason model.RevocationReason) error {
	// Validate certificate exists.
	_, err := s.repo.FindBySerialNumber(ctx, serialNumber)
	if err != nil {
		return errors.New("certificate not found")
	}
	// Revoke certificate.
	return s.repo.Revoke(ctx, serialNumber, string(reason), false)
}

func (s *caService) GetCRL(ctx context.Context, caID int) ([]byte, error) {

	ca, err := s.repo.FindCAByID(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("failed to find CA: %w", err)
	}

	// Parse CA certificate
	block, _ := pem.Decode([]byte(ca.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate PEM block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Get signer.
	signer, err := s.keyService.GetSigner(ca.Name + "-Key")
	if err != nil {
		return nil, err
	}

	revokedCerts, err := s.repo.GetRevokedCertificates(ctx, caID)
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

	// Create CRL using the CA certificate as issuer
	crlTemplate := x509.RevocationList{
		Issuer:                    caCert.Subject,
		SignatureAlgorithm:        x509.SHA256WithRSA,
		RevokedCertificateEntries: revokedList,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(7 * 24 * time.Hour),
		Number:                    big.NewInt(1),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, signer)
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

// tao mot ca moi can tao moi token va key
func (s *caService) CreateCA(ctx context.Context, name string, caType model.CAType, parentCAID *int) (model.CA, error) {

	// create token for new CA
	// token := model.CryptoToken{
	// 	Name:    name + "-Token",
	// 	Backend: "pkcs11",
	// 	SlotID: func() int {
	// 		slot, _ := strconv.ParseInt(s.cfg.KeyManagement.SoftHSM.Slot, 10, 32)
	// 		return int(slot)
	// 	}(),
	// 	PinRef: "keymanagement/softhsm/pin-subca",
	// }

	//save token metadata
	// tokenID, err := s.repo.SaveToken(ctx, token)
	// if err != nil {
	// 	return model.CA{}, err
	// }

	// Generate key pair for the CA
	keyLabel := name + "-Key"
	keyPair, err := s.keyService.GenerateKeyPair(keyLabel)
	if err != nil {
		return model.CA{}, err
	}

	//save key pair metadata
	// publicKeyPEM := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "RSA Public Key",
	// 	Bytes: x509.MarshalPKCS1PublicKey(keyPair.PublicKey),
	// })

	// key := model.CryptoKey{
	// 	Label:     keyLabel,
	// 	TokenID:   tokenID,
	// 	CaID:      1,
	// 	PublicKey: string(publicKeyPEM),
	// 	Status:    "active",
	// }

	// keyID, err := s.repo.SaveKey(ctx, key)
	// if err != nil {
	//     return model.CA{}, nil
	// }

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return model.CA{}, err
	}

	notBefore := time.Now()

	//certificate template for new CA
	CAcertTemplate := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          keyPair.PublicKey,
		Version:            2,
		SerialNumber:       serialNumber,
		Subject: pkix.Name{
			Country:      []string{"VN"},
			Organization: []string{"Viettel"},
			CommonName:   name, // eg: "viettel-rootCA",
		},
		NotBefore:             notBefore,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId: func() []byte {
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(keyPair.PublicKey)
			if err != nil {
				log.Fatal(err)
			}
			sum := sha1.Sum(pubKeyBytes)
			return sum[:]
		}(),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CRLDistributionPoints: []string{"http://ca.example.com/crl.pem"},
		OCSPServer:            []string{"http://ocsp.example.com"},
	}
	var signedCert []byte

	//if caType is root CA, create self-signed certificate
	// else create intermediate CA signed by parent CA
	if caType == model.RootCAType {
		//validity 8 years
		notAfter := notBefore.Add(time.Duration(s.cfg.CA.ValidityDays) * 24 * time.Hour)
		CAcertTemplate.NotAfter = notAfter

		signer, err := s.keyService.GetSigner(keyLabel)
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to get signer for CA key: %v", err)
		}
		// Create self-signed certificate for root CA
		signedCert, err = x509.CreateCertificate(rand.Reader, &CAcertTemplate, &CAcertTemplate, keyPair.PublicKey, signer)
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to create self-signed certificate: %v", err)
		}
	} else { // Create intermediate CA signed by parent CA
		parentCA, err := s.repo.FindCAByID(ctx, *parentCAID)
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to get parent CA: %v", err)
		}

		signer, err := s.keyService.GetSigner(parentCA.Name + "-Key")
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to get signer for parent CA key: %w", err)
		}

		block, _ := pem.Decode([]byte(parentCA.CertPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			return model.CA{}, fmt.Errorf("failed to decode PEM block containing certificate")
		}
		parentCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to get parent CA key: %v", err)
		}

		// set validity to half of parent CA's lifetime
		caLifetime := parentCert.NotAfter.Sub(parentCert.NotBefore)
		halfLifetime := caLifetime / 2
		CAcertTemplate.NotAfter = notBefore.Add(halfLifetime)

		CAcertTemplate.MaxPathLen = 0

		signedCert, err = x509.CreateCertificate(rand.Reader, &CAcertTemplate, parentCert, keyPair.PublicKey, signer)
		if err != nil {
			return model.CA{}, fmt.Errorf("failed to create intermediate CA certificate: %v", err)
		}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert})
	// Save CA
	ca := model.CA{
		Name:       name,
		Type:       caType,
		ParentCAID: parentCAID,
		CertPEM:    string(certPEM),
		Status:     "active",
		CreateAt:   notBefore,
	}

	caID, err := s.repo.SaveCA(ctx, ca)
	if err != nil {
		return model.CA{}, fmt.Errorf("failed to save CA: %w", err)
	}
	// fmt.Println(ca.CertPEM)

	// Update key with ca_id
	// key.CAID = &caID
	// _, err = s.repo.SaveKey(ctx, key)
	// if err != nil {
	//     return model.CA{}, err
	// }
	ca.ID = caID
	return ca, nil
}

func (s *caService) HandleOCSPRequest(ctx context.Context, requestData []byte, caID int) ([]byte, error) {
	// Parse OCSP request
	ocspReq, err := ocsp.ParseRequest(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %w", err)
	}

	// Get CA certificate and key
	ca, err := s.repo.FindCAByID(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("failed to find CA: %w", err)
	}

	// Parse CA certificate
	block, _ := pem.Decode([]byte(ca.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate PEM block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Get signer for OCSP response
	signer, err := s.keyService.GetSigner(ca.Name + "-Key")
	if err != nil {
		return nil, fmt.Errorf("failed to get CA signer: %w", err)
	}

	// Convert serial number to string for database lookup
	serialNumber := ocspReq.SerialNumber.String()

	// Check if certificate exists
	cert, err := s.repo.FindBySerialNumber(ctx, serialNumber)
	if err != nil {
		// Certificate not found - return unknown status
		response := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}
		return ocsp.CreateResponse(caCert, caCert, response, signer)
	}

	// Check if certificate is revoked
	revokedCert, isRevoked, err := s.repo.IsRevoked(ctx, serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to check revocation status: %w", err)
	}

	var response ocsp.Response
	if isRevoked {
		// Certificate is revoked
		reasonCode := getOCSPReasonCode(revokedCert.Reason)
		response = ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     ocspReq.SerialNumber,
			ThisUpdate:       time.Now(),
			NextUpdate:       time.Now().Add(24 * time.Hour),
			RevokedAt:        revokedCert.RevocationDate,
			RevocationReason: reasonCode,
		}
	} else {
		// Check if certificate is expired
		if time.Now().After(cert.NotAfter) {
			response = ocsp.Response{
				Status:       ocsp.Unknown, // Expired certificates can be reported as unknown
				SerialNumber: ocspReq.SerialNumber,
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().Add(24 * time.Hour),
			}
		} else {
			// Certificate is good
			response = ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: ocspReq.SerialNumber,
				ThisUpdate:   time.Now(),
				NextUpdate:   time.Now().Add(24 * time.Hour),
			}
		}
	}

	// Create and sign OCSP response
	return ocsp.CreateResponse(caCert, caCert, response, signer)
}

// Helper function to convert RevocationReason to OCSP reason code
func getOCSPReasonCode(reason model.RevocationReason) int {
	reasonMap := map[model.RevocationReason]int{
		model.ReasonUnspecified:          ocsp.Unspecified,
		model.ReasonKeyCompromise:        ocsp.KeyCompromise,
		model.ReasonCACompromise:         ocsp.CACompromise,
		model.ReasonAffiliationChanged:   ocsp.AffiliationChanged,
		model.ReasonSuperseded:           ocsp.Superseded,
		model.ReasonCessationOfOperation: ocsp.CessationOfOperation,
		model.ReasonCertificateHold:      ocsp.CertificateHold,
	}
	
	if code, exists := reasonMap[reason]; exists {
		return code
	}
	return ocsp.Unspecified
}
