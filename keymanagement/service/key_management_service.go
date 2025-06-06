package service

import (
	"core-ca/keymanagement/model"
	"core-ca/keymanagement/repository"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type KeyManagementService interface {
	GenerateKeyPair(id string) (model.KeyPair, error)
	GetKeyPair(id string) (model.KeyPair, error)
	GetSigner(keyLabel string) (crypto.Signer, error)
}

type keyManagementService struct {
	repo repository.KeyPairRepository
}

func NewKeyManagementService(repo repository.KeyPairRepository) KeyManagementService {
	return &keyManagementService{repo: repo}
}

func (s *keyManagementService) GenerateKeyPair(id string) (model.KeyPair, error) {
	keyPairData, err := s.repo.GenerateKeyPair(id)
	if err != nil {
		return model.KeyPair{}, err
	}
	// Decode the PEM-encoded public key.
	block, _ := pem.Decode([]byte(keyPairData.PublicKey))
	if block == nil {
		return model.KeyPair{}, fmt.Errorf("failed to decode PEM block")
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return model.KeyPair{}, fmt.Errorf("failed to parse public key: %v", err)
	}

	return model.KeyPair{
		ID:        id,
		PublicKey: pubKey,
	}, nil
}

func (s *keyManagementService) GetKeyPair(id string) (model.KeyPair, error) {
	keyPairData, err := s.repo.FindByID(id)
	if err != nil {
		return model.KeyPair{}, err
	}

	// Decode the PEM-encoded public key.
	block, _ := pem.Decode([]byte(keyPairData.PublicKey))
	if block == nil {
		return model.KeyPair{}, fmt.Errorf("failed to decode PEM block")
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return model.KeyPair{}, fmt.Errorf("failed to parse public key: %v", err)
	}

	// PrivateKey is managed by SoftHSM.
	return model.KeyPair{
		ID:         id,
		PublicKey:  pubKey,
		PrivateKey: nil, // PrivateKey is managed by SoftHSM
	}, nil
}

func (s *keyManagementService) GetSigner(keyLabel string) (crypto.Signer, error) {
	signer, err := s.repo.GetSigner(keyLabel)
	if err != nil {
		return nil, err
	}
	return signer, nil
}
