package repository

import (
	"core-ca/keymanagement/model"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/miekg/pkcs11"
)

// KeyPairRepository interface for key storage.
type KeyPairRepository interface {
	GenerateKeyPair(id string) (model.KeyPairData, error)
	FindByID(id string) (model.KeyPairData, error)
	GetSigner(keyLabel string) (crypto.Signer, error)
	Finalize()
}

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

type softHSMKeyPairRepository struct {
	ctx     *pkcs11.Ctx
	slot    uint
	pin     string
	session pkcs11.SessionHandle
}

type softHSMSigner struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privHandle pkcs11.ObjectHandle
	publicKey  *rsa.PublicKey
}

// Public returns the public key associated with the signer.
func (s *softHSMSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the given digest using the private key.
func (s *softHSMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Always use CKM_RSA_PKCS but prepare the data correctly.
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}

	// This is a pre-computed SHA256 hash from x509.CreateCertificate.
	// We need to add the DigestInfo structure for PKCS#1 v1.5 padding.
	// SHA256 DigestInfo: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 + hash.
	if len(digest) == 32 {
		// Prepend DigestInfo for SHA256
		digestInfo := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
		fullDigest := append(digestInfo, digest...)
		digest = fullDigest
	}
	// For raw data or other cases, use as-is.

	err := s.ctx.SignInit(s.session, mechanism, s.privHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to init sign: %v", err)
	}

	signature, err := s.ctx.Sign(s.session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	return signature, nil
}

func (s *softHSMSigner) SignRaw(data []byte) ([]byte, error) {
	// Always use CKM_RSA_PKCS for direct signing
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	err := s.ctx.SignInit(s.session, mechanism, s.privHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to init sign: %v", err)
	}
	signature, err := s.ctx.Sign(s.session, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

func NewSoftHsmKeyPairRepository(modulePath, slot, pin string) (KeyPairRepository, error) {
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, pkcs11.Error(pkcs11.CKR_GENERAL_ERROR)
	}

	// Parse slot string to uint.
	slotID, err := strconv.ParseUint(slot, 10, 32)
	if err != nil {
		return nil, err
	}

	err = ctx.Initialize()
	if err != nil {
		return nil, err
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	var targetSlot uint
	found := false
	for _, s := range slots {
		if uint64(s) == slotID {
			targetSlot = s
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("slot not found")
	}

	session, err := ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, err
	}

	return &softHSMKeyPairRepository{
		ctx:     ctx,
		slot:    uint(slotID),
		pin:     pin,
		session: session,
	}, nil
}

func (r *softHSMKeyPairRepository) GenerateKeyPair(id string) (model.KeyPairData, error) {
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}

	pubHandle, _, err := r.ctx.GenerateKeyPair(r.session, 
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, 
		pubTemplate, privTemplate)
	if err != nil {
		return model.KeyPairData{}, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// Get public key components.
	pubKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	attrs, err := r.ctx.GetAttributeValue(r.session, pubHandle, pubKeyAttr)
	if err != nil {
		return model.KeyPairData{}, fmt.Errorf("failed to get public key attributes: %v", err)
	}

	// Create RSA public key from modulus and exponent.
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(attrs[0].Value),
		E: int(new(big.Int).SetBytes(attrs[1].Value).Int64()),
	}

	// Encode public key in PKCS1 format.
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	})

	return model.KeyPairData{
		ID:        id,
		PublicKey: string(pubKeyPEM),
		KeyLabel:  id,
	}, nil
}

func (r *softHSMKeyPairRepository) FindByID(id string) (model.KeyPairData, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}
	err := r.ctx.FindObjectsInit(r.session, template)
	if err != nil {
		return model.KeyPairData{}, err
	}
	objs, _, err := r.ctx.FindObjects(r.session, 1)
	if err != nil || len(objs) == 0 {
		return model.KeyPairData{}, errors.New("key not found")
	}
	err = r.ctx.FindObjectsFinal(r.session)
	if err != nil {
		return model.KeyPairData{}, err
	}

	// Get public key attributes.
	pubKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attrs, err := r.ctx.GetAttributeValue(r.session, objs[0], pubKeyAttr)
	if err != nil {
		return model.KeyPairData{}, err
	}

	// Create RSA public key from modulus and exponent.
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(attrs[0].Value),
		E: int(new(big.Int).SetBytes(attrs[1].Value).Int64()),
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	})

	return model.KeyPairData{
		ID:        id,
		PublicKey: string(pubKeyPEM),
		KeyLabel:  id,
	}, nil
}

func (r *softHSMKeyPairRepository) GetSigner(keyLabel string) (crypto.Signer, error) {
	// Find private key.
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}
	err := r.ctx.FindObjectsInit(r.session, privTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to init private key search: %v", err)
	}
	privObjs, _, err := r.ctx.FindObjects(r.session, 1)
	if err != nil || len(privObjs) == 0 {
		r.ctx.FindObjectsFinal(r.session)
		return nil, errors.New("private key not found")
	}
	err = r.ctx.FindObjectsFinal(r.session)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize private key search: %v", err)
	}
	privHandle := privObjs[0]

	// Get private key ID.
	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	attrs, err := r.ctx.GetAttributeValue(r.session, privHandle, privAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key ID: %v", err)
	}
	keyID := attrs[0].Value

	// Find corresponding public key using the same ID.
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	err = r.ctx.FindObjectsInit(r.session, pubTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to init public key search: %v", err)
	}
	pubObjs, _, err := r.ctx.FindObjects(r.session, 1)
	if err != nil || len(pubObjs) == 0 {
		r.ctx.FindObjectsFinal(r.session)
		return nil, errors.New("matching public key not found")
	}
	err = r.ctx.FindObjectsFinal(r.session)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize public key search: %v", err)
	}

	// Get public key attributes.
	pubKeyAttr := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	attrs, err = r.ctx.GetAttributeValue(r.session, pubObjs[0], pubKeyAttr)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %v", err)
	}

	// Create RSA public key.
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(attrs[0].Value),
		E: int(new(big.Int).SetBytes(attrs[1].Value).Int64()),
	}

	return &softHSMSigner{
		ctx:        r.ctx,
		session:    r.session,
		privHandle: privHandle,
		publicKey:  publicKey,
	}, nil
}

func (r *softHSMKeyPairRepository) Finalize() {
	r.ctx.Logout(r.session)
	r.ctx.CloseSession(r.session)
	r.ctx.Finalize()
	r.ctx.Destroy()
}
