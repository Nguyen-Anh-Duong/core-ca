package model

type RevocationReason string

const (
	ReasonUnspecified          RevocationReason = "unspecified"
	ReasonKeyCompromise        RevocationReason = "keyCompromise"
	ReasonCACompromise         RevocationReason = "caCompromise"
	ReasonAffiliationChanged   RevocationReason = "affiliationChanged"
	ReasonSuperseded           RevocationReason = "superseded"
	ReasonCessationOfOperation RevocationReason = "cessationOfOperation"
	ReasonCertificateHold      RevocationReason = "certificateHold"
)

type CertificateStatus string

const (
	StatusValid   CertificateStatus = "valid"
	StatusRevoked CertificateStatus = "revoked"
	StatusExpired CertificateStatus = "expired"
	StatusUnknown CertificateStatus = "unknown"
)

type CAType string

const (
	RootCAType        CAType = "root"
	SubordinateCAType CAType = "sub"
)

type CAStatus string

const (
	ActiveCAStatuc  CAStatus = "active"
	RevokedCaStatus CAStatus = "revoked"
	ExpiredCaStatus CAStatus = "expired"
	UnknownCaStatus CAStatus = "unknown"
)

type CryptoKeyStatus string

const (
	ActiveCryptoKeyStatus  CryptoKeyStatus = "active"
	RevokedCryptoKeyStatus CryptoKeyStatus = "revoked"
	ExpiredCryptoKeyStatus CryptoKeyStatus = "expired"
	UnknownCryptoKeyStatus CryptoKeyStatus = "unknown"
)

type KeyUsage string

const (
	KeyUsageCertSign KeyUsage = "certSign"
	KeyUsageCRLSign  KeyUsage = "crlSign"
	KeyUsageOCSPSign KeyUsage = "ocspSign"
	KeyUsageEncrypt  KeyUsage = "encrypt"
	KeyUsageSign     KeyUsage = "sign"
)
