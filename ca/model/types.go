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

type CertStatusValue string

const (
	StatusValid   CertStatusValue = "valid"
	StatusRevoked CertStatusValue = "revoked"
	StatusExpired CertStatusValue = "expired"
	StatusUnknown CertStatusValue = "unknown"
)

type CAType string

const (
	RootCAType        CAType = "root"
	SubordinateCAType CAType = "sub"
)
