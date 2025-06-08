package model

import "time"

type CertificateStatus struct {
	SerialNumber   string          `json:"serial_number"`
	Status         CertStatusValue `json:"status"`
	Revoked        bool            `json:"revoked"`
	RevocationDate time.Time       `json:"revocation_date,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	IsCA           bool            `json:"is_ca"`
}
