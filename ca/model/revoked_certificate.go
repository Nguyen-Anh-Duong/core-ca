package model

import "time"

type RevokedCertificate struct {
	SerialNumber   string           `json:"serial_number"`
	RevocationDate time.Time        `json:"revocation_date"`
	Reason         RevocationReason `json:"reason,omitempty"`
	IsCA           bool             `json:"is_ca"`
}
