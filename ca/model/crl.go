package model

import (
	"crypto/x509/pkix"
	"time"
)

type TBSCertList struct {
	Version             int `asn1:"optional,default:1"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              pkix.RDNSequence
	ThisUpdate          time.Time
	NextUpdate          time.Time                 `asn1:"optional"`
	RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
}
