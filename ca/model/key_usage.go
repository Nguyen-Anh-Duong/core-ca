package model

type KeyUsageData struct {
	KeyID int      `json:"key_id"`
	Usage KeyUsage `json:"usage"` // "sign" or "encrypt"
}
