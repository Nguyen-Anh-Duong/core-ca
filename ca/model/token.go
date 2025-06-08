// crypto token
package model

type CryptoToken struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Backend string `json:"backend"` // e.g., "pkcs11"
	SlotID  int    `json:"slot_id"`
	PinRef  string `json:"pin_ref"` // e.g., "env:PIN1"
}
