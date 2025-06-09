package config

import (
	"github.com/spf13/viper"
)

// AppConfig là config chung cho toàn bộ ứng dụng
type AppConfig struct {
	CA            CAConfig            `yaml:"ca"`
	KeyManagement KeyManagementConfig `yaml:"keymanagement"`
}

// CAConfig chứa config cho CA service
type CAConfig struct {
	Issuer       string         `yaml:"issuer"`
	ValidityDays int            `yaml:"validity_days"`
	Database     DatabaseConfig `yaml:"database"`
}

// KeyManagementConfig chứa config cho Key Management service
type KeyManagementConfig struct {
	SoftHSM SoftHSMConfig `yaml:"softhsm"`
}

// SoftHSMConfig chứa config cho SoftHSM
type SoftHSMConfig struct {
	Module string `yaml:"module"`
	Slot   string `yaml:"slot"`
	Pin    string `yaml:"pin"`
}

// DatabaseConfig chứa config cho database
type DatabaseConfig struct {
	DSN string `yaml:"dsn"` // Data Source Name for PostgreSQL
}

// LoadConfig load config chung từ file YAML
func LoadConfig() (*AppConfig, error) {
	viper.SetConfigFile("config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	config := &AppConfig{
		CA: CAConfig{
			Issuer:       viper.GetString("ca.issuer"),
			ValidityDays: viper.GetInt("ca.validity_days"),
			Database: DatabaseConfig{
				DSN: viper.GetString("ca.database.dsn"),
			},
		},
		KeyManagement: KeyManagementConfig{
			SoftHSM: SoftHSMConfig{
				Module: viper.GetString("keymanagement.softhsm.module"),
				Slot:   viper.GetString("keymanagement.softhsm.slot"),
				Pin:    viper.GetString("keymanagement.softhsm.pin"),
			},
		},
	}

	return config, nil
}

// GetCAConfig trả về CA config từ app config
func (c *AppConfig) GetCAConfig() *CAConfig {
	return &c.CA
}

// GetKeyManagementConfig trả về KeyManagement config từ app config
func (c *AppConfig) GetKeyManagementConfig() *KeyManagementConfig {
	return &c.KeyManagement
}
