package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	SoftHSMModule string // Path to libsofthsm2.so
	SoftHSMSlot   string // Slot ID
	SoftHSMPin    string // User PIN
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile("config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	return &Config{
		SoftHSMModule: viper.GetString("keymanagement.softhsm.module"),
		SoftHSMSlot:   viper.GetString("keymanagement.softhsm.slot"),
		SoftHSMPin:    viper.GetString("keymanagement.softhsm.pin"),
	}, nil
}
