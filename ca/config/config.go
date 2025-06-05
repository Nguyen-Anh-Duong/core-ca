package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Issuer       string
	ValidityDays int
	Database     DatabaseConfig
}

type DatabaseConfig struct {
	DSN string // Data Source Name for PostgreSQL
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile("config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	return &Config{
		Issuer:       viper.GetString("ca.issuer"),
		ValidityDays: viper.GetInt("ca.validity_days"),
		Database: DatabaseConfig{
			DSN: viper.GetString("ca.database.dsn"),
		},
	}, nil
}
