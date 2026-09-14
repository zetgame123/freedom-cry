package config

import (
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	JWT      JWTConfig      `yaml:"jwt"`
	App      AppConfig      `yaml:"app"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Mode string `yaml:"mode"` // debug or release
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type JWTConfig struct {
	Secret string        `yaml:"secret"`
	Expiry time.Duration `yaml:"expiry"`
}

type AppConfig struct {
	BaseURL     string `yaml:"base_url"`      // e.g. http://localhost:8080 or https://vpn.freedomcry.net
	NodeSecret  string `yaml:"node_secret"`   // Secret key used by node agents for sync
	DefaultDNS  string `yaml:"default_dns"`   // e.g. 1.1.1.1, 8.8.8.8
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnv("PORT", "8080"),
			Mode: getEnv("GIN_MODE", "debug"),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "freedomcry"),
			Password: getEnv("DB_PASSWORD", "freedomcry_secret"),
			DBName:   getEnv("DB_NAME", "freedomcry_db"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "freedom-cry-super-secure-jwt-secret-change-in-prod"),
			Expiry: 72 * time.Hour,
		},
		App: AppConfig{
			BaseURL:    getEnv("BASE_URL", "http://localhost:8080"),
			NodeSecret: getEnv("NODE_SECRET", "fc-node-secret-token-key-2026"),
			DefaultDNS: getEnv("DEFAULT_DNS", "1.1.1.1, 8.8.8.8"),
		},
	}

	// Try reading YAML config if exists
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = yaml.Unmarshal(data, cfg)
		}
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
