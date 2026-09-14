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
			Port: "8080",
			Mode: "debug",
		},
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "freedomcry",
			Password: "freedomcry_secret",
			DBName:   "freedomcry_db",
			SSLMode:  "disable",
		},
		Redis: RedisConfig{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		},
		JWT: JWTConfig{
			Secret: "freedom-cry-super-secure-jwt-secret-change-in-prod",
			Expiry: 72 * time.Hour,
		},
		App: AppConfig{
			BaseURL:    "http://localhost:8080",
			NodeSecret: "fc-node-secret-token-key-2026",
			DefaultDNS: "1.1.1.1, 8.8.8.8",
		},
	}

	// 1. Read YAML config if exists
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = yaml.Unmarshal(data, cfg)
		}
	}

	// 2. Environment variables OVERRIDE YAML
	if val := os.Getenv("PORT"); val != "" {
		cfg.Server.Port = val
	}
	if val := os.Getenv("GIN_MODE"); val != "" {
		cfg.Server.Mode = val
	}
	if val := os.Getenv("DB_HOST"); val != "" {
		cfg.Database.Host = val
	}
	if val := os.Getenv("DB_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Database.Port = p
		}
	}
	if val := os.Getenv("DB_USER"); val != "" {
		cfg.Database.User = val
	}
	if val := os.Getenv("DB_PASSWORD"); val != "" {
		cfg.Database.Password = val
	}
	if val := os.Getenv("DB_NAME"); val != "" {
		cfg.Database.DBName = val
	}
	if val := os.Getenv("DB_SSLMODE"); val != "" {
		cfg.Database.SSLMode = val
	}
	if val := os.Getenv("REDIS_ADDR"); val != "" {
		cfg.Redis.Addr = val
	}
	if val := os.Getenv("REDIS_PASSWORD"); val != "" {
		cfg.Redis.Password = val
	}
	if val := os.Getenv("REDIS_DB"); val != "" {
		if d, err := strconv.Atoi(val); err == nil {
			cfg.Redis.DB = d
		}
	}
	if val := os.Getenv("JWT_SECRET"); val != "" {
		cfg.JWT.Secret = val
	}
	if val := os.Getenv("BASE_URL"); val != "" {
		cfg.App.BaseURL = val
	}
	if val := os.Getenv("NODE_SECRET"); val != "" {
		cfg.App.NodeSecret = val
	}
	if val := os.Getenv("DEFAULT_DNS"); val != "" {
		cfg.App.DefaultDNS = val
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
