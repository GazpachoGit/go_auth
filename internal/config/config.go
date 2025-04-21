package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server struct {
		Port         string
		Host         string
		ReadTimeout  time.Duration
		WriteTimeout time.Duration
	}

	Database struct {
		Host     string
		Port     string
		User     string
		Password string
		DBName   string
	}

	JWT struct {
		Secret        string
		TokenExpiry   time.Duration
		RefreshExpiry time.Duration
	}

	Environment string
}

func Load() (*Config, error) {
	//init env vars from .env file from the root
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file")
	}

	var cfg *Config = &Config{}

	cfg.Server.Port = getEnv("SERVER_PORT", "8081")
	cfg.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")
	cfg.Server.ReadTimeout = time.Second * 15
	cfg.Server.WriteTimeout = time.Second * 15

	cfg.Database.Host = getEnv("DB_HOST", "localhost")
	cfg.Database.Port = getEnv("DB_PORT", "6432")
	cfg.Database.User = getEnv("DB_USER", "postgres")
	cfg.Database.Password = getEnv("DB_PASSWORD", "postgres")
	cfg.Database.DBName = getEnv("DB_NAME", "mydb")

	cfg.JWT.Secret = getEnv("JWT_SECRET", "my_secret")
	cfg.JWT.TokenExpiry = time.Hour * 24    // 24 hours
	cfg.JWT.RefreshExpiry = time.Hour * 168 // 7 days

	cfg.Environment = getEnv("ENV", "development")

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	fmt.Printf("Env var value not found '%s' \n", key)
	return defaultValue
}

func (c *Config) GetDBConnStr() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.DBName,
	)
	//return "postgres://postgres:postgres@localhost:6432/mydb?sslmode=disable"
}
