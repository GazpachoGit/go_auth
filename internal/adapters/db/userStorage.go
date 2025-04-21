package db

import (
	"context"
	"errors"
	"fmt"
	"go_auth/internal/models"
	"go_auth/internal/ports"
	"log"
	"time"

	"github.com/go-redis/redis"
	"github.com/jackc/pgx/v5"
)

type UserStorage struct {
	db    *pgx.Conn
	cache *redis.Client
}

func NewUserStorage(connStr string, cacheHost, cachePort string) (ports.UserStoragePort, error) {
	connConfig, err := pgx.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
		return nil, err
	}

	db, err := pgx.Connect(context.Background(), connConfig.ConnString())
	if err != nil {
		log.Println("Failed to connect to DB: %v", err)
		return nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cacheHost, cachePort),
		Password: "predis",
		DB:       0,
	})
	_, err = rdb.Ping().Result()
	if err != nil {
		log.Println("Redis connection failed: %v", err)
	}

	return &UserStorage{
		db:    db,
		cache: rdb,
	}, nil
}

func (s *UserStorage) CheckUserExists(email string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM USERS WHERE email = $1)", email).Scan(&exists)

	if err != nil {
		log.Println(err)
		return false, err
	}

	return exists, nil
}

func (s *UserStorage) CreateUser(email, hashedPassword string) (int, error) {
	tx, err := s.db.Begin(context.Background())
	if err != nil {
		log.Println(err)
		return 0, errors.New("Transaction start failed")
	}

	var id int
	err = tx.QueryRow(context.Background(), `
	INSERT INTO users (email, password_hash) VALUES ($1, $2)
	RETURNING id`,
		email,
		hashedPassword,
	).Scan(&id)

	if err != nil {
		tx.Rollback(context.Background())
		log.Println(err)
		return 0, errors.New("User creation failed")
	}

	if err = tx.Commit(context.Background()); err != nil {
		log.Println(err)
		return 0, errors.New("Transaction commit failed")
	}

	return id, nil
}

func (s *UserStorage) GetUser(email string) (*models.User, error) {
	var user models.User

	err := s.db.QueryRow(context.Background(), `SELECT id, email, password_hash FROM users
	WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash)

	// if errors.Is(err, sql.ErrNoRows) {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	// 	return
	// }

	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserStorage) AddJWTToBlacklist(jti string, ttl time.Duration) error {
	err := s.cache.Set(jti, "revoked", ttl).Err()
	if err != nil {
		log.Printf("Failed to add token to blacklist: %v", err)
		return err
	}
	return nil
}

func (s *UserStorage) CheckJTWBlocked(jti string) (bool, error) {
	_, err := s.cache.Get(jti).Result()
	if err == nil {
		return true, nil
	} else if !errors.Is(err, redis.Nil) {
		log.Printf("Error checking blacklist: %v", err)
		return false, errors.New("Internal error")
	}
	return false, nil
}
