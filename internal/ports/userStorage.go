package ports

import (
	"go_auth/internal/models"
	"time"
)

type UserStoragePort interface {
	CheckUserExists(email string) (bool, error)
	CreateUser(email, hashedPassword string) (int, error)
	GetUser(email string) (*models.User, error)
	CheckJTWBlocked(jti string) (bool, error)
	AddJWTToBlacklist(jti string, ttl time.Duration) error
	Close()
}
