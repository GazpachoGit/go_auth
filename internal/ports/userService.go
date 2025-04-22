package ports

import (
	"go_auth/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

type UserServicePort interface {
	RegisterUser(models.UserRegisterRequest) (int, error)
	LoginUser(models.UserLoginRequest) (string, error)
	LogoutUser(tokenString string) error
	ValidateUsersToken(claims jwt.MapClaims) error
	RefreshToken(userID int, email string) (string, error)
	GetClaimsFromToken(tokenString string) (jwt.MapClaims, error)
}
