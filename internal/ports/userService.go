package ports

import "go_auth/internal/models"

type UserServicePort interface {
	RegisterUser(models.UserRegisterRequest) (int, error)
	LoginUser(models.UserLoginRequest) (string, error)
	LogoutUser(tokenString string) error
	ValidateUsersToken(tokenString string) error
	RefreshToken(userID int, email string) (string, error)
}
