package user

import (
	"errors"
	"go_auth/internal/models"
	"go_auth/internal/ports"
	"go_auth/internal/utils"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserService struct {
	storage         ports.UserStoragePort
	jwtSecret       []byte
	tokenExpiration time.Duration
}

func NewUserService(storage ports.UserStoragePort, jwtSecret []byte, tokenExpiration time.Duration) ports.UserServicePort {
	return &UserService{
		storage:         storage,
		jwtSecret:       jwtSecret,
		tokenExpiration: tokenExpiration,
	}
}

func (s *UserService) RegisterUser(input models.UserRegisterRequest) (int, error) {
	if err := input.Validate(); err != nil {
		return 0, err
	}

	if err := utils.ValidatePassword(input.Password); err != nil {
		return 0, err
	}

	exists, err := s.storage.CheckUserExists(input.Email)
	if err != nil {
		return 0, errors.New("Database error")
	}

	if exists {
		return 0, errors.New("Email already registered")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		log.Println(err)
		return 0, errors.New("Password processing failed")
	}

	id, err := s.storage.CreateUser(input.Email, hashedPassword)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *UserService) LoginUser(input models.UserLoginRequest) (string, error) {
	user, err := s.storage.GetUser(input.Email)
	if err != nil {
		return "", err
	}

	if !utils.CheckPasswordHash(input.Password, user.PasswordHash) {
		return "", errors.New("Invalid credentials")
	}

	return s.createToken(user.ID, user.Email)
}

func (s *UserService) LogoutUser(tokenString string) error {

	claims, err := s.GetClaimsFromToken(tokenString)
	if err != nil {
		return err
	}
	//check token expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("Invalid token claims")
	}

	jti, ok := claims["id"].(string)
	if !ok {
		return errors.New("Invalid token claims")
	}

	if jti == "" {
		//TODO: custom error
		return errors.New("Logged out (no JTI)")
	}

	expiresAt := time.Unix(int64(exp), 0)
	now := time.Now()
	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		//TODO: custom error
		return errors.New("Logged out (token already expired)")
	}

	err = s.storage.AddJWTToBlacklist(jti, ttl)
	if err != nil {
		return errors.New("Failed to log out")
	}

	return nil
}

func (s *UserService) ValidateUsersToken(claims jwt.MapClaims) error {
	//check token expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("Invalid token claims")
	}
	if time.Now().Unix() > int64(exp) {
		return errors.New("Token expired")
	}

	jti, ok := claims["id"].(string)
	if !ok {
		return errors.New("Invalid token claims")
	}
	if jti != "" {
		blocked, err := s.storage.CheckJTWBlocked(jti)
		if err != nil {
			return err
		}
		if blocked {
			//TODO: custom error
			return errors.New("Token has been revoked")
		}
	}
	return nil

}

func (s *UserService) RefreshToken(userID int, email string) (string, error) {
	return s.createToken(userID, email)
}

func (s *UserService) createToken(userID int, email string) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Println(err)
		return "", errors.New("Internal error")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"id":      id,
		"user_id": userID,
		"email":   email,
		"iat":     now.Unix(),
		"exp":     now.Add(s.tokenExpiration).Unix(),
	}

	//add sign method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//sign with private key
	tokenString, err := token.SignedString(s.jwtSecret)

	if err != nil {
		log.Print(err)
		return "", errors.New("Token generation failed")
	}

	return tokenString, nil
}

func (s *UserService) GetClaimsFromToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return jwt.MapClaims{}, jwt.ErrSignatureInvalid
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		log.Println(err)
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return jwt.MapClaims{}, errors.New("Invalid token signature")
		} else {
			return jwt.MapClaims{}, errors.New("Invalid or expired token")
		}
	}

	//extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("Invalid token claims")
	}
	return claims, nil
}
