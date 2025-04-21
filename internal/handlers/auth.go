package handlers

import (
	"context"
	"database/sql"
	"errors"
	"go_auth/internal/database"
	"go_auth/internal/models"
	"go_auth/internal/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	db              *database.Database
	jwtSecret       []byte
	tokenExpiration time.Duration
}

func NewAuthHandler(db *database.Database, jwtSecret []byte, tokenExpiration time.Duration) *AuthHandler {
	return &AuthHandler{
		db:              db,
		jwtSecret:       jwtSecret,
		tokenExpiration: tokenExpiration,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var user models.UserRegisterRequest

	//any source (query param, body) (if only body - use ShouldBindBodyJSON)
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid input format",
			"details": err.Error(),
		})
		return
	}

	if err := user.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := utils.ValidatePassword(user.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//TODO: hexagon arch. move this to datasource level
	var exists bool
	err := h.db.DB.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM USERS WHERE email = $1)", user.Email).Scan(&exists)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
	}

	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password processing failed"})
		return
	}

	tx, err := h.db.DB.Begin(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction start failed"})
		return
	}

	var id int
	err = tx.QueryRow(context.Background(), `
	INSERT INTO users (email, password_hash) VALUES ($1, $2)
	RETURNING id`,
		user.Email,
		hashedPassword,
	).Scan(&id)

	if err != nil {
		tx.Rollback(context.Background())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User creation failed"})
		return
	}

	if err = tx.Commit(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Transaction commit failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user_id": id,
	})
}

// TODO: return the refresh token
func (h *AuthHandler) Login(c *gin.Context) {
	var login models.UserLoginRequest

	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login data"})
		return
	}

	var user models.User

	err := h.db.DB.QueryRow(context.Background(), `SELECT id, email, password_hash FROM users
	WHERE email = $1`,
		login.Email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Login process failed"})
		return
	}

	if !utils.CheckPasswordHash(login.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"iat":     now.Unix(),
		"exp":     now.Add(h.tokenExpiration).Unix(),
	}

	//add sign method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//sign with private key
	tokenString, err := token.SignedString(h.jwtSecret)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_in": h.tokenExpiration.Seconds(),
		//access token type
		"token_type": "Bearer",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	//check context value. comes from the middleware
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	//TODO: code duplication. move to a func
	//new token
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"exp":     now.Add(h.tokenExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(h.jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_in": h.tokenExpiration.Seconds(),
		"token_type": "Bearer",
	})
}

func (h *AuthHandler) GetUserProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")
	email, _ := c.Get("email")

	c.JSON(200, gin.H{
		"user_id": userID,
		"email":   email,
	})
}

//TODO: logout logic
//Blacklisting in server side
//add ID (JTI) to the token claims
//redis for storage?
