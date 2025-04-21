package handlers

import (
	"errors"
	"go_auth/internal/models"
	"go_auth/internal/ports"
	"go_auth/internal/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	service ports.UserServicePort
}

func NewAuthHandler(service ports.UserServicePort) *AuthHandler {
	return &AuthHandler{
		service: service,
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

	id, err := h.service.RegisterUser(user)
	if err != nil {
		if errors.Is(err, utils.ERROR_EMAIL_REGISTERED) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"errors": err.Error(),
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"errors": err.Error(),
		})
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

	tokenString, err := h.service.LoginUser(login)
	if err != nil {
		if errors.Is(err, utils.ERROR_INVALID_CREDENTIALS) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"errors": err.Error(),
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"errors": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"token_type": "Bearer",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	//check context value. comes from the middleware
	userID, exists_id := c.Get("user_id")
	email, exists_email := c.Get("email")
	if !exists_id || !exists_email {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	tokenString, err := h.service.RefreshToken(userID.(int), email.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
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

func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	//TODO: code duplication. to untils
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusOK, gin.H{"message": "Already logged out (no token provided)"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
		return
	}

	tokenString := parts[1]

	err := h.service.LogoutUser(tokenString)
	if err != nil {

		if errors.Is(err, utils.ERROR_FAILED_TO_LOGOUT) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if errors.Is(err, utils.ERROR_TOKEN_EXPIRED) || errors.Is(err, utils.ERROR_NO_JTI) {
			c.JSON(http.StatusOK, gin.H{"message": err.Error()})
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
