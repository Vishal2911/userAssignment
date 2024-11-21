package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/vishal2911/userAssignment/models"
	"github.com/vishal2911/userAssignment/utils"
)

var users []models.User

func SignUp(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if user already exists
		for _, u := range users {
			if u.Email == user.Email {
				c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
				return
			}
		}

		// Hash password
		if err := user.HashPassword(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Save user (in a real application, you'd save to a database)
		users = append(users, user)

		c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
	}
}

func SignIn(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Find user
		var user models.User
		for _, u := range users {
			if u.Email == credentials.Email {
				user = u
				break
			}
		}

		if user.ID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Check password
		if err := user.CheckPassword(credentials.Password); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Generate tokens
		accessToken, err := utils.GenerateAccessToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		refreshToken, err := utils.GenerateRefreshToken(user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}
}

func RefreshToken(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate refresh token
		claims, err := utils.ValidateToken(request.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		// Generate new access token
		userID := uint(claims["user_id"].(float64))
		accessToken, err := utils.GenerateAccessToken(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	}
}

func Logout(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization header"})
			return
		}

		// Remove "Bearer " prefix
		token = token[7:]

		// Add token to blacklist (in a real application, you'd use Redis or a database)
		utils.BlacklistToken(token, time.Hour*24) // Blacklist for 24 hours

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

func ProtectedHandler(c *gin.Context) {
	userID := c.GetUint("user_id")
	c.JSON(http.StatusOK, gin.H{"message": "This is a protected route", "user_id": userID})
}
