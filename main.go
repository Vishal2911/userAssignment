package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/vishal2911/userAssignment/handlers"
	"github.com/vishal2911/userAssignment/middleware"
	"github.com/vishal2911/userAssignment/utils"
)

func main() {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	utils.SetRedisClient(redisClient)

	r := gin.Default()

	// Public routes
	r.POST("/signup", handlers.SignUp(redisClient))
	r.POST("/signin", handlers.SignIn(redisClient))
	r.POST("/refresh", handlers.RefreshToken(redisClient))

	// Protected routes
	authorized := r.Group("/")
	authorized.Use(middleware.AuthMiddleware(redisClient))
	{
		authorized.POST("/logout", handlers.Logout(redisClient))
		authorized.GET("/protected", handlers.ProtectedHandler)
	}

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
