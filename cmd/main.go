package main

import (
	"context"
	"go_auth/internal/config"
	"go_auth/internal/database"
	"go_auth/internal/handlers"
	"go_auth/internal/middlewares"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	db, err := database.NewDatabase(cfg.GetDBConnStr())
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.DB.Close(context.Background())

	cacheDB := database.NewCacheDB(cfg.Redis.Host, cfg.Redis.Port)

	r := gin.New()
	r.Use(gin.Logger())

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	authHandler := handlers.NewAuthHandler(db, cacheDB, []byte(cfg.JWT.Secret), cfg.JWT.TokenExpiry)

	public := r.Group("/api/v1")
	{
		public.POST("/register", authHandler.Register)
		public.POST("/login", authHandler.Login)
	}

	protected := r.Group("/api/v1")
	protected.Use(middlewares.AuthMiddleware([]byte(cfg.JWT.Secret), cacheDB))
	{
		protected.POST("/refresh-token", authHandler.RefreshToken)
		protected.GET("/profile", authHandler.GetUserProfile)
		protected.POST("/logout", authHandler.LogoutHandler)
	}

	serverAddr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("Server starting on %s", serverAddr)

	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("Server failed to start:", err)
	}
}
