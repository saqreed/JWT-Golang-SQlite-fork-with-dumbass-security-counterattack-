package gin

import (
	"JWT/internal/delivery/gin/handlers"
	"JWT/internal/delivery/gin/middleware"
	"JWT/internal/repository"
	"JWT/internal/usecase"
	"JWT/pkg/security"
	"database/sql"
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

func SetupRouters(db *sql.DB) *gin.Engine {
	router := gin.Default()

	rep := repository.NewUserRepository(db)
	useCase := *usecase.NewUserUseCase(rep)
	handler := handlers.UserHandler{UseCase: useCase}

	// Initialize advanced brute force protection
	// 5 attempts within 5 minutes, 1GB base garbage file, 24h permanent block
	protection := security.NewAdvancedProtection(
		5,                // max attempts
		5*time.Minute,    // block time
		24*time.Hour,     // permanent block time
		1*1024*1024*1024, // 1GB base garbage size
	)

	// Start notification handler
	go func() {
		for notification := range protection.GetNotifications() {
			log.Printf("Security Alert: %s", notification)
			// Здесь можно добавить отправку уведомлений в Telegram/Slack/etc
		}
	}()

	api := router.Group("/v1")
	{
		api.POST("/reg", handler.Register)
		api.POST("/login", middleware.BruteForceProtection(protection), handler.Login)

		api.GET("/users", handler.GetAll)
		api.GET("/user/email/:email", handler.GetUserByEmail)
		api.GET("/user/:id", handler.GetUserByID)

		api.DELETE("/user/:id", handler.DeleteUser)
	}

	auth := router.Group("/profile")
	auth.Use(handlers.Authorization())
	{
	}

	return router
}
