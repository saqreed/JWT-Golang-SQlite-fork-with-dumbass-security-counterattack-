package gin

import (
	"JWT/internal/delivery/gin/handlers"
	"JWT/internal/repository"
	"JWT/internal/usecase"
	"database/sql"
	"github.com/gin-gonic/gin"
)

func SetupRouters(db *sql.DB) *gin.Engine {
	router := gin.Default()

	rep := repository.NewUserRepository(db)
	useCase := *usecase.NewUserUseCase(rep)
	handler := handlers.UserHandler{UseCase: useCase}

	api := router.Group("/v1")
	{
		api.POST("/reg", handler.Register)
		api.POST("/login", handler.Login)

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
