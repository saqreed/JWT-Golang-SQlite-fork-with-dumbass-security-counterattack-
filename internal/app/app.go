package app

import (
	"JWT/internal/delivery/gin"
	"JWT/pkg/database"
)

func Run() {
	db := database.SQLite()
	eng := gin.SetupRouters(db)
	eng.Run(":7328")
}
