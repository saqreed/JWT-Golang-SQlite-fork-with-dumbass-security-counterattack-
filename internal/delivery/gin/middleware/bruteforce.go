package middleware

import (
	"JWT/pkg/security"
	"net/http"

	"github.com/gin-gonic/gin"
)

func BruteForceProtection(protection *security.AdvancedProtection) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		// Check if IP is permanently blocked
		if protection.IsIPBlocked(ip) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "IP address is blocked due to suspicious activity",
			})
			c.Abort()
			return
		}

		// Get username from request
		var loginData struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			c.Abort()
			return
		}

		if protection.RecordFailedAttempt(ip, loginData.Email) {
			// Generate and send garbage data
			garbage := protection.GenerateGarbage(ip)

			c.Header("Content-Type", "application/octet-stream")
			c.Header("Content-Disposition", "attachment; filename=garbage.bin")
			c.Data(http.StatusOK, "application/octet-stream", garbage)
			c.Abort()
			return
		}

		c.Next()

		// Reset attempts on successful login
		if c.Writer.Status() == http.StatusOK {
			protection.ResetAttempts(ip)
		}
	}
}
