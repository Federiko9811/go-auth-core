package api

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSMiddleware crea un middleware CORS configurabile
// origins: lista di origini autorizzate (es. ["http://localhost:3000"])
func CORSMiddleware(origins []string) gin.HandlerFunc {
	return cors.New(cors.Config{
		// Origini autorizzate
		AllowOrigins: origins,

		// Metodi HTTP permessi
		AllowMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"OPTIONS",
		},

		// Headers permessi nelle richieste
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Content-Length",
			"Accept",
			"Accept-Encoding",
			"Authorization",
			"X-Requested-With",
		},

		// Headers esposti al client (es. per rate limiting)
		ExposeHeaders: []string{
			"Content-Length",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		},

		// Permette l'invio di cookie cross-origin
		// IMPORTANTE per l'autenticazione con HttpOnly cookies
		AllowCredentials: true,

		// Quanto tempo il browser può cacheare la risposta preflight
		MaxAge: 12 * time.Hour,
	})
}
