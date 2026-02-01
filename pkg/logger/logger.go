package logger

import (
	"io"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Log is the global application logger
var Log zerolog.Logger

// Init initializes the global logger
// level: debug, info, warn, error
// format: console (colored) or json
func Init(level string, format string) {
	// Set log level
	var logLevel zerolog.Level
	switch level {
	case "debug":
		logLevel = zerolog.DebugLevel
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "error":
		logLevel = zerolog.ErrorLevel
	default:
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	// Set output format
	var output io.Writer
	if format == "console" {
		// Colored output for development
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
	} else {
		// JSON for production
		output = os.Stdout
	}

	Log = zerolog.New(output).With().Timestamp().Caller().Logger()
}

// RequestLoggerMiddleware logs every HTTP request
func RequestLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		if raw != "" {
			path = path + "?" + raw
		}

		// Log with structured fields
		event := Log.Info()
		if status >= 400 && status < 500 {
			event = Log.Warn()
		} else if status >= 500 {
			event = Log.Error()
		}

		event.
			Str("method", method).
			Str("path", path).
			Int("status", status).
			Dur("latency", latency).
			Str("ip", clientIP).
			Str("user_agent", c.Request.UserAgent())

		if errorMessage != "" {
			event.Str("error", errorMessage)
		}

		event.Msg("request")
	}
}

// Info logs an informational message
func Info(msg string) {
	Log.Info().Msg(msg)
}

// Debug logs a debug message
func Debug(msg string) {
	Log.Debug().Msg(msg)
}

// Error logs an error
func Error(msg string, err error) {
	Log.Error().Err(err).Msg(msg)
}

// Warn logs a warning
func Warn(msg string) {
	Log.Warn().Msg(msg)
}

// Fatal logs and terminates the program
func Fatal(msg string, err error) {
	Log.Fatal().Err(err).Msg(msg)
}
