package middleware

import (
	"log"
	"net/http"
	"time"
)

// capture the status code
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw ResponseWriter) StatusCode(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func PathLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		writer := &ResponseWriter{w, http.StatusOK}

		handler.ServeHTTP(writer, r)

		log.Printf("%s %s %d %v", r.Method, r.URL.Path, writer.statusCode, start)
	})
}
