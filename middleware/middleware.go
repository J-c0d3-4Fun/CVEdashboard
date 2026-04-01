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
	written    bool
}

func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.written {

		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}

}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}
func PathLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		writer := &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		handler.ServeHTTP(writer, r)

		log.Printf("%s %s %d %v", r.Method, r.URL.Path, writer.statusCode, time.Since(start))
	})
}
