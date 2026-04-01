package storage

import (
	"context"
	"net/http"
)

func PoolMiddleware(pool *ConnectionPool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db := pool.Get()
			defer pool.Release(db)

			ctx := context.WithValue(r.Context(), "db", db)
			next.ServeHTTP(w, r.WithContext(ctx))

		})

	}
}
