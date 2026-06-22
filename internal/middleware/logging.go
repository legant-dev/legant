package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

// Flush forwards to the underlying ResponseWriter so streaming handlers (SSE) can
// flush through this wrapper instead of being silently buffered.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped ResponseWriter so http.NewResponseController can
// walk down to the base connection for Flush / SetWriteDeadline (needed to keep
// a long-lived SSE stream alive past the server's WriteTimeout).
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"size", rw.size,
			"duration", time.Since(start).String(),
			"ip", r.RemoteAddr,
			"request_id", GetRequestID(r.Context()),
		)
	})
}
