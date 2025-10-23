package demo01

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// MyMiddleware is the module type.
type MyMiddleware struct {
	// Add any configuration fields for your middleware here
	Message string `json:"message,omitempty"`
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MyMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.mymiddleware",
		New: func() caddy.Module { return new(MyMiddleware) },
	}
}

// Provision sets up the middleware.
func (m *MyMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m MyMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Your middleware logic goes here
	m.logger.Info("MyMiddleware received a request", zap.String("path", r.URL.Path))

	// Example: Modify a header
	w.Header().Set("X-My-Middleware", m.Message)

	// Pass the request to the next handler in the chain
	return next.ServeHTTP(w, r)
}

func init() {
	caddy.RegisterModule(MyMiddleware{})
}
