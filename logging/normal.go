package logging

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(NormalLogging{})
	httpcaddyfile.RegisterHandlerDirective("normal_logging", parseCaddyfile)
}

type NormalLogging struct {
	Tag    string `json:"tag,omitempty"`
	logger *zap.Logger
}

func (NormalLogging) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.normal_logging",
		New: func() caddy.Module { return new(NormalLogging) },
	}
}

func (m *NormalLogging) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

func (m *NormalLogging) Validate() error {
	if m.Tag == "" {
		m.Tag = "normal_logging"
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m NormalLogging) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	m.logger.Debug("NormalLogging ServeHTTP: ", zap.String("tag", m.Tag))
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *NormalLogging) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// require an argument
	if !d.NextArg() {
		return d.ArgErr()
	}

	// store the argument
	m.Tag = d.Val()
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m NormalLogging
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*NormalLogging)(nil)
	_ caddy.Validator             = (*NormalLogging)(nil)
	_ caddyhttp.MiddlewareHandler = (*NormalLogging)(nil)
	_ caddyfile.Unmarshaler       = (*NormalLogging)(nil)
)
