package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// NewServer returns an *http.Server for the gateway with hardened defaults
// for timeouts and header size taken from the server config.
func (g *Gateway) NewServer() *http.Server {
	s := g.cfg.Server
	or := func(d Duration, def time.Duration) time.Duration {
		if d == 0 {
			return def
		}
		return d.D()
	}
	addr := s.Listen
	if addr == "" {
		addr = ":8080"
	}
	maxHdr := s.MaxHeaderBytes
	if maxHdr == 0 {
		maxHdr = 32 << 10
	}
	return &http.Server{
		Addr:              addr,
		Handler:           g,
		ReadHeaderTimeout: or(s.ReadHeaderTimeout, 5*time.Second),
		ReadTimeout:       or(s.ReadTimeout, 30*time.Second),
		WriteTimeout:      or(s.WriteTimeout, 60*time.Second),
		IdleTimeout:       or(s.IdleTimeout, 120*time.Second),
		MaxHeaderBytes:    maxHdr,
		ErrorLog:          slog.NewLogLogger(g.logger.Handler(), slog.LevelWarn),
	}
}

// ListenAndServe runs the gateway until ctx is cancelled, then shuts down
// gracefully within server.shutdownTimeout (default 15s).
func (g *Gateway) ListenAndServe(ctx context.Context) error {
	srv := g.NewServer()
	errc := make(chan error, 1)
	go func() {
		g.logger.Info("gateway listening", "addr", srv.Addr, "routes", len(g.cfg.Routes), "tls", g.cfg.Server.TLS != nil)
		var err error
		if t := g.cfg.Server.TLS; t != nil {
			err = srv.ListenAndServeTLS(t.CertFile, t.KeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	timeout := g.cfg.Server.ShutdownTimeout.D()
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	sctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	g.logger.Info("shutting down", "timeout", timeout)
	if err := srv.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
