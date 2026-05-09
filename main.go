package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	appconfig "github.com/define42/elasticgateway/internal/config"
	"github.com/define42/elasticgateway/internal/elastic"
	ldappkg "github.com/define42/elasticgateway/internal/ldap"
	"github.com/define42/elasticgateway/internal/server"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Minute
	httpWriteTimeout      = 10 * time.Minute
	httpIdleTimeout       = 2 * time.Minute
)

func main() {
	configureLogger()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := appconfig.LoadGateway()
	if err != nil {
		fatal(err)
	}
	if err := run(ctx, cfg, func(handler http.Handler) error {
		srv := newHTTPServer(cfg.ListenAddr, handler)

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()

		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}); err != nil {
		fatal(err)
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
}

func configureLogger() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
}

func run(ctx context.Context, cfg appconfig.Config, serve func(http.Handler) error) error {
	client := elastic.NewClient(cfg)

	if err := client.EnsureILMPolicy(ctx, elastic.DefaultILMPolicyID, 100000000); err != nil {
		return err
	}

	if err := client.EnsureIndexTemplate(ctx, elastic.DefaultIndexTemplateName); err != nil {
		return err
	}

	authenticator := ldappkg.New(appconfig.LoadLDAP())
	return serve(server.New(client, authenticator.AuthenticateAccess).Handler())
}

func fatal(err error) {
	if err == nil {
		return
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		fmt.Fprintf(os.Stderr, "network error: %v\n", urlErr)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
