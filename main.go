// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"github.com/adrianosela/catsnet/internal/keyloader"
	"go.uber.org/zap"
	"tailscale.com/tsnet"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}

	var addr string
	var authkey string
	var hostname string
	var certFilepath string
	var keyFilepath string

	flag.StringVar(&addr, "addr", ":80", "address to listen on")
	flag.StringVar(&authkey, "authkey", "", "Tailscale auth key")
	flag.StringVar(&hostname, "hostname", "catsnet", "hostname to use for Tailscale machine")
	flag.StringVar(&certFilepath, "cert", "./.sample_data/ca-cert.pem", "CA certificate PEM filepath")
	flag.StringVar(&keyFilepath, "key", "./.sample_data/ca-key.pem", "CA private key PEM filepath")
	flag.Parse()

	if authkey == "" {
		logger.Fatal("flag authkey is required but was empty")
	}

	srv := new(tsnet.Server)
	srv.AuthKey = authkey
	srv.Hostname = hostname
	defer func() {
		if err := srv.Close(); err != nil {
			logger.Error("failed to close tsnet server", zap.Error(err))
		}
	}()

	ln, err := srv.Listen("tcp", addr)
	if err != nil {
		logger.Fatal("failed to initialize TCP listener", zap.String("addr", addr), zap.Error(err))
	}
	defer func() {
		if err := ln.Close(); err != nil {
			logger.Error("failed to close listener", zap.Error(err))
		}
	}()

	lc, err := srv.LocalClient()
	if err != nil {
		logger.Fatal("failed to initialize tailscale local client", zap.Error(err))
	}

	// wrap tcp listener in tls listener if port is HTTPS port
	if addr == ":443" {
		ln = tls.NewListener(ln, &tls.Config{GetCertificate: lc.GetCertificate})
	}

	keyLoader, err := keyloader.NewStaticLoader(certFilepath, keyFilepath)
	if err != nil {
		logger.Fatal("failed to initialize static key loader", zap.Error(err))
	}

	handler := getHandler(
		logger,
		lc,
		keyLoader,
	)

	err = http.Serve(ln, handler)
	if err != nil {
		logger.Fatal("failed to serve HTTP over tsnet listener", zap.Error(err))
	}
}
