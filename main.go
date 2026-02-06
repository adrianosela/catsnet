// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"

	"go.uber.org/zap"
	"tailscale.com/tsnet"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}

	var addr string
	var authkey string
	var hostname string
	flag.StringVar(&addr, "addr", ":80", "address to listen on")
	flag.StringVar(&authkey, "authkey", "", "Tailscale auth key")
	flag.StringVar(&hostname, "hostname", "catsnet", "hostname to use for Tailscale machine")
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

	err = http.Serve(ln, getHandler(logger, lc))
	if err != nil {
		logger.Fatal("failed to serve HTTP over tsnet listener", zap.Error(err))
	}
}
