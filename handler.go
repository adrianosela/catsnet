// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/adrianosela/catsnet/internal/keyloader"
	"github.com/adrianosela/catsnet/internal/signer"
	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

type Cap struct {
	Subjects []string `json:"subjects"`
}

type Template struct {
	LoginName    string
	ComputedName string
	RemoteAddr   string
	Caps         []Cap
}

type CSRRequest struct {
	CSR string `json:"csr"`
}

type CSRResponse struct {
	Certificate string `json:"certificate,omitempty"`
	Error       string `json:"error,omitempty"`
}

const (
	capName = "adrianosela.com/catsnet"

	pageTmpl = `<!doctype html>
<html>
  <body>
    <h1>Hello, world!</h1>

    <p>
      You are <b>{{.LoginName}}</b> from <b>{{.ComputedName}}</b> ({{.RemoteAddr}})
    </p>

    {{if .Caps}}
      <h2>Caps</h2>
      <ul>
        {{range .Caps}}
          <li>{{.Subjects}}</li>
        {{end}}
      </ul>
    {{else}}
      <p><i>No caps</i></p>
    {{end}}
  </body>
</html>`
)

func getHandler(
	logger *zap.Logger,
	tsClient *local.Client,
	keyLoader keyloader.KeyLoader,
) http.Handler {
	mux := http.NewServeMux()

	tmpl := template.Must(template.New("index").Parse(pageTmpl))

	// Initialize signer
	cert, key, err := keyLoader.Load()
	if err != nil {
		logger.Fatal("failed to load CA cert and key for signer", zap.Error(err))
	}
	certSigner := signer.New(cert, key)

	mux.Handle("/", getRootHandler(logger, tsClient, tmpl))
	mux.Handle("/cert", getCertHandler(logger, keyLoader))
	mux.Handle("/sign", getSignHandler(logger, tsClient, certSigner))

	return mux
}

func getCertHandler(logger *zap.Logger, keyLoader keyloader.KeyLoader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		logger := logger.With(
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)

		cert, _, err := keyLoader.Load()
		if err != nil {
			logger.Error("failed to load certificate", zap.Error(err))
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		_, _ = fmt.Fprintf(w, "%s", certPEM)
	})
}

func getSignHandler(logger *zap.Logger, tsClient *local.Client, certSigner *signer.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := logger.With(
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		who, err := tsClient.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			logger.Error("failed to retrieve WhoIs data for client", zap.Error(err))
			respondError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		caps, err := tailcfg.UnmarshalCapJSON[Cap](who.CapMap, tailcfg.PeerCapability(capName))
		if err != nil {
			logger.Error("failed to unmarshal capabilities JSON", zap.String("capname", capName), zap.Error(err))
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}

		allowedNames := make(set.Set[string])
		for _, cap := range caps {
			allowedNames.AddSlice(cap.Subjects)
		}

		if len(allowedNames) == 0 {
			logger.Warn("user has no allowed subjects in caps", zap.String("login_name", who.UserProfile.LoginName))
			respondError(w, "no allowed certificate subjects in capabilities", http.StatusForbidden)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error("failed to read request body", zap.Error(err))
			respondError(w, "failed to read request", http.StatusBadRequest)
			return
		}

		var req CSRRequest
		if err := json.Unmarshal(body, &req); err != nil {
			logger.Error("failed to parse request JSON", zap.Error(err))
			respondError(w, "invalid request format", http.StatusBadRequest)
			return
		}

		certPEM, err := certSigner.SignCSR(req.CSR, allowedNames)
		if err != nil {
			logger.Error("failed to sign CSR",
				zap.Error(err),
				zap.String("login_name", who.UserProfile.LoginName),
				zap.Strings("allowed_names", allowedNames.Slice()),
			)
			respondError(w, fmt.Sprintf("failed to sign CSR: %v", err), http.StatusBadRequest)
			return
		}

		logger.Info("signed certificate",
			zap.String("login_name", who.UserProfile.LoginName),
			zap.Strings("allowed_names", allowedNames.Slice()),
		)

		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(CSRResponse{
			Certificate: certPEM,
		}); err != nil {
			logger.Error("failed to encode reqsponse as JSON", zap.Error(err))
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}
	})
}

func respondError(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(CSRResponse{Error: msg}) // FIXME:errcheck
}

func getRootHandler(logger *zap.Logger, tsClient *local.Client, tmpl *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		logger := logger.With(
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)

		who, err := tsClient.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			logger.Error("failed to retrieve WhoIs data for client", zap.Error(err))
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}

		caps, err := tailcfg.UnmarshalCapJSON[Cap](who.CapMap, tailcfg.PeerCapability(capName))
		if err != nil {
			logger.Error(
				"failed to unmarshal capabilities JSON",
				zap.String("capname", capName),
				zap.Error(err),
			)
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, &Template{
			LoginName:    who.UserProfile.LoginName,
			ComputedName: who.Node.ComputedName,
			RemoteAddr:   r.RemoteAddr,
			Caps:         caps,
		})
		if err != nil {
			logger.Error(
				"failed to execute template",
				zap.String("login_name", who.UserProfile.LoginName),
				zap.String("computed_name", who.Node.ComputedName),
				zap.Error(err),
			)
			respondError(w, "an unknown error occured... try again later.", http.StatusInternalServerError)
			return
		}
	})
}
