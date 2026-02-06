// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package main

import (
	"html/template"
	"net/http"

	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
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

func getHandler(logger *zap.Logger, lc *local.Client) http.Handler {
	mux := http.NewServeMux()

	tmpl := template.Must(template.New("page").Parse(pageTmpl))

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			logger.Error(
				"failed to retrieve WhoIs data for client",
				zap.String("remote_addr", r.RemoteAddr),
				zap.Error(err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		caps, err := tailcfg.UnmarshalCapJSON[Cap](who.CapMap, tailcfg.PeerCapability(capName))
		if err != nil {
			logger.Error(
				"failed to unmarshal capabilities JSON",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("capname", capName),
				zap.Error(err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("login_name", who.UserProfile.LoginName),
				zap.String("computed_name", who.Node.ComputedName),
				zap.Error(err),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	return mux
}
