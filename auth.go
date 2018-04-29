package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-graphite/carbonapi/auth"
	"github.com/go-graphite/carbonapi/util"
	"github.com/lomik/zapwriter"
	uuid "github.com/satori/go.uuid"
	"go.uber.org/zap"
)

func usersHandler(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		uuid := uuid.NewV4()
		ctx := util.SetUUID(r.Context(), uuid.String())
		username, _, _ := r.BasicAuth()

		srcIP, srcPort := splitRemoteAddr(r.RemoteAddr)
		accessLogger := zapwriter.Logger("access").With(
			zap.String("handler", "render"),
			zap.String("carbonapi_uuid", uuid.String()),
			zap.String("username", username),
			zap.String("url", r.URL.RequestURI()),
			zap.String("peer_ip", srcIP),
			zap.String("peer_port", srcPort),
			zap.String("host", r.Host),
			zap.String("referer", r.Referer()),
			zap.String("method", r.Method),
		)

		id := strings.TrimPrefix(r.URL.Path, "/users")
		id = strings.TrimPrefix(id, "/")

		if id == "" {
			switch r.Method {
			case http.MethodGet: // GET /users
				u, err := store.List(ctx)
				if err != nil {
					handleError(w, accessLogger, t0, err)
					return
				}

				b, err := json.Marshal(u)
				if err != nil {
					handleError(w, accessLogger, t0, err)
					return
				}
				writeResponse(w, b, "json", "")
			case http.MethodPost: // POST /users
				var u auth.User
				if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
					handleError(w, accessLogger, t0, err)
					return
				}

				if err := store.Save(ctx, &u); err != nil {
					if verr, ok := err.(auth.ValidationError); ok {
						http.Error(w, http.StatusText(http.StatusBadRequest)+": "+verr.Error(), http.StatusBadRequest)
						accessLogger.Info("bad request",
							zap.Int("http_code", http.StatusBadRequest),
							zap.String("reason", verr.Error()),
						)
						return
					}

					handleError(w, accessLogger, t0, err)
					return
				}
				w.WriteHeader(http.StatusOK)
			default:
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
				accessLogger.Info("request failed",
					zap.Int("http_code", http.StatusMethodNotAllowed),
				)
			}
		} else {
			switch r.Method {
			case http.MethodGet: // GET /users/:id
				u, err := store.FindByUsername(ctx, id)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					accessLogger.Info("not found",
						zap.Int("http_code", http.StatusMethodNotAllowed),
						zap.String("id", id),
					)
				}

				b, err := json.Marshal(u)
				if err != nil {
					handleError(w, accessLogger, t0, err)
					return
				}
				writeResponse(w, b, "json", "")
			case http.MethodDelete: // DELETE /users/:id
				if err := store.Delete(ctx, id); err != nil {
					handleError(w, accessLogger, t0, err)
					return
				}
				w.WriteHeader(http.StatusOK)
			default:
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
				accessLogger.Info("request failed",
					zap.Int("http_code", http.StatusMethodNotAllowed),
				)
			}
		}

		accessLogger.Info("request served",
			zap.String("uri", r.RequestURI),
			zap.Int("http_code", http.StatusOK),
			zap.Duration("runtime", time.Since(t0)),
		)
	}
}

func handleError(w http.ResponseWriter, accessLogger *zap.Logger, t0 time.Time, err error) {
	http.Error(w, http.StatusText(http.StatusInternalServerError)+": "+err.Error(), http.StatusInternalServerError)
	accessLogger.Info("request failed",
		zap.Int("http_code", http.StatusInternalServerError),
		zap.String("reason", err.Error()),
		zap.Duration("runtime", time.Since(t0)),
	)
}

type contextKey int

const (
	userKey contextKey = iota
)

// userFromRequest returns user entity from the context
// when the auth feature is enabled or returns nil.
func userFromContext(ctx context.Context) *auth.User {
	if config.Auth.Enable {
		return ctx.Value(userKey).(*auth.User)
	}
	return nil
}

// authUser authorizes users saved to sql database.
func authUser(h http.HandlerFunc, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()
		u, err := store.FindByUsernameAndPassword(r.Context(), username, password)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// save user to the request context
		c := context.WithValue(r.Context(), userKey, u)
		r = r.WithContext(c)
		h(w, r)
	}
}

// authAdmin authorized admin user using credentials from config.
func authAdmin(h http.HandlerFunc, u, p string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()
		if username != u || password != p {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}
