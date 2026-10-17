package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type cfg struct {
	ListenAddr string
	DBPath     string
	Pepper     string
	AdminToken string
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func mustCfg() cfg {
	c := cfg{
		ListenAddr: getenv("LISTEN_ADDR", "0.0.0.0:8080"),
		DBPath:     getenv("DB_PATH", "/data/keys.sqlite"),
		Pepper:     os.Getenv("AUTH_PEPPER"),
		AdminToken: os.Getenv("ADMIN_TOKEN"),
	}
	if strings.TrimSpace(c.Pepper) == "" {
		log.Fatal("AUTH_PEPPER is required")
	}
	if strings.TrimSpace(c.AdminToken) == "" {
		log.Fatal("ADMIN_TOKEN is required")
	}
	return c
}

func hmacKeyHex(pepper, apiKey string) string {
	m := hmac.New(sha256.New, []byte(pepper))
	_, _ = m.Write([]byte(apiKey))
	return hex.EncodeToString(m.Sum(nil))
}

func readAPIKey(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k
	}
	// Authorization: Bearer <token>
	if a := strings.TrimSpace(r.Header.Get("Authorization")); a != "" {
		parts := strings.SplitN(a, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func jsonWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var (
	reqTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "llm_auth_requests_total",
			Help: "Total auth service requests",
		},
		[]string{"endpoint", "result"},
	)
	validateLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "llm_auth_validate_seconds",
			Help:    "Validation request latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)
)

func init() {
	prometheus.MustRegister(reqTotal, validateLatency)
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hmac TEXT NOT NULL UNIQUE,
  user_name TEXT NOT NULL,
  group_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
`)
	return err
}

type adminCreateReq struct {
	User  string `json:"user"`
	Group string `json:"group"`
	// Optional: allow callers to provide a key (otherwise we generate one)
	Key string `json:"key,omitempty"`
}

type adminCreateResp struct {
	ID    int64  `json:"id"`
	Key   string `json:"key"`
	User  string `json:"user"`
	Group string `json:"group"`
}

func randomKey() (string, error) {
	// 32 bytes -> 64 hex chars
	b := make([]byte, 32)
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func adminAuth(c cfg, w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) != c.AdminToken {
		reqTotal.WithLabelValues(r.URL.Path, "forbidden").Inc()
		jsonWrite(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}

func main() {
	c := mustCfg()

	db, err := sql.Open("sqlite", c.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	if err := migrate(db); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		reqTotal.WithLabelValues("/healthz", "ok").Inc()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		result := "deny"
		defer func() {
			validateLatency.WithLabelValues(result).Observe(time.Since(start).Seconds())
			reqTotal.WithLabelValues("/validate", result).Inc()
		}()

		apiKey := readAPIKey(r)
		if apiKey == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}

		keyH := hmacKeyHex(c.Pepper, apiKey)

		var user, group string
		var enabled int
		err := db.QueryRow(`SELECT user_name, group_name, enabled FROM api_keys WHERE key_hmac = ? LIMIT 1`, keyH).Scan(&user, &group, &enabled)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "invalid api key", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("db error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if enabled != 1 {
			http.Error(w, "revoked", http.StatusUnauthorized)
			return
		}

		// Success: return low-cardinality attributes as headers for nginx
		w.Header().Set("X-Api-User", user)
		w.Header().Set("X-Api-Group", group)
		result = "ok"
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/admin/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			reqTotal.WithLabelValues("/admin/keys", "method_not_allowed").Inc()
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !adminAuth(c, w, r) {
			return
		}

		var req adminCreateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reqTotal.WithLabelValues("/admin/keys", "bad_request").Inc()
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		req.User = strings.TrimSpace(req.User)
		req.Group = strings.TrimSpace(req.Group)
		if req.User == "" || req.Group == "" {
			reqTotal.WithLabelValues("/admin/keys", "bad_request").Inc()
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "user and group are required"})
			return
		}
		key := strings.TrimSpace(req.Key)
		if key == "" {
			k, err := randomKey()
			if err != nil {
				reqTotal.WithLabelValues("/admin/keys", "error").Inc()
				jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate key"})
				return
			}
			key = k
		}

		keyH := hmacKeyHex(c.Pepper, key)
		now := time.Now().UTC().Format(time.RFC3339)

		res, err := db.Exec(`INSERT INTO api_keys(key_hmac, user_name, group_name, enabled, created_at) VALUES (?, ?, ?, 1, ?)`, keyH, req.User, req.Group, now)
		if err != nil {
			reqTotal.WithLabelValues("/admin/keys", "error").Inc()
			jsonWrite(w, http.StatusConflict, map[string]string{"error": "key already exists or db error"})
			return
		}
		id, _ := res.LastInsertId()
		reqTotal.WithLabelValues("/admin/keys", "ok").Inc()
		jsonWrite(w, http.StatusOK, adminCreateResp{ID: id, Key: key, User: req.User, Group: req.Group})
	})

	mux.HandleFunc("/admin/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			reqTotal.WithLabelValues("/admin/revoke", "method_not_allowed").Inc()
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !adminAuth(c, w, r) {
			return
		}

		// revoke by api key (plaintext) or by id
		var body struct {
			Key string `json:"key,omitempty"`
			ID  int64  `json:"id,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reqTotal.WithLabelValues("/admin/revoke", "bad_request").Inc()
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}

		var (
			res sql.Result
			err error
		)
		if body.ID > 0 {
			res, err = db.Exec(`UPDATE api_keys SET enabled = 0 WHERE id = ?`, body.ID)
		} else if k := strings.TrimSpace(body.Key); k != "" {
			res, err = db.Exec(`UPDATE api_keys SET enabled = 0 WHERE key_hmac = ?`, hmacKeyHex(c.Pepper, k))
		} else {
			reqTotal.WithLabelValues("/admin/revoke", "bad_request").Inc()
			jsonWrite(w, http.StatusBadRequest, map[string]string{"error": "id or key required"})
			return
		}
		if err != nil {
			reqTotal.WithLabelValues("/admin/revoke", "error").Inc()
			jsonWrite(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		n, _ := res.RowsAffected()
		reqTotal.WithLabelValues("/admin/revoke", "ok").Inc()
		jsonWrite(w, http.StatusOK, map[string]any{"revoked": n})
	})

	srv := &http.Server{
		Addr:              c.ListenAddr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("llm-auth listening on %s (db=%s)", c.ListenAddr, c.DBPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rr := &respRec{ResponseWriter: w, status: 200}
		next.ServeHTTP(rr, r)
		d := time.Since(start)
		log.Printf("%s %s %d %s ua=%q", r.Method, r.URL.Path, rr.status, d.String(), r.UserAgent())
	})
}

type respRec struct {
	http.ResponseWriter
	status int
}

func (r *respRec) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// compile-time check
var _ = fmt.Sprintf

