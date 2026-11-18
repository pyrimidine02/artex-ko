package server

// Single sign-on through the platform OIDC provider (Ory Hydra at sso.noraneko.cc).
// This deployment signs in only this way: the password routes (/api/auth/init, /login,
// /change-password) are not registered. A successful callback issues the same HS256
// session token the rest of the server already checks, so requireAuth is unchanged.
//
// Configuration (all required; without it every sign-in attempt fails closed):
//   ARTEX_OIDC_ISSUER          e.g. https://sso.noraneko.cc/
//   ARTEX_OIDC_CLIENT_ID
//   ARTEX_OIDC_CLIENT_SECRET
//   ARTEX_OIDC_REDIRECT_URL    e.g. https://artex.noraneko.cc/api/auth/oidc/callback
//   ARTEX_OIDC_REQUIRED_ROLE   role the SSO must grant, e.g. artex
//   ARTEX_OIDC_ROLES_CLAIM     ID token claim holding the roles (default "roles")
//
// Who may sign in is managed in the SSO, not here: the provider puts the user's
// roles into the ID token, and only a token carrying the required role opens a session.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

const (
	oidcCookie    = "artex_oidc"
	oidcCookieTTL = 10 * time.Minute
	oidcTimeout   = 10 * time.Second
)

type oidcConfig struct {
	issuer, clientID, clientSecret, redirectURL string
	requiredRole, rolesClaim                    string
}

func oidcConfigFromEnv() (oidcConfig, error) {
	c := oidcConfig{
		issuer:       strings.TrimSpace(os.Getenv("ARTEX_OIDC_ISSUER")),
		clientID:     strings.TrimSpace(os.Getenv("ARTEX_OIDC_CLIENT_ID")),
		clientSecret: strings.TrimSpace(os.Getenv("ARTEX_OIDC_CLIENT_SECRET")),
		redirectURL:  strings.TrimSpace(os.Getenv("ARTEX_OIDC_REDIRECT_URL")),
		requiredRole: strings.TrimSpace(os.Getenv("ARTEX_OIDC_REQUIRED_ROLE")),
		rolesClaim:   strings.TrimSpace(os.Getenv("ARTEX_OIDC_ROLES_CLAIM")),
	}
	if c.rolesClaim == "" {
		c.rolesClaim = "roles"
	}
	if c.issuer == "" || c.clientID == "" || c.clientSecret == "" || c.redirectURL == "" || c.requiredRole == "" {
		return c, errors.New("ARTEX_OIDC_ISSUER, _CLIENT_ID, _CLIENT_SECRET, _REDIRECT_URL and _REQUIRED_ROLE must all be set")
	}
	return c, nil
}

// oidcClient is discovered lazily and cached, so the server starts even while the
// provider is down; a failed discovery is retried on the next sign-in.
type oidcClient struct {
	cfg      oidcConfig
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

var (
	oidcMu     sync.Mutex
	oidcCached *oidcClient
)

func getOIDCClient(ctx context.Context) (*oidcClient, error) {
	oidcMu.Lock()
	defer oidcMu.Unlock()
	cfg, err := oidcConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if oidcCached != nil && oidcCached.cfg.issuer == cfg.issuer && oidcCached.cfg.clientID == cfg.clientID {
		// A copy per call: the allowlist and secret may change without a new discovery,
		// and handlers keep using their copy after the lock is released.
		c := *oidcCached
		c.cfg = cfg
		c.oauth.ClientSecret = cfg.clientSecret
		return &c, nil
	}
	p, err := oidc.NewProvider(ctx, cfg.issuer)
	if err != nil {
		return nil, err
	}
	oidcCached = &oidcClient{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.clientID,
			ClientSecret: cfg.clientSecret,
			RedirectURL:  cfg.redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "roles"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.clientID}),
	}
	c := *oidcCached
	return &c, nil
}

// sessionHash returns the stored hash that the session signing key is bound to
// (signingKey). With SSO only, no password is ever set, so on first sign-in a random
// one is stored: revoking every session then means overwriting it
// (reset-password.sh or a direct settings edit), as before. Without a database
// (tests) the raw key is used.
func (s *Server) sessionHash() (string, error) {
	hash, err := s.cachedPassHash()
	if err != nil || hash != "" || s.m == nil || s.m.pg == nil {
		return hash, err
	}
	secret, err := randomToken(32)
	if err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if _, err := s.m.pg.InsertSettingIfAbsent(authPassKey, string(h)); err != nil {
		return "", err
	}
	return s.reloadPassHash()
}

// noStore keeps auth redirects (one carries the session token) out of caches and
// Referer headers.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// oidcFlow is the per-attempt state kept in a short-lived HttpOnly cookie, signed
// with the server's JWT key so a client cannot forge or swap it.
type oidcFlow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

func (s *Server) oidcSign(payload string) string {
	m := hmac.New(sha256.New, s.jwtKey)
	m.Write([]byte("oidc-flow:" + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) encodeFlow(f oidcFlow) (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + s.oidcSign(p), nil
}

func (s *Server) decodeFlow(v string) (oidcFlow, bool) {
	var f oidcFlow
	p, sig, ok := strings.Cut(v, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.oidcSign(p))) {
		return f, false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || json.Unmarshal(b, &f) != nil || time.Now().Unix() > f.Expires {
		return f, false
	}
	return f, true
}

func setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: value, Path: "/api/auth/oidc", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// oidcFail sends the browser back to the login page with a short reason code the
// page turns into a message. Details go to the server log only.
func oidcFail(w http.ResponseWriter, r *http.Request, code string, err error) {
	log.Printf("[auth] sso sign-in failed: %s: %q (client=%s)", code, fmt.Sprint(err), clientLogID(r))
	noStore(w)
	setFlowCookie(w, "", -1)
	http.Redirect(w, r, "/login?sso_error="+url.QueryEscape(code), http.StatusFound)
}

// GET /api/auth/oidc/start — redirects to the provider with state, nonce and PKCE.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), oidcTimeout)
	defer cancel()
	c, err := getOIDCClient(ctx)
	if err != nil {
		oidcFail(w, r, "unavailable", err)
		return
	}
	state, err1 := randomToken(32)
	nonce, err2 := randomToken(32)
	if err1 != nil || err2 != nil {
		oidcFail(w, r, "unavailable", errors.Join(err1, err2))
		return
	}
	f := oidcFlow{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(oidcCookieTTL).Unix()}
	v, err := s.encodeFlow(f)
	if err != nil {
		oidcFail(w, r, "unavailable", err)
		return
	}
	noStore(w)
	setFlowCookie(w, v, int(oidcCookieTTL.Seconds()))
	http.Redirect(w, r, c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

// GET /api/auth/oidc/callback — checks state, exchanges the code, verifies the ID
// token and the role the SSO granted, then hands the session token to the login page in
// the URL fragment (never sent to a server, so it stays out of access logs).
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), oidcTimeout)
	defer cancel()
	ck, err := r.Cookie(oidcCookie)
	if err != nil {
		oidcFail(w, r, "state", err)
		return
	}
	f, ok := s.decodeFlow(ck.Value)
	q := r.URL.Query()
	if !ok || q.Get("state") == "" || !hmac.Equal([]byte(q.Get("state")), []byte(f.State)) {
		oidcFail(w, r, "state", errors.New("state cookie missing, expired or mismatched"))
		return
	}
	if e := q.Get("error"); e != "" {
		oidcFail(w, r, "denied", errors.New(e))
		return
	}
	c, err := getOIDCClient(ctx)
	if err != nil {
		oidcFail(w, r, "unavailable", err)
		return
	}
	tok, err := c.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		oidcFail(w, r, "exchange", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		oidcFail(w, r, "token", err)
		return
	}
	if !hmac.Equal([]byte(idt.Nonce), []byte(f.Nonce)) {
		oidcFail(w, r, "token", errors.New("nonce mismatch"))
		return
	}
	// The SSO decides who may use ARTEX by granting the role; this only checks the
	// signed claim. An exact, case-sensitive match on a claim the provider controls.
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		oidcFail(w, r, "token", err)
		return
	}
	email, _ := claims["email"].(string)
	if !hasRole(claims[c.cfg.rolesClaim], c.cfg.requiredRole) {
		oidcFail(w, r, "forbidden", fmt.Errorf("role %q not granted to sub %q (%s)", c.cfg.requiredRole, idt.Subject, email))
		return
	}
	hash, err := s.sessionHash()
	if err != nil {
		oidcFail(w, r, "unavailable", err)
		return
	}
	session, err := signJWT(s.signingKey(hash))
	if err != nil {
		oidcFail(w, r, "unavailable", err)
		return
	}
	noStore(w)
	setFlowCookie(w, "", -1)
	log.Printf("[auth] sso sign-in: sub %q %q (client=%s)", idt.Subject, email, clientLogID(r))
	http.Redirect(w, r, "/login#token="+url.QueryEscape(session), http.StatusFound)
}

// hasRole reports whether the roles claim (a JSON array of strings, or one string)
// contains role exactly.
func hasRole(claim any, role string) bool {
	switch v := claim.(type) {
	case string:
		return v == role
	case []any:
		for _, x := range v {
			if x == role {
				return true
			}
		}
	}
	return false
}
