// Package web is the BFF's driving adapter: Gin handlers, cookies, CSRF
// and Origin checks, security headers, and HTML templates.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/bff/app"
	"github.com/aamirlatif1/warden/internal/bff/domain"
)

//go:embed templates/*.html
var templateFS embed.FS

type AuthFlows interface {
	Login(ctx context.Context, req app.LoginRequest) (txID, redirectURL string, err error)
	Callback(ctx context.Context, req app.CallbackRequest) (app.CallbackResult, error)
	Logout(ctx context.Context, sid, postLogoutRedirect string) (string, error)
}

type PortalActions interface {
	Dashboard(ctx context.Context, sid string) (app.Dashboard, error)
	UpdatePayout(ctx context.Context, sid, policyID, iban string) (app.Policy, error)
}

type SessionReader interface {
	Get(ctx context.Context, id string) (domain.Session, error)
}

type Config struct {
	Title   string // "Policyholder portal", "Claims app"
	BaseURL string // e.g. http://localhost:8082 — the only accepted Origin
	// CookiePrefix must start with "__Host-" and differ per instance:
	// cookies are not isolated by port, and portal and claims-app both run
	// on localhost.
	CookiePrefix string
	// IdPOrigin (e.g. http://localhost:8080) is allowed in CSP form-action:
	// browsers apply form-action to the redirect after a form POST, and
	// step-up and logout redirect to the IdP.
	IdPOrigin string
}

type Server struct {
	cfg      Config
	auth     AuthFlows
	portal   PortalActions
	sessions SessionReader
	log      *slog.Logger
	tmpl     *template.Template
	origin   string
}

func New(cfg Config, auth AuthFlows, portal PortalActions, sessions SessionReader, log *slog.Logger) (*Server, error) {
	if !strings.HasPrefix(cfg.CookiePrefix, "__Host-") {
		return nil, errors.New("web: CookiePrefix must start with __Host-")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("web: BaseURL must be an absolute URL")
	}
	t, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, auth: auth, portal: portal, sessions: sessions, log: log, tmpl: t, origin: u.Scheme + "://" + u.Host}, nil
}

func (s *Server) sidCookie() string     { return s.cfg.CookiePrefix + "sid" }
func (s *Server) preauthCookie() string { return s.cfg.CookiePrefix + "preauth" }

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, rec any) {
		s.log.ErrorContext(c.Request.Context(), "panic in handler", "path", c.FullPath(), "panic", rec)
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	r.Use(s.securityHeaders)

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	r.GET("/", s.home)
	r.GET("/login", s.login)
	r.GET("/callback", s.callback)
	r.POST("/payout", s.requireCSRF, s.payout)
	r.POST("/logout", s.requireCSRF, s.logout)
	return r
}

// securityHeaders: no framing, no sniffing, no caching of pages that show
// personal data, scripts only from us (there are none).
func (s *Server) securityHeaders(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' "+s.cfg.IdPOrigin+"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	c.Next()
}

// ---- cookies ----

func (s *Server) setCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(c *gin.Context, name string) { s.setCookie(c, name, "", -1) }

func (s *Server) cookie(c *gin.Context, name string) string {
	v, _ := c.Cookie(name)
	return v
}

// ---- pages ----

type page struct {
	Title    string
	Session  *domain.Session
	Policies []app.Policy
	Kind     string
	Heading  string
	Text     string
}

func (s *Server) render(c *gin.Context, status int, name string, p page) {
	p.Title = s.cfg.Title
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(c.Writer, name, p); err != nil {
		s.log.ErrorContext(c.Request.Context(), "render", "template", name, "err", err)
	}
}

func (s *Server) message(c *gin.Context, status int, kind, heading, text string) {
	s.render(c, status, "message.html", page{Kind: kind, Heading: heading, Text: text})
}

func (s *Server) home(c *gin.Context) {
	sid := s.cookie(c, s.sidCookie())
	if sid == "" {
		s.render(c, http.StatusOK, "index.html", page{})
		return
	}
	d, err := s.portal.Dashboard(c.Request.Context(), sid)
	if errors.Is(err, domain.ErrNoSession) || errors.Is(err, app.ErrSessionEnded) {
		s.clearCookie(c, s.sidCookie())
		s.render(c, http.StatusOK, "index.html", page{})
		return
	}
	if err != nil {
		s.log.ErrorContext(c.Request.Context(), "dashboard", "err", err)
		s.message(c, http.StatusBadGateway, "warn", "Something went wrong", "Your policies could not be loaded. Try again shortly.")
		return
	}
	s.render(c, http.StatusOK, "dashboard.html", page{Session: &d.Session, Policies: d.Policies})
}

func (s *Server) startLogin(c *gin.Context, req app.LoginRequest, status int) {
	txID, redirect, err := s.auth.Login(c.Request.Context(), req)
	if err != nil {
		s.log.ErrorContext(c.Request.Context(), "login start", "err", err)
		s.message(c, http.StatusServiceUnavailable, "warn", "Login unavailable", "Please try again shortly.")
		return
	}
	s.setCookie(c, s.preauthCookie(), txID, 600)
	c.Redirect(status, redirect)
}

func (s *Server) login(c *gin.Context) {
	s.startLogin(c, app.LoginRequest{ReturnTo: c.Query("return_to")}, http.StatusFound)
}

func (s *Server) callback(c *gin.Context) {
	ctx := c.Request.Context()
	txID := s.cookie(c, s.preauthCookie())
	s.clearCookie(c, s.preauthCookie())

	res, err := s.auth.Callback(ctx, app.CallbackRequest{
		TxID: txID, State: c.Query("state"), Code: c.Query("code"), Error: c.Query("error"),
		PriorSID: s.cookie(c, s.sidCookie()),
	})
	if err != nil {
		var le *app.LoginError
		reason := "internal"
		if errors.As(err, &le) {
			reason = string(le.Reason)
		}
		s.log.WarnContext(ctx, "login failed", "reason", reason)
		s.message(c, http.StatusBadRequest, "warn", "Login failed", "Please start again from the home page.")
		return
	}
	s.setCookie(c, s.sidCookie(), res.Session.ID, 0)
	s.log.InfoContext(ctx, "login", "sub", res.Session.Subject, "acr", res.Session.ACR)

	if p := res.Pending; p != nil && p.Kind == domain.PendingUpdatePayout {
		// Step-up done: replay the intent with the new, stronger session.
		pol, err := s.portal.UpdatePayout(ctx, res.Session.ID, p.PolicyID, p.IBAN)
		s.payoutResult(c, pol, err)
		return
	}
	c.Redirect(http.StatusFound, res.ReturnTo)
}

func (s *Server) payout(c *gin.Context) {
	sid := s.cookie(c, s.sidCookie())
	pol, err := s.portal.UpdatePayout(c.Request.Context(), sid, c.PostForm("policy_id"), c.PostForm("iban"))
	var need *app.StepUpNeeded
	if errors.As(err, &need) {
		// 303: the browser follows with GET to Keycloak.
		s.startLogin(c, need.Login, http.StatusSeeOther)
		return
	}
	s.payoutResult(c, pol, err)
}

func (s *Server) payoutResult(c *gin.Context, pol app.Policy, err error) {
	switch {
	case err == nil:
		s.message(c, http.StatusOK, "ok", "Payout account updated", "Policy "+pol.ID+" now pays out to "+pol.PayoutIBANMasked+".")
	case errors.Is(err, domain.ErrNoSession), errors.Is(err, app.ErrSessionEnded):
		s.clearCookie(c, s.sidCookie())
		s.message(c, http.StatusUnauthorized, "warn", "Session ended", "Please log in again.")
	case errors.Is(err, app.ErrAPIInvalid):
		s.message(c, http.StatusBadRequest, "warn", "Invalid IBAN", "Check the account number and try again.")
	case errors.Is(err, app.ErrAPIForbidden), errors.Is(err, app.ErrAPINotFound):
		s.message(c, http.StatusForbidden, "warn", "Not allowed", "You can only change your own policies.")
	default:
		var need *app.StepUpNeeded
		if errors.As(err, &need) {
			// Still not strong enough after re-auth: don't loop.
			s.message(c, http.StatusForbidden, "warn", "Stronger login required", "This change needs a one-time code. Please try again.")
			return
		}
		s.log.ErrorContext(c.Request.Context(), "payout", "err", err)
		s.message(c, http.StatusBadGateway, "warn", "Something went wrong", "The change was not saved. Try again shortly.")
	}
}

func (s *Server) logout(c *gin.Context) {
	sid := s.cookie(c, s.sidCookie())
	next, err := s.auth.Logout(c.Request.Context(), sid, s.cfg.BaseURL+"/")
	s.clearCookie(c, s.sidCookie())
	if err != nil {
		s.log.ErrorContext(c.Request.Context(), "logout", "err", err)
		next = "/"
	}
	c.Redirect(http.StatusSeeOther, next)
}

// requireCSRF guards state-changing requests (D9): the Origin (or, if
// absent, Referer) must be ours, and the form's synchroniser token must
// equal the session's. SameSite=Lax on the cookie is the third layer.
func (s *Server) requireCSRF(c *gin.Context) {
	if !s.sameOrigin(c.Request) {
		s.log.WarnContext(c.Request.Context(), "csrf: foreign origin", "origin", c.GetHeader("Origin"))
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	sess, err := s.sessions.Get(c.Request.Context(), s.cookie(c, s.sidCookie()))
	if err != nil {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	got := c.PostForm("csrf_token")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
		s.log.WarnContext(c.Request.Context(), "csrf: token mismatch", "sub", sess.Subject)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.Next()
}

func (s *Server) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == s.origin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Scheme+"://"+u.Host == s.origin
	}
	return true // neither header: rely on the token and SameSite
}
