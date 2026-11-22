// Package httpapi is the REST (Gin) driving adapter for policy-api. It
// mirrors the gRPC API; *gin.Context stops at the handlers.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/authn"
	"github.com/aamirlatif1/warden/internal/authz"
	"github.com/aamirlatif1/warden/internal/policy/app"
	"github.com/aamirlatif1/warden/internal/policy/domain"
)

// PolicyService is the part of *app.Service this adapter calls.
type PolicyService interface {
	CreateQuote(ctx context.Context, p authn.Principal, in app.CreateQuoteInput) (domain.Quote, error)
	ListPolicies(ctx context.Context, p authn.Principal) ([]domain.Policy, error)
	GetPolicy(ctx context.Context, p authn.Principal, id string) (domain.Policy, error)
	UpdatePayoutAccount(ctx context.Context, p authn.Principal, policyID, iban string) (domain.Policy, error)
	ApproveClaim(ctx context.Context, p authn.Principal, claimID string) (domain.Claim, error)
}

type handlers struct {
	svc PolicyService
	log *slog.Logger
}

// NewRouter builds the REST API. auth runs on every /v1 route; /healthz is
// unauthenticated.
func NewRouter(svc PolicyService, auth gin.HandlerFunc, log *slog.Logger) *gin.Engine {
	h := &handlers{svc: svc, log: log}
	r := gin.New()
	// Logs and limits must see the TCP peer, not a client-sent
	// X-Forwarded-For.
	_ = r.SetTrustedProxies(nil)
	// Custom recovery: gin's default dumps request headers to the log.
	r.Use(gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, rec any) {
		log.ErrorContext(c.Request.Context(), "panic in handler", "method", c.Request.Method, "path", c.FullPath(), "panic", rec)
		c.AbortWithStatusJSON(http.StatusInternalServerError, errBody("internal error"))
	}))

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	v1 := r.Group("/v1", auth, requirePrincipal)
	v1.POST("/quotes", h.createQuote)
	v1.GET("/policies", h.listPolicies)
	v1.GET("/policies/:id", h.getPolicy)
	v1.PUT("/policies/:id/payout-account", h.updatePayoutAccount)
	// Google AIP custom method "/v1/claims/{id}:approve". Gin allows one
	// wildcard per segment, so the handler splits the ":approve" suffix.
	v1.POST("/claims/:idAction", h.claimAction)
	return r
}

// requirePrincipal guards against a misconfigured auth middleware: no
// principal in the context means 401, never an anonymous call.
func requirePrincipal(c *gin.Context) {
	if _, ok := authn.FromContext(c.Request.Context()); !ok {
		c.Header("WWW-Authenticate", `Bearer realm="warden"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, errBody("unauthenticated"))
		return
	}
	c.Next()
}

// principal is safe after requirePrincipal.
func principal(c *gin.Context) authn.Principal {
	p, _ := authn.FromContext(c.Request.Context())
	return p
}

type moneyJSON struct {
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
}

type quoteJSON struct {
	ID        string    `json:"id"`
	PartnerID string    `json:"partner_id"`
	Product   string    `json:"product"`
	Premium   moneyJSON `json:"premium"`
	CreatedAt time.Time `json:"created_at"`
}

type policyJSON struct {
	ID               string `json:"id"`
	HolderSubject    string `json:"holder_subject"`
	Product          string `json:"product"`
	Status           string `json:"status"`
	PayoutIBANMasked string `json:"payout_iban_masked"`
}

type claimJSON struct {
	ID       string    `json:"id"`
	PolicyID string    `json:"policy_id"`
	Amount   moneyJSON `json:"amount"`
	Status   string    `json:"status"`
}

func (h *handlers) createQuote(c *gin.Context) {
	var req struct {
		PartnerID    string    `json:"partner_id"`
		Product      string    `json:"product"`
		InsuredValue moneyJSON `json:"insured_value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}
	q, err := h.svc.CreateQuote(c.Request.Context(), principal(c), app.CreateQuoteInput{
		PartnerID:    req.PartnerID,
		Product:      req.Product,
		InsuredValue: domain.Money{AmountMinor: req.InsuredValue.AmountMinor, Currency: req.InsuredValue.Currency},
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"quote": quoteJSON{
		ID: q.ID, PartnerID: q.PartnerID, Product: q.Product,
		Premium:   moneyJSON{q.Premium.AmountMinor, q.Premium.Currency},
		CreatedAt: q.CreatedAt,
	}})
}

func (h *handlers) listPolicies(c *gin.Context) {
	ps, err := h.svc.ListPolicies(c.Request.Context(), principal(c))
	if err != nil {
		h.fail(c, err)
		return
	}
	out := make([]policyJSON, 0, len(ps))
	for _, pol := range ps {
		out = append(out, toPolicyJSON(pol))
	}
	c.JSON(http.StatusOK, gin.H{"policies": out})
}

func (h *handlers) getPolicy(c *gin.Context) {
	pol, err := h.svc.GetPolicy(c.Request.Context(), principal(c), c.Param("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": toPolicyJSON(pol)})
}

func (h *handlers) updatePayoutAccount(c *gin.Context) {
	var req struct {
		IBAN string `json:"iban"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}
	pol, err := h.svc.UpdatePayoutAccount(c.Request.Context(), principal(c), c.Param("id"), req.IBAN)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": toPolicyJSON(pol)})
}

func (h *handlers) claimAction(c *gin.Context) {
	id, ok := strings.CutSuffix(c.Param("idAction"), ":approve")
	if !ok || id == "" {
		c.JSON(http.StatusNotFound, errBody("not found"))
		return
	}
	cl, err := h.svc.ApproveClaim(c.Request.Context(), principal(c), id)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"claim": claimJSON{
		ID: cl.ID, PolicyID: cl.PolicyID,
		Amount: moneyJSON{cl.Amount.AmountMinor, cl.Amount.Currency},
		Status: string(cl.Status),
	}})
}

func (h *handlers) fail(c *gin.Context, err error) {
	var denied *authz.DeniedError
	var stepUp *authz.StepUpError
	switch {
	case errors.As(err, &stepUp):
		// RFC 9470: the client re-authenticates with acr_values and max_age.
		c.Header("WWW-Authenticate", stepUp.Challenge())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "insufficient_user_authentication", "reason": stepUp.Reason})
	case errors.As(err, &denied):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "reason": denied.Reason})
	case errors.Is(err, app.ErrTokenInactive):
		c.Header("WWW-Authenticate", `Bearer realm="warden", error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, errBody("token inactive"))
	case errors.Is(err, app.ErrUnavailable):
		c.JSON(http.StatusServiceUnavailable, errBody("temporarily unavailable"))
	case errors.Is(err, domain.ErrNotFound):
		c.JSON(http.StatusNotFound, errBody("not found"))
	case errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, errBody(err.Error()))
	case errors.Is(err, domain.ErrConflict):
		c.JSON(http.StatusConflict, errBody("conflict"))
	default:
		h.log.ErrorContext(c.Request.Context(), "policy-api internal error", "path", c.FullPath(), "err", err)
		c.JSON(http.StatusInternalServerError, errBody("internal error"))
	}
}

func toPolicyJSON(p domain.Policy) policyJSON {
	return policyJSON{ID: p.ID, HolderSubject: p.HolderSubject, Product: p.Product, Status: p.Status, PayoutIBANMasked: p.MaskedIBAN()}
}

func errBody(msg string) gin.H { return gin.H{"error": msg} }
