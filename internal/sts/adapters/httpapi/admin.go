package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/aamirlatif1/warden/internal/issuer/keyring"
	"github.com/aamirlatif1/warden/internal/sts/domain"
)

type AdminService interface {
	Rotate(ctx context.Context) (keyring.KeyInfo, error)
	Keys() []keyring.KeyInfo
	SuspendPartner(ctx context.Context, clientID string) error
	ResumePartner(ctx context.Context, clientID string) error
}

// NewAdminRouter serves operator actions. partner-sts binds it to a
// loopback-only listener: in this demo, being on the host is the
// authorization. Production would put it behind mTLS or an identity-aware
// proxy, with audit logging.
func NewAdminRouter(svc AdminService, log *slog.Logger) *gin.Engine {
	r := gin.New()
	r.Use(gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, rec any) {
		log.ErrorContext(c.Request.Context(), "panic in admin handler", "path", c.FullPath(), "panic", rec)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}))

	r.GET("/admin/keys", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"keys": svc.Keys()}) })

	r.POST("/admin/rotate", func(c *gin.Context) {
		info, err := svc.Rotate(c.Request.Context())
		switch {
		case errors.Is(err, keyring.ErrRotationInProgress):
			c.JSON(http.StatusConflict, gin.H{"error": "rotation already in progress"})
		case err != nil:
			log.ErrorContext(c.Request.Context(), "rotate failed", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rotate failed"})
		default:
			c.JSON(http.StatusAccepted, gin.H{"next": info})
		}
	})

	partnerAction := func(do func(context.Context, string) error) gin.HandlerFunc {
		return func(c *gin.Context) {
			err := do(c.Request.Context(), c.Param("id"))
			switch {
			case errors.Is(err, domain.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "partner not found"})
			case err != nil:
				log.ErrorContext(c.Request.Context(), "partner action failed", "err", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
			default:
				c.Status(http.StatusNoContent)
			}
		}
	}
	r.POST("/admin/partners/:id/suspend", partnerAction(svc.SuspendPartner))
	r.POST("/admin/partners/:id/resume", partnerAction(svc.ResumePartner))
	return r
}
