package worker

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/AhmadShamli/Funnel/internal/database"
	"github.com/AhmadShamli/Funnel/internal/models"
	"github.com/AhmadShamli/Funnel/internal/policy"
)

// Worker runs background tasks for grant expiration and audit log pruning.
type Worker struct {
	db                 *database.DB
	engine             *policy.Engine
	auditRetentionDays int
	pollInterval       time.Duration
	cleanupInterval    time.Duration
}

// NewWorker initializes a background worker.
func NewWorker(db *database.DB, engine *policy.Engine, auditRetentionDays int) *Worker {
	return &Worker{
		db:                 db,
		engine:             engine,
		auditRetentionDays: auditRetentionDays,
		pollInterval:       10 * time.Second,
		cleanupInterval:    1 * time.Hour,
	}
}

// Start runs the worker event loop until context cancellation.
func (w *Worker) Start(ctx context.Context) {
	log.Printf("[WORKER] Background expiration and maintenance worker started")

	pollTicker := time.NewTicker(w.pollInterval)
	cleanupTicker := time.NewTicker(w.cleanupInterval)
	defer pollTicker.Stop()
	defer cleanupTicker.Stop()

	// Initial cleanup run
	w.runCleanup(ctx, time.Now().UTC())

	for {
		select {
		case <-ctx.Done():
			log.Printf("[WORKER] Background worker shutting down gracefully")
			return

		case t := <-pollTicker.C:
			w.runExpiration(ctx, t.UTC())

		case t := <-cleanupTicker.C:
			w.runCleanup(ctx, t.UTC())
		}
	}
}

// runExpiration checks for expired grants and updates firewall delta.
func (w *Worker) runExpiration(ctx context.Context, now time.Time) {
	expiredGrants, err := w.db.ExpireOldGrants(ctx, now)
	if err != nil {
		log.Printf("[WORKER] Error checking expired grants: %v", err)
		return
	}

	for _, g := range expiredGrants {
		log.Printf("[WORKER] Grant #%d for IP %s expired. Synchronizing firewall port deltas...", g.ID, g.SourceIP)
		if err := w.engine.SyncPortDeltaForIP(ctx, g.SourceIP, g.Ports, now); err != nil {
			log.Printf("[WORKER] Error syncing firewall for expired grant #%d: %v", g.ID, err)
		}

		details, _ := json.Marshal(map[string]interface{}{
			"grant_id": g.ID,
			"ports":    g.Ports,
			"source":   g.GrantSource,
		})
		_ = w.db.RecordAuditEvent(ctx, &models.AuditEvent{
			EventType:       "GRANT_EXPIRED",
			ActorType:       "system",
			ActorIdentifier: "funnel_worker",
			TargetIP:        g.SourceIP,
			DetailsJSON:     string(details),
		})
	}
}

// runCleanup prunes old audit events and expired admin sessions.
func (w *Worker) runCleanup(ctx context.Context, now time.Time) {
	// 1. Prune expired sessions
	prunedSessions, err := w.db.PruneExpiredSessions(ctx, now)
	if err == nil && prunedSessions > 0 {
		log.Printf("[WORKER] Pruned %d expired admin sessions", prunedSessions)
	}

	// 2. Prune audit events if retention is configured
	if w.auditRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -w.auditRetentionDays)
		prunedEvents, err := w.db.PruneAuditEvents(ctx, cutoff)
		if err == nil && prunedEvents > 0 {
			log.Printf("[WORKER] Pruned %d audit events older than %d days", prunedEvents, w.auditRetentionDays)
		}
	}
}
