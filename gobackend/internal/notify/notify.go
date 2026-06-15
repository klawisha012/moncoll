package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// Store is the persistence surface the Notifier needs.
type Store interface {
	CreateNotification(ctx context.Context, n *store.Notification) (*store.Notification, error)
	ListMembersForTenant(ctx context.Context, tenantID int64) ([]store.TeamMember, error)
}

// Publisher mirrors *centrifugo.Publisher (best-effort realtime ping).
type Publisher interface {
	Publish(ctx context.Context, channel string, data any) (bool, error)
}

// Notifier creates per-user notification rows and pings the recipient's
// Centrifugo personal channel so the client refetches.
type Notifier struct {
	store Store
	pub   Publisher
	log   *slog.Logger
}

// New constructs a Notifier. pub and log may be nil (pub → no realtime ping,
// log → warnings are silently dropped).
func New(s Store, pub Publisher, log *slog.Logger) *Notifier {
	return &Notifier{store: s, pub: pub, log: log}
}

func personalChannel(userID int64) string { return fmt.Sprintf("personal:#%d", userID) }

// NotifyUser creates one notification for userID and pings their channel.
// Publish failure is best-effort: it is logged but does not fail the call.
func (n *Notifier) NotifyUser(ctx context.Context, userID int64, tenantID *int64, typ, title, body string, data map[string]any) error {
	raw := []byte("{}")
	if data != nil {
		if b, err := json.Marshal(data); err == nil {
			raw = b
		} else if n.log != nil {
			n.log.Warn("notify: marshal data", "err", err)
		}
	}
	if _, err := n.store.CreateNotification(ctx, &store.Notification{
		UserID:   userID,
		TenantID: tenantID,
		Type:     typ,
		Title:    title,
		Body:     body,
		Data:     raw,
	}); err != nil {
		return err
	}
	n.ping(ctx, userID)
	return nil
}

// NotifyTenantMembers notifies every member of tenantID except excludeUserID.
// A per-member failure is logged but does not abort the remaining members.
func (n *Notifier) NotifyTenantMembers(ctx context.Context, tenantID, excludeUserID int64, typ, title, body string, data map[string]any) error {
	members, err := n.store.ListMembersForTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	tid := tenantID
	for _, m := range members {
		if m.UserID == excludeUserID {
			continue
		}
		if err := n.NotifyUser(ctx, m.UserID, &tid, typ, title, body, data); err != nil && n.log != nil {
			n.log.Warn("notify: member notify failed", "user", m.UserID, "err", err)
		}
	}
	return nil
}

// ping publishes a content-free realtime hint to the user's personal channel.
// Failure is best-effort: logged and never propagated.
func (n *Notifier) ping(ctx context.Context, userID int64) {
	if n.pub == nil {
		return
	}
	if _, err := n.pub.Publish(ctx, personalChannel(userID), map[string]any{"kind": "notifications"}); err != nil && n.log != nil {
		n.log.Warn("notify: publish ping failed", "user", userID, "err", err)
	}
}
