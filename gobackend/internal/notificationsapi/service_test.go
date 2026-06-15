package notificationsapi

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	notificationsv1 "github.com/zwarder/waf/gobackend/gen/notifications/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── Fake store ────────────────────────────────────────────────────────────────

type fakeStore struct {
	rows   []store.Notification
	nextID int64
}

func (f *fakeStore) CreateNotification(_ context.Context, n *store.Notification) (*store.Notification, error) {
	f.nextID++
	n.ID = f.nextID
	n.CreatedAt = time.Now()
	if n.Data == nil {
		n.Data = []byte("{}")
	}
	cp := *n
	f.rows = append(f.rows, cp)
	return &cp, nil
}

// ListNotifications mimics the SQL query: user-scoped, filter, pagination,
// deleted_at IS NULL, descending ID order.
func (f *fakeStore) ListNotifications(_ context.Context, userID int64, filter string, limit int, beforeID int64) ([]store.Notification, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var out []store.Notification
	// Iterate in reverse insertion order to approximate DESC id.
	for i := len(f.rows) - 1; i >= 0; i-- {
		n := f.rows[i]
		if n.UserID != userID {
			continue
		}
		if n.DeletedAt != nil {
			continue
		}
		if beforeID > 0 && n.ID >= beforeID {
			continue
		}
		switch filter {
		case "unread":
			if n.ReadAt != nil {
				continue
			}
		case "starred":
			if !n.Starred {
				continue
			}
		}
		out = append(out, n)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeStore) CountUnread(_ context.Context, userID int64) (int64, error) {
	var count int64
	for _, n := range f.rows {
		if n.UserID == userID && n.DeletedAt == nil && n.ReadAt == nil {
			count++
		}
	}
	return count, nil
}

func (f *fakeStore) MarkNotificationsRead(_ context.Context, userID int64, ids []int64) error {
	idSet := make(map[int64]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	now := time.Now()
	for i := range f.rows {
		n := &f.rows[i]
		if n.UserID == userID && idSet[n.ID] && n.ReadAt == nil {
			t := now
			n.ReadAt = &t
		}
	}
	return nil
}

func (f *fakeStore) MarkAllNotificationsRead(_ context.Context, userID int64) error {
	now := time.Now()
	for i := range f.rows {
		n := &f.rows[i]
		if n.UserID == userID && n.DeletedAt == nil && n.ReadAt == nil {
			t := now
			n.ReadAt = &t
		}
	}
	return nil
}

func (f *fakeStore) SetNotificationStar(_ context.Context, userID, id int64, starred bool) (*store.Notification, error) {
	for i := range f.rows {
		n := &f.rows[i]
		if n.ID == id && n.UserID == userID && n.DeletedAt == nil {
			n.Starred = starred
			cp := *n
			return &cp, nil
		}
	}
	return nil, &store.NotFoundError{Entity: "notification"}
}

func (f *fakeStore) SoftDeleteNotifications(_ context.Context, userID int64, ids []int64) error {
	idSet := make(map[int64]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	now := time.Now()
	for i := range f.rows {
		n := &f.rows[i]
		if n.UserID == userID && idSet[n.ID] && n.DeletedAt == nil {
			t := now
			n.DeletedAt = &t
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func ctxWithUser(userID int64) context.Context {
	tid := int64(0) // no active tenant needed for these tests
	return auth.WithIdentity(context.Background(), &auth.Identity{
		UserID: userID, PlatformRole: "client", TenantID: &tid,
	})
}

func newSvc(f *fakeStore) *Service {
	return New(f, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// seed inserts a notification for userID into the fakeStore and returns its ID.
func seed(t *testing.T, f *fakeStore, svc *Service, userID int64, title string) int64 {
	t.Helper()
	n := &store.Notification{
		UserID: userID,
		Type:   "info",
		Title:  title,
		Body:   "body",
		Data:   []byte(`{"k":"v"}`),
	}
	out, err := f.CreateNotification(context.Background(), n)
	require.NoError(t, err)
	return out.ID
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestListNotificationsAll(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)
	otherUID := int64(2)

	seed(t, f, svc, uid, "A")
	seed(t, f, svc, uid, "B")
	seed(t, f, svc, otherUID, "C") // different user — must not appear

	resp, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{Filter: "all"})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 2)
	// Titles should be B, A (descending ID order).
	assert.Equal(t, "B", resp.Notifications[0].Title)
	assert.Equal(t, "A", resp.Notifications[1].Title)
}

func TestListNotificationsFilterUnread(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	id1 := seed(t, f, svc, uid, "unread")
	id2 := seed(t, f, svc, uid, "will-be-read")

	// Mark id2 as read directly in the store.
	require.NoError(t, f.MarkNotificationsRead(context.Background(), uid, []int64{id2}))
	_ = id1

	resp, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{Filter: "unread"})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 1)
	assert.Equal(t, "unread", resp.Notifications[0].Title)
	assert.False(t, resp.Notifications[0].Read)
}

func TestListNotificationsFilterStarred(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	id1 := seed(t, f, svc, uid, "starred")
	seed(t, f, svc, uid, "not-starred")

	// Star id1 directly.
	_, err := f.SetNotificationStar(context.Background(), uid, id1, true)
	require.NoError(t, err)

	resp, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{Filter: "starred"})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 1)
	assert.Equal(t, "starred", resp.Notifications[0].Title)
	assert.True(t, resp.Notifications[0].Starred)
}

func TestListNotificationsPagination(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	// Insert 3 rows; IDs will be 1, 2, 3.
	seed(t, f, svc, uid, "first")
	seed(t, f, svc, uid, "second")
	id3 := seed(t, f, svc, uid, "third")

	// First page: limit=2, no cursor → get ids 3, 2; next_before_id=2.
	resp, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{Limit: 2})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 2)
	assert.Equal(t, id3, resp.Notifications[0].Id)
	assert.NotZero(t, resp.NextBeforeId) // cursor set because page is full

	// Second page: before_id = next_before_id → should get id 1.
	resp2, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{Limit: 2, BeforeId: resp.NextBeforeId})
	require.NoError(t, err)
	require.Len(t, resp2.Notifications, 1)
	assert.Zero(t, resp2.NextBeforeId) // last page
}

func TestGetUnreadCount(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	seed(t, f, svc, uid, "A")
	id2 := seed(t, f, svc, uid, "B")
	seed(t, f, svc, uid, "C")
	require.NoError(t, f.MarkNotificationsRead(context.Background(), uid, []int64{id2}))

	resp, err := svc.GetUnreadCount(ctxWithUser(uid), &notificationsv1.GetUnreadCountRequest{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), resp.Count)
}

func TestMarkReadOnlyAffectsCaller(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid1 := int64(1)
	uid2 := int64(2)

	id1 := seed(t, f, svc, uid1, "user1-notif")
	_ = seed(t, f, svc, uid2, "user2-notif")

	// uid2 tries to mark uid1's notification — must be a no-op.
	_, err := svc.MarkRead(ctxWithUser(uid2), &notificationsv1.MarkReadRequest{Ids: []int64{id1}})
	require.NoError(t, err) // silently skipped, not an error

	// uid1's notification should still be unread.
	count, err := f.CountUnread(context.Background(), uid1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// uid1 marks its own notification.
	_, err = svc.MarkRead(ctxWithUser(uid1), &notificationsv1.MarkReadRequest{Ids: []int64{id1}})
	require.NoError(t, err)

	count, err = f.CountUnread(context.Background(), uid1)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestMarkAllRead(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	seed(t, f, svc, uid, "A")
	seed(t, f, svc, uid, "B")
	seed(t, f, svc, uid, "C")

	_, err := svc.MarkAllRead(ctxWithUser(uid), &notificationsv1.MarkAllReadRequest{})
	require.NoError(t, err)

	count, err := f.CountUnread(context.Background(), uid)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestToggleStarReturnsUpdated(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	id1 := seed(t, f, svc, uid, "notif")

	resp, err := svc.ToggleStar(ctxWithUser(uid), &notificationsv1.ToggleStarRequest{Id: id1, Starred: true})
	require.NoError(t, err)
	assert.True(t, resp.Starred)
	assert.Equal(t, id1, resp.Id)

	// Unstar.
	resp, err = svc.ToggleStar(ctxWithUser(uid), &notificationsv1.ToggleStarRequest{Id: id1, Starred: false})
	require.NoError(t, err)
	assert.False(t, resp.Starred)
}

func TestToggleStarNotFoundForOtherUser(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid1 := int64(1)
	uid2 := int64(2)

	id1 := seed(t, f, svc, uid1, "notif")

	// uid2 tries to star uid1's notification → NotFound.
	_, err := svc.ToggleStar(ctxWithUser(uid2), &notificationsv1.ToggleStarRequest{Id: id1, Starred: true})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteNotificationsHidesFromList(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid := int64(1)

	id1 := seed(t, f, svc, uid, "keep")
	id2 := seed(t, f, svc, uid, "delete-me")

	_, err := svc.DeleteNotifications(ctxWithUser(uid), &notificationsv1.DeleteNotificationsRequest{Ids: []int64{id2}})
	require.NoError(t, err)

	resp, err := svc.ListNotifications(ctxWithUser(uid), &notificationsv1.ListNotificationsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 1)
	assert.Equal(t, id1, resp.Notifications[0].Id)
}

func TestDeleteDoesNotAffectOtherUsersRows(t *testing.T) {
	f := &fakeStore{}
	svc := newSvc(f)
	uid1 := int64(1)
	uid2 := int64(2)

	id1 := seed(t, f, svc, uid1, "uid1-notif")

	// uid2 attempts to delete uid1's notification.
	_, err := svc.DeleteNotifications(ctxWithUser(uid2), &notificationsv1.DeleteNotificationsRequest{Ids: []int64{id1}})
	require.NoError(t, err) // silently skipped

	// uid1's notification still visible.
	resp, err := svc.ListNotifications(ctxWithUser(uid1), &notificationsv1.ListNotificationsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Notifications, 1)
}

func TestToProtoDataJSONDefault(t *testing.T) {
	n := store.Notification{
		ID:        42,
		Type:      "info",
		Title:     "Hi",
		Body:      "there",
		Data:      nil, // empty — should default to "{}"
		CreatedAt: time.Now(),
	}
	p := toProto(n)
	assert.Equal(t, "{}", p.DataJson)
	assert.False(t, p.Read)
	assert.False(t, p.HasTenantId)
}

func TestToProtoWithTenantID(t *testing.T) {
	tid := int64(7)
	n := store.Notification{
		ID:        1,
		TenantID:  &tid,
		CreatedAt: time.Now(),
	}
	p := toProto(n)
	assert.Equal(t, int64(7), p.TenantId)
	assert.True(t, p.HasTenantId)
}
