package notify

import (
	"context"
	"testing"

	"github.com/zwarder/waf/gobackend/internal/store"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeStore struct {
	created []store.Notification
	members []store.TeamMember
}

func (f *fakeStore) CreateNotification(_ context.Context, n *store.Notification) (*store.Notification, error) {
	f.created = append(f.created, *n)
	out := *n
	out.ID = int64(len(f.created))
	return &out, nil
}

func (f *fakeStore) ListMembersForTenant(_ context.Context, _ int64) ([]store.TeamMember, error) {
	return f.members, nil
}

type fakePublisher struct {
	calls []pingCall
}

type pingCall struct {
	channel string
	data    any
}

func (f *fakePublisher) Publish(_ context.Context, channel string, data any) (bool, error) {
	f.calls = append(f.calls, pingCall{channel: channel, data: data})
	return true, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func channelFor(userID int64) string { return personalChannel(userID) }

// ── tests ────────────────────────────────────────────────────────────────────

func TestNotifyUser_createsRowAndPings(t *testing.T) {
	fs := &fakeStore{}
	fp := &fakePublisher{}
	n := New(fs, fp, nil)

	data := map[string]any{"key": "value"}
	if err := n.NotifyUser(context.Background(), 42, nil, "test", "Hello", "World", data); err != nil {
		t.Fatalf("NotifyUser: %v", err)
	}

	// exactly one notification row
	if len(fs.created) != 1 {
		t.Fatalf("want 1 row, got %d", len(fs.created))
	}
	row := fs.created[0]
	if row.UserID != 42 {
		t.Errorf("UserID: want 42, got %d", row.UserID)
	}
	if row.TenantID != nil {
		t.Errorf("TenantID: want nil, got %v", row.TenantID)
	}
	if row.Type != "test" {
		t.Errorf("Type: want %q, got %q", "test", row.Type)
	}
	if row.Title != "Hello" {
		t.Errorf("Title: want %q, got %q", "Hello", row.Title)
	}
	if row.Body != "World" {
		t.Errorf("Body: want %q, got %q", "World", row.Body)
	}
	if string(row.Data) != `{"key":"value"}` {
		t.Errorf("Data: want %q, got %q", `{"key":"value"}`, string(row.Data))
	}

	// exactly one ping on the personal channel
	if len(fp.calls) != 1 {
		t.Fatalf("want 1 ping, got %d", len(fp.calls))
	}
	if fp.calls[0].channel != channelFor(42) {
		t.Errorf("channel: want %q, got %q", channelFor(42), fp.calls[0].channel)
	}
}

func TestNotifyUser_nilData_usesEmptyJSON(t *testing.T) {
	fs := &fakeStore{}
	n := New(fs, nil, nil)

	if err := n.NotifyUser(context.Background(), 7, nil, "t", "ti", "bo", nil); err != nil {
		t.Fatalf("NotifyUser: %v", err)
	}
	if string(fs.created[0].Data) != "{}" {
		t.Errorf("Data: want %q, got %q", "{}", string(fs.created[0].Data))
	}
}

func TestNotifyTenantMembers_excludesAndPings(t *testing.T) {
	fs := &fakeStore{
		members: []store.TeamMember{
			{UserID: 1, Email: "a@x.com", Role: "owner"},
			{UserID: 2, Email: "b@x.com", Role: "admin"},
			{UserID: 3, Email: "c@x.com", Role: "member"},
		},
	}
	fp := &fakePublisher{}
	n := New(fs, fp, nil)

	if err := n.NotifyTenantMembers(context.Background(), 7, 1, "ev", "T", "B", nil); err != nil {
		t.Fatalf("NotifyTenantMembers: %v", err)
	}

	// rows for users 2 and 3 only
	if len(fs.created) != 2 {
		t.Fatalf("want 2 rows, got %d", len(fs.created))
	}
	gotUsers := map[int64]bool{fs.created[0].UserID: true, fs.created[1].UserID: true}
	for _, wantUID := range []int64{2, 3} {
		if !gotUsers[wantUID] {
			t.Errorf("expected row for user %d", wantUID)
		}
	}
	// user 1 must NOT have a row
	for _, row := range fs.created {
		if row.UserID == 1 {
			t.Errorf("excluded user 1 must not get a notification")
		}
	}

	// two pings on personal:#2 and personal:#3
	if len(fp.calls) != 2 {
		t.Fatalf("want 2 pings, got %d", len(fp.calls))
	}
	pinged := map[string]bool{}
	for _, c := range fp.calls {
		pinged[c.channel] = true
	}
	for _, wantUID := range []int64{2, 3} {
		ch := channelFor(wantUID)
		if !pinged[ch] {
			t.Errorf("expected ping on %q", ch)
		}
	}
	// TenantID on rows must be 7
	tid := int64(7)
	for _, row := range fs.created {
		if row.TenantID == nil || *row.TenantID != tid {
			t.Errorf("TenantID: want %d, got %v", tid, row.TenantID)
		}
	}
}

func TestNotifyUser_nilPublisher_doesNotPanic(t *testing.T) {
	fs := &fakeStore{}
	n := New(fs, nil, nil) // nil pub

	// must not panic
	if err := n.NotifyUser(context.Background(), 99, nil, "t", "ti", "bo", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs.created) != 1 {
		t.Fatalf("want 1 row, got %d", len(fs.created))
	}
}
