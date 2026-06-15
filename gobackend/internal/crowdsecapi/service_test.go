package crowdsecapi

import (
	"context"
	"encoding/json"
	"testing"
	"unicode/utf8"

	crowdsecv1 "github.com/zwarder/waf/gobackend/gen/crowdsec/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

type fakeRunner struct {
	// runReturns maps the first arg to (exitCode, stdout, stderr).
	runReturns map[string][3]string
	// jsonReturns maps the first arg to raw JSON (nil = empty result).
	jsonReturns map[string]json.RawMessage
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (int, string, string, error) {
	if len(args) == 0 {
		return 0, "", "", nil
	}
	key := args[0]
	if len(args) > 1 {
		key = args[0] + "/" + args[1]
	}
	if v, ok := f.runReturns[key]; ok {
		code := 0
		if v[0] != "0" {
			code = 1
		}
		return code, v[1], v[2], nil
	}
	return 0, "", "", nil
}

func (f *fakeRunner) RunJSON(_ context.Context, args ...string) (json.RawMessage, error) {
	if len(args) == 0 {
		return nil, nil
	}
	key := args[0]
	if len(args) > 1 {
		key = args[0] + "/" + args[1]
	}
	if v, ok := f.jsonReturns[key]; ok {
		return v, nil
	}
	return nil, nil
}

type fakeSyncer struct {
	mapping    map[string][]int64
	syncCalled int
	saveCalled int
	lastSaved  map[string][]int64
}

func (f *fakeSyncer) SyncBlockedIPsConf(_ context.Context) error {
	f.syncCalled++
	return nil
}

func (f *fakeSyncer) LoadBlockedIPsMapping() map[string][]int64 {
	if f.mapping == nil {
		return make(map[string][]int64)
	}
	// Return a copy
	out := make(map[string][]int64, len(f.mapping))
	for k, v := range f.mapping {
		cp := make([]int64, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (f *fakeSyncer) SaveBlockedIPsMapping(m map[string][]int64) error {
	f.saveCalled++
	f.lastSaved = m
	f.mapping = m
	return nil
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

// decisionsListJSON is a realistic `cscli decisions list -o json` payload.
// Shape: list of alert objects, each with source + decisions array.
const decisionsListJSON = `[
  {
    "id": 42,
    "scenario": "crowdsecurity/http-probing",
    "message": "test",
    "source": {"value": "1.2.3.4", "scope": "Ip"},
    "stop_at": "2026-06-05T10:00:00Z",
    "start_at": "2026-06-04T10:00:00Z",
    "decisions": [
      {
        "id": 101,
        "value": "1.2.3.4",
        "type": "ban",
        "duration": "4h",
        "origin": "crowdsec",
        "scope": "Ip"
      }
    ],
    "meta": []
  },
  {
    "id": 43,
    "scenario": "crowdsecurity/ssh-bf",
    "message": "brute force",
    "source": {"value": "5.6.7.8", "scope": "Ip"},
    "stop_at": "2026-06-05T11:00:00Z",
    "start_at": "2026-06-04T11:00:00Z",
    "decisions": [
      {
        "id": 102,
        "value": "5.6.7.8",
        "type": "ban",
        "duration": "24h",
        "origin": "cscli",
        "scope": "Ip"
      }
    ],
    "meta": [
      {"key": "target_host", "value": "example.com"}
    ]
  }
]`

// scenariosListJSON is a realistic `cscli scenarios list -o json` payload.
const scenariosListJSON = `{
  "scenarios": [
    {
      "name": "crowdsecurity/http-probing",
      "description": "Detect HTTP probing",
      "status": "enabled",
      "type": "leakybucket",
      "labels": ["attack", "http"]
    },
    {
      "name": "crowdsecurity/ssh-bf",
      "description": "SSH brute force",
      "status": "enabled",
      "type": "leakybucket",
      "labels": ["brute-force"]
    }
  ]
}`

// alertsListJSON is a realistic `cscli alerts list -o json` payload.
const alertsListJSON = `[
  {
    "id": 10,
    "scenario": "crowdsecurity/http-probing",
    "message": "test alert",
    "source": {"value": "9.9.9.9", "scope": "Ip"},
    "start_at": "2026-06-04T09:00:00Z",
    "stop_at": "2026-06-04T09:30:00Z",
    "capacity": 10,
    "decisions": [{"id": 200, "value": "9.9.9.9", "type": "ban"}],
    "meta": []
  }
]`

// ── Fake Notifier ─────────────────────────────────────────────────────────────

type csNotifyCall struct {
	tenantID      int64
	excludeUserID int64
	typ           string
	title         string
	body          string
	data          map[string]any
}

type fakeNotifier struct {
	calls []csNotifyCall
}

func (f *fakeNotifier) NotifyTenantMembers(_ context.Context, tenantID, excludeUserID int64, typ, title, body string, data map[string]any) error {
	f.calls = append(f.calls, csNotifyCall{
		tenantID:      tenantID,
		excludeUserID: excludeUserID,
		typ:           typ,
		title:         title,
		body:          body,
		data:          data,
	})
	return nil
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func newTestService() (*Service, *fakeRunner, *fakeSyncer) {
	runner := &fakeRunner{
		runReturns:  map[string][3]string{},
		jsonReturns: map[string]json.RawMessage{},
	}
	syncer := &fakeSyncer{}
	svc := New(runner, syncer, nil)
	return svc, runner, syncer
}

// TestGetStatus_MapsVersionAndCounts verifies GetStatus parses version from
// cscli output and counts decisions/scenarios/alerts correctly.
func TestGetStatus_MapsVersionAndCounts(t *testing.T) {
	svc, runner, _ := newTestService()

	runner.runReturns["version"] = [3]string{"0", "version: v1.6.2-debian-pragmatic-amd64\nbuild_date: ...", ""}
	runner.jsonReturns["decisions/list"] = json.RawMessage(decisionsListJSON)
	runner.jsonReturns["scenarios/list"] = json.RawMessage(scenariosListJSON)
	runner.jsonReturns["alerts/list"] = json.RawMessage(alertsListJSON)

	resp, err := svc.GetStatus(context.Background(), &crowdsecv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !resp.Running {
		t.Error("expected Running=true")
	}
	if resp.Version == "" {
		t.Error("expected non-empty version")
	}
	// 2 alerts × 1 decision each = 2 decisions total
	if resp.DecisionsCount != 2 {
		t.Errorf("DecisionsCount: got %d, want 2", resp.DecisionsCount)
	}
	// 2 scenarios in the JSON
	if resp.ScenariosCount != 2 {
		t.Errorf("ScenariosCount: got %d, want 2", resp.ScenariosCount)
	}
	// 1 alert in alertsListJSON
	if resp.AlertsCount != 1 {
		t.Errorf("AlertsCount: got %d, want 1", resp.AlertsCount)
	}
}

// TestGetStatus_SanitizesInvalidUTF8 reproduces the HTTP 500 caused by cscli
// stdout containing invalid UTF-8 bytes: the version string flows into a
// protobuf string field, and gRPC rejects invalid UTF-8 with codes.Internal.
// The response must carry valid UTF-8 and marshal cleanly.
func TestGetStatus_SanitizesInvalidUTF8(t *testing.T) {
	svc, runner, _ := newTestService()

	// "version: v1.6.2" followed by a raw invalid UTF-8 byte (0xff).
	runner.runReturns["version"] = [3]string{"0", "version: v1.6.2\xff", ""}

	resp, err := svc.GetStatus(context.Background(), &crowdsecv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !utf8.ValidString(resp.Version) {
		t.Errorf("Version is not valid UTF-8: %q", resp.Version)
	}
	if _, err := proto.Marshal(resp); err != nil {
		t.Errorf("response failed to marshal (would be HTTP 500): %v", err)
	}
}

// TestGetDecisions_ParsesList verifies GetDecisions parses the decisions list
// and populates blocked_on / manual mapping correctly.
func TestGetDecisions_ParsesList(t *testing.T) {
	svc, runner, syncer := newTestService()

	runner.jsonReturns["decisions/list"] = json.RawMessage(decisionsListJSON)
	// Set manual mapping for IP 5.6.7.8 → conn 99
	syncer.mapping = map[string][]int64{"5.6.7.8": {99}}

	resp, err := svc.GetDecisions(context.Background(), &crowdsecv1.GetDecisionsRequest{})
	if err != nil {
		t.Fatalf("GetDecisions: %v", err)
	}
	if len(resp.Decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(resp.Decisions))
	}

	// First decision: 1.2.3.4, no manual mapping → fallback (all conns = nil in test)
	d0 := resp.Decisions[0]
	if d0.Value != "1.2.3.4" {
		t.Errorf("d0.Value: got %q, want %q", d0.Value, "1.2.3.4")
	}
	if d0.Reason != "crowdsecurity/http-probing" {
		t.Errorf("d0.Reason: got %q", d0.Reason)
	}

	// Second decision: 5.6.7.8, manual mapping → conn 99
	d1 := resp.Decisions[1]
	if d1.Value != "5.6.7.8" {
		t.Errorf("d1.Value: got %q, want %q", d1.Value, "5.6.7.8")
	}
	if len(d1.BlockedOn) != 1 || d1.BlockedOn[0] != "conn_99" {
		t.Errorf("d1.BlockedOn: got %v, want [conn_99]", d1.BlockedOn)
	}
}

// TestGetDecisions_DecisionItemID verifies nullable ID is handled correctly.
func TestGetDecisions_DecisionItemID(t *testing.T) {
	svc, runner, _ := newTestService()
	runner.jsonReturns["decisions/list"] = json.RawMessage(decisionsListJSON)

	resp, err := svc.GetDecisions(context.Background(), &crowdsecv1.GetDecisionsRequest{})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.Decisions[0].Id == nil {
		t.Error("expected non-nil Id for decision 0")
	}
	if resp.Decisions[0].Id.GetValue() != 101 {
		t.Errorf("Id: got %d, want 101", resp.Decisions[0].Id.GetValue())
	}
}

// TestAddDecision_CallsCscliAndSyncs verifies AddDecision:
//   - passes the right cscli args
//   - updates the mapping when connection_ids are provided
//   - calls SyncBlockedIPsConf
func TestAddDecision_CallsCscliAndSyncs(t *testing.T) {
	svc, runner, syncer := newTestService()
	runner.runReturns["decisions/add"] = [3]string{"0", "Decision added", ""}

	req := &crowdsecv1.DecisionCreate{
		Ip:            "10.0.0.1",
		Duration:      "2h",
		Reason:        "test",
		Type:          "ban",
		ConnectionIds: []int64{7, 8},
	}
	resp, err := svc.AddDecision(context.Background(), req)
	if err != nil {
		t.Fatalf("AddDecision: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true, got false: %s", resp.Message)
	}
	if resp.Action != "block" {
		t.Errorf("Action: got %q, want %q", resp.Action, "block")
	}
	if resp.Ip != "10.0.0.1" {
		t.Errorf("Ip: got %q, want %q", resp.Ip, "10.0.0.1")
	}

	// Mapping should be updated
	if syncer.saveCalled == 0 {
		t.Error("expected SaveBlockedIPsMapping to be called")
	}
	ids := syncer.lastSaved["10.0.0.1"]
	if len(ids) != 2 || ids[0] != 7 || ids[1] != 8 {
		t.Errorf("mapping for 10.0.0.1: got %v, want [7 8]", ids)
	}

	// Sync must be called
	if syncer.syncCalled == 0 {
		t.Error("expected SyncBlockedIPsConf to be called")
	}
}

// TestDeleteDecision_CleansMapping verifies DeleteDecision removes the IP from
// the mapping and triggers a sync.
func TestDeleteDecision_CleansMapping(t *testing.T) {
	svc, runner, syncer := newTestService()
	runner.runReturns["decisions/delete"] = [3]string{"0", "Decisions(s) deleted", ""}
	syncer.mapping = map[string][]int64{"1.2.3.4": {5}}

	resp, err := svc.DeleteDecision(context.Background(), &crowdsecv1.DeleteDecisionRequest{Ip: "1.2.3.4"})
	if err != nil {
		t.Fatalf("DeleteDecision: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true: %s", resp.Message)
	}
	if resp.Action != "unblock" {
		t.Errorf("Action: got %q", resp.Action)
	}

	// Mapping should have the IP removed
	if _, ok := syncer.mapping["1.2.3.4"]; ok {
		t.Error("expected 1.2.3.4 to be removed from mapping")
	}
	if syncer.syncCalled == 0 {
		t.Error("expected SyncBlockedIPsConf to be called")
	}
}

// TestGetScenarios_ParsesList verifies GetScenarios maps the cscli JSON output.
func TestGetScenarios_ParsesList(t *testing.T) {
	svc, runner, _ := newTestService()
	runner.jsonReturns["scenarios/list"] = json.RawMessage(scenariosListJSON)

	resp, err := svc.GetScenarios(context.Background(), &crowdsecv1.Empty2{})
	if err != nil {
		t.Fatalf("GetScenarios: %v", err)
	}
	if len(resp.Scenarios) != 2 {
		t.Fatalf("expected 2 scenarios, got %d", len(resp.Scenarios))
	}
	s0 := resp.Scenarios[0]
	if s0.Name != "crowdsecurity/http-probing" {
		t.Errorf("Name: got %q", s0.Name)
	}
	if !s0.Loaded {
		t.Error("expected Loaded=true (status=enabled)")
	}
	if len(s0.Labels) != 2 {
		t.Errorf("Labels: got %v, want 2 items", s0.Labels)
	}
}

// TestGetAlerts_ParsesList verifies GetAlerts maps the cscli JSON output.
func TestGetAlerts_ParsesList(t *testing.T) {
	svc, runner, _ := newTestService()
	runner.jsonReturns["alerts/list"] = json.RawMessage(alertsListJSON)

	resp, err := svc.GetAlerts(context.Background(), &crowdsecv1.GetAlertsRequest{})
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(resp.Alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(resp.Alerts))
	}
	a := resp.Alerts[0]
	if a.SourceIp != "9.9.9.9" {
		t.Errorf("SourceIp: got %q, want %q", a.SourceIp, "9.9.9.9")
	}
	if a.Scenario != "crowdsecurity/http-probing" {
		t.Errorf("Scenario: got %q", a.Scenario)
	}
	if a.DecisionsCount != 1 {
		t.Errorf("DecisionsCount: got %d, want 1", a.DecisionsCount)
	}
	if a.Capacity == nil || a.Capacity.GetValue() != 10 {
		t.Errorf("Capacity: got %v, want 10", a.Capacity)
	}
}

// TestGetAlerts_HoursFilter verifies that the hours filter drops old alerts.
func TestGetAlerts_HoursFilter(t *testing.T) {
	svc, runner, _ := newTestService()
	// Alert start_at is 2026-06-04T09:00:00Z — that's in the past relative to
	// now (2026-06-04). With hours=0.1 (~6 minutes), it should be filtered out.
	runner.jsonReturns["alerts/list"] = json.RawMessage(alertsListJSON)

	// 0.1 hours = 6 minutes ago — the alert is hours old, so it should be filtered.
	resp, err := svc.GetAlerts(context.Background(), &crowdsecv1.GetAlertsRequest{
		Hours: wrapperspb.Double(0.1),
	})
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	// The fixture alert is from far in the past, so it must be filtered out.
	if len(resp.Alerts) != 0 {
		t.Errorf("expected 0 alerts after hours filter, got %d", len(resp.Alerts))
	}
}

// TestAddDecision_Failure_ReturnsFalse verifies that a cscli failure produces
// success=false with the stderr message.
func TestAddDecision_Failure_ReturnsFalse(t *testing.T) {
	svc, runner, syncer := newTestService()
	// non-zero exit = failure
	runner.runReturns["decisions/add"] = [3]string{"1", "", "invalid IP address"}

	resp, err := svc.AddDecision(context.Background(), &crowdsecv1.DecisionCreate{
		Ip: "bad-ip",
	})
	if err != nil {
		t.Fatalf("AddDecision: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false on cscli failure")
	}
	if resp.Message != "invalid IP address" {
		t.Errorf("Message: got %q, want %q", resp.Message, "invalid IP address")
	}
	// Sync must NOT be called on failure
	if syncer.syncCalled != 0 {
		t.Error("expected SyncBlockedIPsConf NOT to be called on failure")
	}
}

// TestRemoveScenario_InvalidNameReturnsFalse verifies the safety regex.
func TestRemoveScenario_InvalidNameReturnsFalse(t *testing.T) {
	svc, _, _ := newTestService()

	resp, err := svc.RemoveScenario(context.Background(), &crowdsecv1.ScenarioNameRequest{
		Name: "../../etc/passwd",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.Success {
		t.Error("expected Success=false for invalid name")
	}
}

// ── Notification tests ────────────────────────────────────────────────────────

// identityCtx returns a context with an injected auth.Identity carrying the
// given tenantID and userID — mirrors how the gRPC interceptor sets identity.
func identityCtx(tenantID, userID int64) context.Context {
	tid := tenantID
	id := &auth.Identity{UserID: userID, PlatformRole: "user", TenantID: &tid}
	return auth.WithIdentity(context.Background(), id)
}

// TestAddDecision_EmitsNotification verifies that a successful AddDecision
// emits security.crowdsec_ban to the actor's tenant, excluding the actor.
func TestAddDecision_EmitsNotification(t *testing.T) {
	runner := &fakeRunner{
		runReturns:  map[string][3]string{"decisions/add": {"0", "Decision added", ""}},
		jsonReturns: map[string]json.RawMessage{},
	}
	syncer := &fakeSyncer{}
	notif := &fakeNotifier{}
	svc := New(runner, syncer, notif)

	ctx := identityCtx(99, 7) // tenant 99, actor user 7
	req := &crowdsecv1.DecisionCreate{
		Ip:     "10.0.0.5",
		Reason: "test ban",
	}
	resp, err := svc.AddDecision(ctx, req)
	if err != nil {
		t.Fatalf("AddDecision: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected Success=true: %s", resp.Message)
	}

	if len(notif.calls) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notif.calls))
	}
	c := notif.calls[0]
	if c.tenantID != 99 {
		t.Errorf("tenantID: got %d, want 99", c.tenantID)
	}
	if c.excludeUserID != 7 {
		t.Errorf("excludeUserID: got %d, want 7 (actor)", c.excludeUserID)
	}
	if c.typ != "security.crowdsec_ban" {
		t.Errorf("typ: got %q, want %q", c.typ, "security.crowdsec_ban")
	}
	if c.data["ip"] != "10.0.0.5" {
		t.Errorf("data.ip: got %v, want %q", c.data["ip"], "10.0.0.5")
	}
	if c.data["reason"] != "test ban" {
		t.Errorf("data.reason: got %v, want %q", c.data["reason"], "test ban")
	}
}

// TestAddDecision_FailureDoesNotEmitNotification verifies that when the cscli
// runner returns non-zero (failure), no notification is emitted.
func TestAddDecision_FailureDoesNotEmitNotification(t *testing.T) {
	runner := &fakeRunner{
		runReturns:  map[string][3]string{"decisions/add": {"1", "", "bad IP"}},
		jsonReturns: map[string]json.RawMessage{},
	}
	syncer := &fakeSyncer{}
	notif := &fakeNotifier{}
	svc := New(runner, syncer, notif)

	ctx := identityCtx(99, 7)
	_, err := svc.AddDecision(ctx, &crowdsecv1.DecisionCreate{Ip: "bad-ip"})
	if err != nil {
		t.Fatalf("AddDecision: %v", err)
	}

	if len(notif.calls) != 0 {
		t.Errorf("expected no notifications on failure, got %d", len(notif.calls))
	}
}

// TestAddDecision_NilNotifier_DoesNotPanic verifies nil notifier is safe.
func TestAddDecision_NilNotifier_DoesNotPanic(t *testing.T) {
	runner := &fakeRunner{
		runReturns:  map[string][3]string{"decisions/add": {"0", "ok", ""}},
		jsonReturns: map[string]json.RawMessage{},
	}
	svc := New(runner, &fakeSyncer{}, nil)

	ctx := identityCtx(1, 2)
	_, err := svc.AddDecision(ctx, &crowdsecv1.DecisionCreate{Ip: "1.2.3.4"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
